"""Typed, server-side Python facade for the Sekai/Chisei gRPC contracts."""

from __future__ import annotations

from dataclasses import dataclass
import time
from typing import Any, Iterable, Iterator, Literal, Mapping, Protocol, Sequence, TypedDict
from uuid import uuid4


SDK_CONTRACT_VERSION = "sekai.sdk-core-loop/v1"
ServiceName = Literal["sekai", "chisei"]
SdkErrorCode = Literal[
    "cancelled",
    "invalid_argument",
    "deadline_exceeded",
    "not_found",
    "already_exists",
    "permission_denied",
    "resource_exhausted",
    "failed_precondition",
    "aborted",
    "unavailable",
    "unimplemented",
    "internal",
    "unauthenticated",
    "unknown",
]


RETRYABLE_CODES: tuple[SdkErrorCode, ...] = (
    "aborted",
    "deadline_exceeded",
    "resource_exhausted",
    "unavailable",
)


@dataclass(frozen=True)
class RetryPolicy:
    max_attempts: int = 3
    initial_backoff_seconds: float = 0.05
    max_backoff_seconds: float = 1.0
    retryable_codes: tuple[SdkErrorCode, ...] = RETRYABLE_CODES


@dataclass(frozen=True)
class RpcCallOptions:
    metadata: Mapping[str, str]
    deadline: float


class RpcTransport(Protocol):
    def unary(
        self,
        service: ServiceName,
        method: str,
        request: Mapping[str, Any],
        options: RpcCallOptions,
    ) -> Any: ...

    def stream(
        self,
        service: ServiceName,
        method: str,
        request: Mapping[str, Any],
        options: RpcCallOptions,
    ) -> Iterable[Any]: ...

    def close(self) -> None: ...


@dataclass(frozen=True)
class ClientConfig:
    principal: str
    target: str | None = None
    token: str | None = None
    namespace: str | None = None
    catalog_version: str | None = None
    default_timeout_seconds: float = 30.0
    retry: RetryPolicy = RetryPolicy()
    allow_insecure_remote: bool = False
    tls_root_certificates: bytes | None = None


class SchemaType(TypedDict, total=False):
    kind: str
    description: str
    properties: list[dict[str, Any]]
    is_builtin: bool
    implements: list[str]


class FactObject(TypedDict, total=False):
    id: str
    kind: str
    name: str
    namespace: str
    external_id: str
    properties: dict[str, str]
    created: int
    updated: int


class FactLink(TypedDict, total=False):
    id: str
    from_id: str
    to_id: str
    relation: str
    created: int


class ExecutionInput(TypedDict, total=False):
    request_id: str
    namespace: str
    spec: str
    preferred_model: str
    preferred_runtime: str
    task_type: str
    priority: int
    user_id: str
    estimated_tokens: int
    messages: list[dict[str, Any]]
    tools: list[dict[str, Any]]
    system: str
    max_tokens: int
    task_class: str
    logical_operation_id: str
    attempt_id: str
    route_override: str


class ExecutionPlan(TypedDict, total=False):
    plan_id: str
    input: ExecutionInput
    resolved_runtime: str
    resolved_model: str
    executable: bool


class OperationReceipt(TypedDict, total=False):
    receipt_json: str
    complete: bool
    missing_surfaces: list[str]


@dataclass(frozen=True)
class CallContext:
    namespace: str | None = None
    capability: str | None = None
    operation_id: str | None = None
    catalog_version: str | None = None
    metadata: Mapping[str, str] | None = None


@dataclass(frozen=True)
class CallOptions:
    context: CallContext = CallContext()
    timeout_seconds: float | None = None
    # None uses the helper's default; False is an explicit retry opt-out.
    retryable: bool | None = None
    request_id: str | None = None


class SdkError(RuntimeError):
    """Stable error envelope; raw RPC status objects stay transport-local."""

    def __init__(
        self,
        code: SdkErrorCode,
        message: str,
        *,
        service: ServiceName | None = None,
        method: str | None = None,
        operation_id: str | None = None,
        request_id: str | None = None,
        retryable: bool | None = None,
        cause: BaseException | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.retryable = retryable if retryable is not None else code in RETRYABLE_CODES
        self.service = service
        self.method = method
        self.operation_id = operation_id
        self.request_id = request_id
        self.cause = cause

    @classmethod
    def from_exception(
        cls,
        error: BaseException,
        *,
        service: ServiceName | None = None,
        method: str | None = None,
        operation_id: str | None = None,
        request_id: str | None = None,
    ) -> "SdkError":
        if isinstance(error, cls):
            return cls(
                error.code,
                str(error),
                service=service or error.service,
                method=method or error.method,
                operation_id=operation_id or error.operation_id,
                request_id=request_id or error.request_id,
                retryable=error.retryable,
                cause=error,
            )
        raw_code = getattr(error, "code", None)
        if callable(raw_code):
            raw_code = raw_code()
        raw_code = getattr(raw_code, "name", raw_code)
        code = _normalize_code(raw_code)
        return cls(
            code,
            _safe_error_message(code),
            service=service,
            method=method,
            operation_id=operation_id,
            request_id=request_id,
            cause=error,
        )


def _normalize_code(value: object) -> SdkErrorCode:
    if isinstance(value, int):
        return {
            1: "cancelled",
            2: "unknown",
            3: "invalid_argument",
            4: "deadline_exceeded",
            5: "not_found",
            6: "already_exists",
            7: "permission_denied",
            8: "resource_exhausted",
            9: "failed_precondition",
            10: "aborted",
            12: "unimplemented",
            13: "internal",
            14: "unavailable",
            16: "unauthenticated",
        }.get(value, "unknown")
    if not isinstance(value, str):
        return "unknown"
    normalized = value.lower().replace("-", "_")
    aliases: dict[str, SdkErrorCode] = {
        "cancelled": "cancelled",
        "canceled": "cancelled",
        "deadlineexceeded": "deadline_exceeded",
        "deadline_exceeded": "deadline_exceeded",
        "invalidargument": "invalid_argument",
        "invalid_argument": "invalid_argument",
        "notfound": "not_found",
        "not_found": "not_found",
        "alreadyexists": "already_exists",
        "already_exists": "already_exists",
        "permissiondenied": "permission_denied",
        "permission_denied": "permission_denied",
        "resourceexhausted": "resource_exhausted",
        "resource_exhausted": "resource_exhausted",
        "failedprecondition": "failed_precondition",
        "failed_precondition": "failed_precondition",
        "unauthenticated": "unauthenticated",
        "unavailable": "unavailable",
        "unimplemented": "unimplemented",
        "internal": "internal",
        "aborted": "aborted",
        "unknown": "unknown",
    }
    return aliases.get(normalized, "unknown")


def _safe_error_message(code: SdkErrorCode) -> str:
    return {
        "cancelled": "RPC cancelled",
        "invalid_argument": "RPC request was invalid",
        "deadline_exceeded": "RPC deadline exceeded",
        "not_found": "RPC resource was not found",
        "already_exists": "RPC resource already exists",
        "permission_denied": "RPC permission denied",
        "resource_exhausted": "RPC resource exhausted",
        "failed_precondition": "RPC precondition failed",
        "aborted": "RPC was aborted",
        "unavailable": "Sekai/Chisei is unavailable",
        "unimplemented": "RPC is not implemented",
        "internal": "Sekai/Chisei returned an internal error",
        "unauthenticated": "Sekai/Chisei authentication failed",
        "unknown": "Sekai/Chisei RPC failed",
    }[code]


def _required_text(name: str, value: str | None, max_length: int = 512) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > max_length or any(
        character in value for character in ("\r", "\n", "\0")
    ):
        raise SdkError("invalid_argument", f"{name} must be a bounded non-empty string")
    return value


def _optional_text(name: str, value: str | None, max_length: int = 512) -> str | None:
    if value is None or value == "":
        return None
    return _required_text(name, value, max_length)


class CancellableStream(Iterator[Any]):
    def __init__(self, source: Iterable[Any], cancel_target: Any | None = None) -> None:
        self._iterator = iter(source)
        self._source = source
        self._cancel_target = cancel_target or source
        self._closed = False

    def __iter__(self) -> "CancellableStream":
        return self

    def __next__(self) -> Any:
        if self._closed:
            raise StopIteration
        try:
            return next(self._iterator)
        except StopIteration:
            self._closed = True
            raise

    def cancel(self) -> None:
        self._closed = True
        cancel = getattr(self._cancel_target, "cancel", None)
        if callable(cancel):
            cancel()
        close = getattr(self._cancel_target, "close", None)
        if callable(close):
            close()

    close = cancel


class RawRpcFacade:
    def __init__(self, client: "SekaiChiseiClient") -> None:
        self._client = client

    def unary(
        self,
        service: ServiceName,
        method: str,
        request: Mapping[str, Any] | None = None,
        options: CallOptions = CallOptions(),
    ) -> Any:
        return self._client.call_unary(service, method, request or {}, options)

    def stream(
        self,
        service: ServiceName,
        method: str,
        request: Mapping[str, Any] | None = None,
        options: CallOptions = CallOptions(),
    ) -> CancellableStream:
        return self._client.call_stream(service, method, request or {}, options)


class SekaiChiseiClient:
    def __init__(self, config: ClientConfig, transport: RpcTransport) -> None:
        self.config = config
        self._transport = transport
        _required_text("principal", config.principal, 200)
        _optional_text("namespace", config.namespace, 200)
        _optional_text("catalog_version", config.catalog_version, 200)
        if config.token is not None:
            _required_text("token", config.token, 4096)
        if not 0 < config.default_timeout_seconds <= 600:
            raise SdkError("invalid_argument", "default_timeout_seconds must be between 0 and 600")
        if not 1 <= config.retry.max_attempts <= 8:
            raise SdkError("invalid_argument", "retry.max_attempts must be between 1 and 8")
        if config.retry.initial_backoff_seconds < 0 or config.retry.max_backoff_seconds < config.retry.initial_backoff_seconds:
            raise SdkError("invalid_argument", "retry backoff bounds are invalid")
        self.raw = RawRpcFacade(self)

    @classmethod
    def connect(cls, config: ClientConfig, bindings: Any) -> "SekaiChiseiClient":
        from sekai_grpc import connect_grpc

        return cls(config, connect_grpc(config, bindings))

    def close(self) -> None:
        self._transport.close()

    def metadata(self, context: CallContext = CallContext()) -> dict[str, str]:
        namespace = _optional_text("namespace", context.namespace or self.config.namespace, 200)
        capability = _optional_text("capability", context.capability, 200)
        operation = _optional_text("operation_id", context.operation_id, 200)
        catalog = _optional_text(
            "catalog_version",
            context.catalog_version or self.config.catalog_version,
            200,
        )
        metadata: dict[str, str] = {"x-principal": _required_text("principal", self.config.principal, 200)}
        if self.config.token:
            metadata["authorization"] = f"Bearer {self.config.token}"
        if namespace:
            metadata["x-sekai-namespace"] = namespace
        if capability:
            metadata["x-sekai-capability"] = capability
        if operation:
            metadata["x-sekai-operation-id"] = operation
            metadata["x-chisei-work-unit"] = operation
        if catalog:
            metadata["x-sekai-catalog-version"] = catalog
        reserved = {
            "authorization",
            "x-principal",
            "x-sekai-namespace",
            "x-sekai-capability",
            "x-sekai-operation-id",
            "x-chisei-work-unit",
            "x-sekai-catalog-version",
        }
        for key, value in (context.metadata or {}).items():
            normalized = key.lower()
            if normalized in reserved:
                raise SdkError("invalid_argument", f"reserved metadata must be set through SDK context: {key}")
            if not normalized.replace("-", "").isalnum() or normalized.endswith("-bin"):
                raise SdkError("invalid_argument", f"invalid metadata key: {key}")
            metadata[normalized] = _required_text(f"metadata {key}", value, 4096)
        return metadata

    def call_unary(
        self,
        service: ServiceName,
        method: str,
        request: Mapping[str, Any],
        options: CallOptions = CallOptions(),
    ) -> Any:
        request_id = options.request_id or str(uuid4())
        operation = options.context.operation_id
        timeout = options.timeout_seconds if options.timeout_seconds is not None else self.config.default_timeout_seconds
        if not 0 < timeout <= 600:
            raise SdkError("invalid_argument", "timeout_seconds must be between 0 and 600")
        deadline = time.monotonic() + timeout
        attempts = self.config.retry.max_attempts if options.retryable else 1
        for attempt in range(1, attempts + 1):
            if deadline <= time.monotonic():
                raise SdkError(
                    "deadline_exceeded",
                    "RPC deadline exceeded",
                    service=service,
                    method=method,
                    operation_id=operation,
                    request_id=request_id,
                )
            try:
                return self._transport.unary(
                    service,
                    method,
                    request,
                    RpcCallOptions(self.metadata(options.context), deadline),
                )
            except BaseException as error:
                if isinstance(error, KeyboardInterrupt):
                    raise
                sdk_error = SdkError.from_exception(
                    error,
                    service=service,
                    method=method,
                    operation_id=operation,
                    request_id=request_id,
                )
                if (
                    attempt >= attempts
                    or not sdk_error.retryable
                    or sdk_error.code not in self.config.retry.retryable_codes
                ):
                    raise sdk_error from error
                backoff = min(
                    self.config.retry.max_backoff_seconds,
                    self.config.retry.initial_backoff_seconds * (2 ** (attempt - 1)),
                )
                if backoff:
                    time.sleep(backoff)
        raise SdkError("unknown", "RPC retry loop terminated unexpectedly")

    def call_stream(
        self,
        service: ServiceName,
        method: str,
        request: Mapping[str, Any],
        options: CallOptions = CallOptions(),
    ) -> CancellableStream:
        request_id = options.request_id or str(uuid4())
        timeout = options.timeout_seconds if options.timeout_seconds is not None else self.config.default_timeout_seconds
        if not 0 < timeout <= 600:
            raise SdkError("invalid_argument", "timeout_seconds must be between 0 and 600")
        try:
            source = self._transport.stream(
                service,
                method,
                request,
                RpcCallOptions(self.metadata(options.context), time.monotonic() + timeout),
            )
        except BaseException as error:
            if isinstance(error, KeyboardInterrupt):
                raise
            raise SdkError.from_exception(
                error,
                service=service,
                method=method,
                operation_id=options.context.operation_id,
                request_id=request_id,
            ) from error

        def guarded() -> Iterator[Any]:
            try:
                yield from source
            except BaseException as error:
                if isinstance(error, KeyboardInterrupt):
                    raise
                raise SdkError.from_exception(
                    error,
                    service=service,
                    method=method,
                    operation_id=options.context.operation_id,
                    request_id=request_id,
                ) from error
            finally:
                cancel = getattr(source, "cancel", None)
                if callable(cancel):
                    cancel()

        return CancellableStream(guarded(), source)

    def create_schema_type(self, schema: SchemaType, options: CallOptions = CallOptions()) -> SchemaType:
        response = self.call_unary("sekai", "CreateSchemaType", {"type": schema}, CallOptions(
            context=CallContext(
                namespace=options.context.namespace,
                capability=options.context.capability or "sekai.schema.create",
                operation_id=options.context.operation_id,
                catalog_version=options.context.catalog_version,
                metadata=options.context.metadata,
            ),
            timeout_seconds=options.timeout_seconds,
            retryable=options.retryable,
            request_id=options.request_id,
        ))
        return _response_field(response, "type", "CreateSchemaType")

    def create_object(self, obj: FactObject, options: CallOptions = CallOptions()) -> FactObject:
        _required_text("object.id", obj.get("id"), 200)
        _required_text("object.kind", obj.get("kind"), 200)
        response = self.call_unary("sekai", "CreateObject", {"object": obj}, _with_capability(options, "sekai.fact.seed"))
        return _response_field(response, "object", "CreateObject")

    def create_link(self, link: FactLink, options: CallOptions = CallOptions()) -> FactLink:
        for name in ("id", "from_id", "to_id", "relation"):
            _required_text(f"link.{name}", link.get(name), 200)
        response = self.call_unary("sekai", "CreateLink", {
            "link": link,
            "fail_if_exists": False,
        }, _with_capability(options, "sekai.fact.seed"))
        return _response_field(response, "link", "CreateLink")

    def seed_facts(
        self,
        namespace: str,
        objects: Sequence[FactObject],
        links: Sequence[FactLink] = (),
        *,
        operation_id: str | None = None,
        options: CallOptions = CallOptions(),
    ) -> tuple[list[FactObject], list[FactLink]]:
        _required_text("namespace", namespace, 200)
        base = _with_context(options, namespace=namespace, operation_id=operation_id)
        seeded_objects = []
        for obj in objects:
            if "namespace" in obj and obj["namespace"] != namespace:
                raise SdkError("invalid_argument", "object namespace must match seed namespace")
            seeded_objects.append(self.create_object({**obj, "namespace": namespace}, base))
        seeded_links = [self.create_link(link, base) for link in links]
        return seeded_objects, seeded_links

    def plan_execution(self, execution: ExecutionInput, options: CallOptions = CallOptions()) -> ExecutionPlan:
        namespace = _required_text("execution.namespace", execution.get("namespace") or options.context.namespace, 200)
        request_id = execution.get("request_id") or options.request_id or str(uuid4())
        normalized = dict(execution)
        normalized["namespace"] = namespace
        normalized["request_id"] = request_id
        if execution.get("logical_operation_id") or options.context.operation_id:
            normalized["logical_operation_id"] = execution.get("logical_operation_id") or options.context.operation_id
        context = _with_capability(_with_context(options, namespace=namespace), "chisei.plan.execute")
        context = CallOptions(
            context=context.context,
            timeout_seconds=context.timeout_seconds,
            retryable=context.retryable,
            request_id=request_id,
        )
        response = self.call_unary("chisei", "PlanExecution", {"input": normalized}, context)
        return _response_field(response, "plan", "PlanExecution")

    def execute_plan(self, plan: ExecutionPlan, options: CallOptions = CallOptions()) -> Any:
        return self.call_unary("chisei", "ExecutePlan", {"plan": plan}, _with_capability(options, "chisei.plan.execute"))

    def execute_plan_stream(self, plan: ExecutionPlan, options: CallOptions = CallOptions()) -> CancellableStream:
        return self.call_stream("chisei", "ExecutePlanStream", {"plan": plan}, _with_capability(options, "chisei.plan.execute"))

    def get_operation_receipt(
        self,
        operation_id: str | None = None,
        *,
        request_id: str | None = None,
        caller_scope: str = "",
        attempt: int = 0,
        options: CallOptions = CallOptions(),
    ) -> OperationReceipt:
        if not operation_id and not request_id:
            raise SdkError("invalid_argument", "receipt requires operation_id or request_id")
        if operation_id and request_id:
            raise SdkError("invalid_argument", "receipt accepts exactly one of operation_id or request_id")
        request_id = request_id or ("" if operation_id else options.request_id or str(uuid4()))
        response = self.call_unary("chisei", "GetOperationReceipt", {
            "operation_id": operation_id or "",
            "request_id": request_id,
            "caller_scope": caller_scope,
            "attempt": attempt,
        }, CallOptions(
            context=CallContext(
                namespace=options.context.namespace,
                capability=options.context.capability or "chisei.receipt.read",
                operation_id=options.context.operation_id,
                catalog_version=options.context.catalog_version,
                metadata=options.context.metadata,
            ),
            timeout_seconds=options.timeout_seconds,
            retryable=True if options.retryable is None else options.retryable,
            request_id=request_id,
        ))
        return response

    def run_core_loop(
        self,
        namespace: str,
        objects: Sequence[FactObject],
        execution: ExecutionInput,
        *,
        schema: SchemaType | None = None,
        links: Sequence[FactLink] = (),
        operation_id: str | None = None,
        caller_scope: str = "",
        stream: bool = True,
        options: CallOptions = CallOptions(),
    ) -> dict[str, Any]:
        namespace = _required_text("namespace", namespace, 200)
        operation_id = operation_id or str(uuid4())
        base = _with_context(options, namespace=namespace, operation_id=operation_id)
        created_schema = self.create_schema_type(schema, base) if schema is not None else None
        seeded_objects, seeded_links = self.seed_facts(
            namespace,
            objects,
            links,
            operation_id=operation_id,
            options=options,
        )
        request_id = execution.get("request_id") or str(uuid4())
        normalized_execution = dict(execution)
        normalized_execution.update({
            "namespace": namespace,
            "request_id": request_id,
            "logical_operation_id": execution.get("logical_operation_id") or operation_id,
        })
        plan = self.plan_execution(normalized_execution, base)
        events: list[Any] = []
        if plan.get("executable", True):
            if stream:
                events.extend(self.execute_plan_stream(plan, CallOptions(
                    context=base.context,
                    timeout_seconds=base.timeout_seconds,
                    request_id=request_id,
                )))
            else:
                events.append(self.execute_plan(plan, CallOptions(
                    context=base.context,
                    timeout_seconds=base.timeout_seconds,
                    request_id=request_id,
                )))
        receipt = self.get_operation_receipt(
            operation_id=_required_text("plan.plan_id", plan.get("plan_id"), 200),
            caller_scope=caller_scope,
            options=CallOptions(
                context=base.context,
                timeout_seconds=base.timeout_seconds,
                request_id=request_id,
            ),
        )
        return {
            "operation_id": operation_id,
            "request_id": request_id,
            "schema": created_schema,
            "objects": seeded_objects,
            "links": seeded_links,
            "plan": plan,
            "events": events,
            "receipt": receipt,
        }


def _response_field(response: Any, field: str, label: str) -> Any:
    if not isinstance(response, Mapping) or field not in response:
        raise SdkError("internal", f"{label} omitted {field}")
    return response[field]


def _with_context(options: CallOptions, *, namespace: str | None = None, operation_id: str | None = None) -> CallOptions:
    context = options.context
    return CallOptions(
        context=CallContext(
            namespace=namespace or context.namespace,
            capability=context.capability,
            operation_id=operation_id or context.operation_id,
            catalog_version=context.catalog_version,
            metadata=context.metadata,
        ),
        timeout_seconds=options.timeout_seconds,
        retryable=options.retryable,
        request_id=options.request_id,
    )


def _with_capability(options: CallOptions, capability: str) -> CallOptions:
    context = options.context
    return CallOptions(
        context=CallContext(
            namespace=context.namespace,
            capability=context.capability or capability,
            operation_id=context.operation_id,
            catalog_version=context.catalog_version,
            metadata=context.metadata,
        ),
        timeout_seconds=options.timeout_seconds,
        retryable=options.retryable,
        request_id=options.request_id,
    )
