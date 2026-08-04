"""Optional grpcio transport for :mod:`sekai_client`.

The SDK keeps generated protobuf modules in the consuming application. Pass the
generated service/message modules through ``GrpcBindings`` so this facade does
not publish a second protocol snapshot.
"""

from __future__ import annotations

from dataclasses import dataclass
import re
import time
from types import ModuleType
from typing import Any, Iterable, Mapping
from urllib.parse import urlparse

from sekai_client import ClientConfig, RpcCallOptions, RpcTransport, ServiceName


@dataclass(frozen=True)
class GrpcBindings:
    sekai_stub: type
    chisei_stub: type
    sekai_messages: ModuleType
    chisei_messages: ModuleType


class GrpcTransportError(RuntimeError):
    def __init__(self, code: object, message: str) -> None:
        super().__init__(message)
        self.code = code


def _snake_case(name: str) -> str:
    return re.sub(r"(?<!^)(?=[A-Z])", "_", name).lower()


def _request_message_name(service: ServiceName, method: str) -> str:
    if service == "chisei" and method == "ExecutePlanStream":
        return "ExecutePlanRequest"
    return f"{method}Request"


def _target(config: ClientConfig) -> tuple[str, bool]:
    if not config.target:
        raise ValueError("gRPC target is required")
    raw = config.target.strip()
    if raw.startswith("unix://"):
        return raw, False
    parsed = urlparse(raw)
    if parsed.scheme not in {"http", "https"} or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("gRPC target must be an http(s) URL or unix:// path")
    hostname = parsed.hostname
    if not hostname:
        raise ValueError("gRPC target hostname is required")
    if parsed.scheme == "http" and not config.allow_insecure_remote and hostname.lower() not in {"localhost", "127.0.0.1", "::1"}:
        raise ValueError("insecure gRPC is restricted to loopback; use HTTPS for remote targets")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    host = f"[{hostname}]" if ":" in hostname else hostname
    return f"{host}:{port}", parsed.scheme == "https"


class _GrpcStream:
    def __init__(self, call: Any, messages: ModuleType, message_name: str) -> None:
        self._call = call
        self._messages = messages
        self._message_name = message_name
        self._closed = False

    def __iter__(self) -> "_GrpcStream":
        return self

    def __next__(self) -> dict[str, Any]:
        if self._closed:
            raise StopIteration
        try:
            message = next(self._call)
        except StopIteration:
            self._closed = True
            raise
        except BaseException as error:
            raise GrpcTransportError(_grpc_code(error), _grpc_message(error)) from error
        return _message_to_dict(message)

    def cancel(self) -> None:
        self._closed = True
        cancel = getattr(self._call, "cancel", None)
        if callable(cancel):
            cancel()

    close = cancel


def _grpc_code(error: BaseException) -> object:
    code = getattr(error, "code", None)
    if callable(code):
        code = code()
    return getattr(code, "name", code)


def _grpc_message(error: BaseException) -> str:
    details = getattr(error, "details", None)
    if callable(details):
        details = details()
    return str(details or error)


def _message_to_dict(message: Any) -> dict[str, Any]:
    from google.protobuf.json_format import MessageToDict

    return MessageToDict(message, preserving_proto_field_name=True)


class GrpcTransport(RpcTransport):
    def __init__(self, channel: Any, bindings: GrpcBindings) -> None:
        self._channel = channel
        self._bindings = bindings
        self._stubs = {
            "sekai": bindings.sekai_stub(channel),
            "chisei": bindings.chisei_stub(channel),
        }

    def _message(self, service: ServiceName, method: str, request: Mapping[str, Any]) -> Any:
        from google.protobuf.json_format import ParseDict

        module = self._bindings.sekai_messages if service == "sekai" else self._bindings.chisei_messages
        message_type = getattr(module, _request_message_name(service, method), None)
        if message_type is None:
            raise ValueError(f"{service}.{method} request type is unavailable")
        return ParseDict(dict(request), message_type(), ignore_unknown_fields=False)

    def unary(
        self,
        service: ServiceName,
        method: str,
        request: Mapping[str, Any],
        options: RpcCallOptions,
    ) -> dict[str, Any]:
        stub = self._stubs[service]
        # grpcio preserves the RPC name on generated stubs (for example,
        # ``CreateObject``). Keep a snake_case fallback for hand-written
        # adapters used by hosts that expose Pythonic method names.
        rpc = getattr(stub, method, None) or getattr(stub, _snake_case(method), None)
        if rpc is None:
            raise ValueError(f"{service}.{method} is unavailable")
        timeout = max(0.0, options.deadline - time.monotonic())
        try:
            response = rpc(
                self._message(service, method, request),
                timeout=timeout,
                metadata=list(options.metadata.items()),
            )
        except BaseException as error:
            raise GrpcTransportError(_grpc_code(error), _grpc_message(error)) from error
        return _message_to_dict(response)

    def stream(
        self,
        service: ServiceName,
        method: str,
        request: Mapping[str, Any],
        options: RpcCallOptions,
    ) -> Iterable[dict[str, Any]]:
        stub = self._stubs[service]
        rpc = getattr(stub, method, None) or getattr(stub, _snake_case(method), None)
        if rpc is None:
            raise ValueError(f"{service}.{method} is unavailable")
        timeout = max(0.0, options.deadline - time.monotonic())
        try:
            call = rpc(
                self._message(service, method, request),
                timeout=timeout,
                metadata=list(options.metadata.items()),
            )
        except BaseException as error:
            raise GrpcTransportError(_grpc_code(error), _grpc_message(error)) from error
        return _GrpcStream(call, self._bindings.chisei_messages if service == "chisei" else self._bindings.sekai_messages, f"{method}Response")

    def close(self) -> None:
        close = getattr(self._channel, "close", None)
        if callable(close):
            close()


def connect_grpc(config: ClientConfig, bindings: GrpcBindings) -> GrpcTransport:
    try:
        import grpc
    except ImportError as error:
        raise RuntimeError("install the SDK grpc extra: pip install 'sekai-chisei-sdk[grpc]'") from error
    target, secure = _target(config)
    if secure:
        credentials = grpc.ssl_channel_credentials(root_certificates=config.tls_root_certificates)
        channel = grpc.secure_channel(target, credentials)
    else:
        channel = grpc.insecure_channel(target)
    return GrpcTransport(channel, bindings)
