"""Thin Python binding for a server-projected Sekai capability."""

PROJECTION_VERSION = "sekai.capability-projection/v1"


def invocation(capability: dict, operation_id: str, input_value: dict) -> dict:
    context = capability["context"]
    for name, value in (
        ("namespace", context["namespace"]),
        ("principal", context["principal"]),
        ("catalog_version", context["catalog_version"]),
        ("operation_id", operation_id),
    ):
        if not value.strip():
            raise ValueError(f"projection requires {name}")
    if (
        capability["projection_version"] != PROJECTION_VERSION
        or capability["contract_version"] != context["contract_version"]
        or capability["minimum_compatible_version"] != context["contract_version"]
        or capability["maximum_compatible_version"] != context["contract_version"]
    ):
        raise ValueError("capability contract version drift")
    return {
        "projection_version": PROJECTION_VERSION,
        "contract_version": capability["contract_version"],
        "catalog_version": context["catalog_version"],
        "namespace": context["namespace"],
        "principal": context["principal"],
        "capability": capability["name"],
        "operation_id": operation_id,
        "input_type": capability["input_type"],
        "output_type": capability["output_type"],
        "input": input_value,
    }


def native_metadata(call: dict) -> dict[str, str]:
    return {
        "x-principal": call["principal"],
        "x-sekai-namespace": call["namespace"],
        "x-sekai-capability": call["capability"],
        "x-sekai-operation-id": call["operation_id"],
    }


def normalize_error(call: dict, code: str, message: str) -> dict:
    return {
        "code": code,
        "message": message,
        "capability": call["capability"],
        "operation_id": call["operation_id"],
        "retryable": code in {"aborted", "unavailable", "deadline_exceeded"},
    }
