from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any

from .encoding import b64url_decode


@dataclass(slots=True)
class AppOutcome:
    transport_success: bool
    application_status: str
    error_strings: list[str]
    component: str | None
    parsed_json: dict[str, Any] | list[Any] | None


def classify_application_response(status: int, body: str | None) -> AppOutcome:
    transport_success = 200 <= status < 300
    parsed_json: dict[str, Any] | list[Any] | None = None
    component: str | None = None
    error_strings: list[str] = []
    application_status = "unknown"

    if body:
        try:
            parsed = json.loads(body)
            if isinstance(parsed, (dict, list)):
                parsed_json = parsed
        except Exception:
            parsed_json = None

    if isinstance(parsed_json, dict):
        component_val = parsed_json.get("component")
        if isinstance(component_val, str):
            component = component_val

        response_errors = parsed_json.get("response_errors")
        if isinstance(response_errors, dict):
            for value in response_errors.values():
                if isinstance(value, list):
                    for item in value:
                        if isinstance(item, dict):
                            text = item.get("string")
                            if isinstance(text, str):
                                error_strings.append(text)
                elif isinstance(value, dict):
                    text = value.get("string")
                    if isinstance(text, str):
                        error_strings.append(text)

        ok_value = parsed_json.get("ok")
        if isinstance(ok_value, bool):
            application_status = "accepted" if ok_value else "rejected"
        elif error_strings:
            application_status = "rejected"
        elif transport_success:
            application_status = "unknown"
        else:
            application_status = "rejected"
    else:
        application_status = "accepted" if transport_success else "rejected"

    return AppOutcome(
        transport_success=transport_success,
        application_status=application_status,
        error_strings=error_strings,
        component=component,
        parsed_json=parsed_json,
    )


def build_mutation_diff(
    original: dict[str, Any] | list[Any],
    mutated: dict[str, Any] | list[Any],
) -> dict[str, Any]:
    operations: list[dict[str, Any]] = []
    _collect_diff(original, mutated, "$", operations)
    return {
        "changed": bool(operations),
        "operation_count": len(operations),
        "changed_paths": [op["path"] for op in operations],
        "operations": operations,
    }


def extract_challenges(payload: Any) -> list[str]:
    out: list[str] = []

    def _walk(node: Any) -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                if key == "challenge" and isinstance(value, str):
                    out.append(value)
                _walk(value)
            return
        if isinstance(node, list):
            for item in node:
                _walk(item)

    _walk(payload)
    return out


def stable_body_fingerprint(body: str | None) -> str | None:
    if body is None:
        return None
    normalized = " ".join(body.split())
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def _collect_diff(before: Any, after: Any, path: str, out: list[dict[str, Any]]) -> None:
    if isinstance(before, dict) and isinstance(after, dict):
        keys = sorted(set(before.keys()) | set(after.keys()))
        for key in keys:
            key_path = f"{path}.{key}"
            if key not in before:
                out.append(
                    {
                        "path": key_path,
                        "op": "add",
                        "before": None,
                        "after": _value_summary(key_path, after[key]),
                    }
                )
                continue
            if key not in after:
                out.append(
                    {
                        "path": key_path,
                        "op": "remove",
                        "before": _value_summary(key_path, before[key]),
                        "after": None,
                    }
                )
                continue
            _collect_diff(before[key], after[key], key_path, out)
        return

    if isinstance(before, list) and isinstance(after, list):
        max_len = max(len(before), len(after))
        for idx in range(max_len):
            idx_path = f"{path}[{idx}]"
            if idx >= len(before):
                out.append(
                    {
                        "path": idx_path,
                        "op": "add",
                        "before": None,
                        "after": _value_summary(idx_path, after[idx]),
                    }
                )
                continue
            if idx >= len(after):
                out.append(
                    {
                        "path": idx_path,
                        "op": "remove",
                        "before": _value_summary(idx_path, before[idx]),
                        "after": None,
                    }
                )
                continue
            _collect_diff(before[idx], after[idx], idx_path, out)
        return

    if before == after:
        return

    out.append(
        {
            "path": path,
            "op": "replace",
            "before": _value_summary(path, before),
            "after": _value_summary(path, after),
        }
    )


def _value_summary(path: str, value: Any) -> dict[str, Any] | Any:
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    if isinstance(value, dict):
        return {"type": "object", "keys": sorted(value.keys())}
    if isinstance(value, list):
        return {"type": "array", "length": len(value)}
    if not isinstance(value, str):
        return str(value)

    summary: dict[str, Any] = {
        "type": "string",
        "length": len(value),
        "sha256": hashlib.sha256(value.encode("utf-8")).hexdigest(),
    }
    if len(value) <= 180:
        summary["value"] = value
    else:
        summary["preview"] = f"{value[:80]}...{value[-20:]}"

    if path.endswith("clientDataJSON"):
        decoded = _try_decode_client_data(value)
        if decoded is not None:
            summary["decoded_client_data"] = decoded
    if path.endswith("authenticatorData"):
        decoded = _try_decode_authenticator_data(value)
        if decoded is not None:
            summary["decoded_authenticator_data"] = decoded
    return summary


def _try_decode_client_data(value: str) -> dict[str, Any] | None:
    try:
        decoded = b64url_decode(value).decode("utf-8")
        obj = json.loads(decoded)
    except Exception:
        return None
    if not isinstance(obj, dict):
        return None
    out: dict[str, Any] = {}
    for key in ("type", "challenge", "origin", "crossOrigin"):
        if key in obj:
            out[key] = obj[key]
    return out


def _try_decode_authenticator_data(value: str) -> dict[str, Any] | None:
    try:
        raw = b64url_decode(value)
    except Exception:
        return None
    out: dict[str, Any] = {"length": len(raw)}
    if len(raw) >= 37:
        flags = raw[32]
        out["flags"] = flags
        out["up"] = bool(flags & 0x01)
        out["uv"] = bool(flags & 0x04)
        out["sign_count"] = int.from_bytes(raw[33:37], "big")
    return out
