from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Any

from .config import MutationConfig
from .encoding import b64url_decode, b64url_encode
from .state import StateStore

try:
    from fido2 import cbor
except Exception:  # pragma: no cover - import fallback
    cbor = None


@dataclass(slots=True)
class MutationLog:
    changed: bool = False
    details: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def mark(self, message: str) -> None:
        self.changed = True
        self.details.append(message)

    def error(self, message: str) -> None:
        self.errors.append(message)


def mutate_json_payload(
    payload: dict[str, Any] | list[Any],
    mutation: MutationConfig,
    state: StateStore,
    ceremony: str | None = None,
) -> tuple[dict[str, Any] | list[Any], MutationLog]:
    log = MutationLog()
    if not mutation.enabled:
        return payload, log

    _walk_and_mutate(payload, mutation, state, ceremony, log, path="root")
    return payload, log


def contains_webauthn_payload(payload: dict[str, Any] | list[Any]) -> bool:
    return _has_webauthn_node(payload)


def _has_webauthn_node(node: Any) -> bool:
    if isinstance(node, dict):
        if _is_webauthn_credential(node):
            return True
        return any(_has_webauthn_node(v) for v in node.values())
    if isinstance(node, list):
        return any(_has_webauthn_node(v) for v in node)
    return False


def _walk_and_mutate(
    node: Any,
    mutation: MutationConfig,
    state: StateStore,
    ceremony: str | None,
    log: MutationLog,
    path: str,
) -> None:
    if isinstance(node, dict):
        if _is_webauthn_credential(node):
            _mutate_credential(node, mutation, state, ceremony, log, path)
        for key, value in list(node.items()):
            _walk_and_mutate(
                value, mutation, state, ceremony, log, path=f"{path}.{key}"
            )
        return

    if isinstance(node, list):
        for idx, value in enumerate(node):
            _walk_and_mutate(
                value, mutation, state, ceremony, log, path=f"{path}[{idx}]"
            )


def _is_webauthn_credential(node: dict[str, Any]) -> bool:
    response = node.get("response")
    if not isinstance(response, dict):
        return False
    has_primary = isinstance(node.get("id"), str) or isinstance(node.get("rawId"), str)
    has_response_fields = any(
        key in response
        for key in (
            "clientDataJSON",
            "authenticatorData",
            "attestationObject",
            "signature",
        )
    )
    return has_primary and has_response_fields


def _mutate_credential(
    credential: dict[str, Any],
    mutation: MutationConfig,
    state: StateStore,
    ceremony: str | None,
    log: MutationLog,
    path: str,
) -> None:
    if mutation.duplicate_credential_id:
        prior = state.any_credential_id()
        if prior:
            credential["id"] = prior
            credential["rawId"] = prior
            log.mark(f"{path}: duplicated credential id")

    response = credential.get("response")
    if not isinstance(response, dict):
        return

    client_data = response.get("clientDataJSON")
    if isinstance(client_data, str):
        updated = _mutate_client_data_json(client_data, mutation, state, ceremony, log, path)
        if updated is not None:
            response["clientDataJSON"] = updated

    authenticator_data = response.get("authenticatorData")
    if isinstance(authenticator_data, str):
        updated = _mutate_authenticator_data(authenticator_data, mutation, state, log, path)
        if updated is not None:
            response["authenticatorData"] = updated

    attestation_object = response.get("attestationObject")
    if isinstance(attestation_object, str):
        updated = _mutate_attestation_object(attestation_object, mutation, log, path)
        if updated is not None:
            response["attestationObject"] = updated


def _mutate_client_data_json(
    encoded: str,
    mutation: MutationConfig,
    state: StateStore,
    ceremony: str | None,
    log: MutationLog,
    path: str,
) -> str | None:
    try:
        raw = b64url_decode(encoded)
        obj = json.loads(raw.decode("utf-8"))
    except Exception as exc:
        log.error(f"{path}: clientDataJSON decode failed: {exc}")
        return None

    changed = False
    if mutation.tamper_origin:
        obj["origin"] = mutation.tamper_origin
        changed = True
        log.mark(f"{path}: tampered clientDataJSON.origin")

    if mutation.tamper_challenge:
        if mutation.tamper_challenge == "stale":
            source = state.previous_challenge(ceremony or "auth")
            if source:
                obj["challenge"] = source
                changed = True
                log.mark(f"{path}: replayed stale challenge")
        elif mutation.tamper_challenge == "random":
            obj["challenge"] = b64url_encode(os.urandom(32))
            changed = True
            log.mark(f"{path}: replaced challenge with random bytes")
        else:
            obj["challenge"] = mutation.tamper_challenge
            changed = True
            log.mark(f"{path}: replaced challenge with provided value")

    if mutation.tamper_type:
        obj["type"] = mutation.tamper_type
        changed = True
        log.mark(f"{path}: changed clientDataJSON.type")

    if not changed:
        return None

    return b64url_encode(json.dumps(obj, separators=(",", ":")).encode("utf-8"))


def _mutate_authenticator_data(
    encoded: str,
    mutation: MutationConfig,
    state: StateStore,
    log: MutationLog,
    path: str,
) -> str | None:
    try:
        raw = bytearray(b64url_decode(encoded))
    except Exception as exc:
        log.error(f"{path}: authenticatorData decode failed: {exc}")
        return None

    if len(raw) < 37:
        log.error(f"{path}: authenticatorData shorter than 37 bytes")
        return None

    changed = False
    flags_index = 32
    sign_count_index = 33

    if mutation.force_up_flag is not None:
        if mutation.force_up_flag:
            raw[flags_index] |= 0x01
        else:
            raw[flags_index] &= ~0x01
        changed = True
        log.mark(f"{path}: modified UP flag")

    if mutation.force_uv_flag is not None:
        if mutation.force_uv_flag:
            raw[flags_index] |= 0x04
        else:
            raw[flags_index] &= ~0x04
        changed = True
        log.mark(f"{path}: modified UV flag")

    if mutation.sign_count_mode:
        current = int.from_bytes(raw[sign_count_index : sign_count_index + 4], "big")
        previous = state.previous_sign_count()
        new_value = current
        if mutation.sign_count_mode == "stall" and previous is not None:
            new_value = previous
        if mutation.sign_count_mode == "rollback":
            if previous is not None:
                new_value = max(0, previous - 1)
            else:
                new_value = max(0, current - 1)
        if new_value != current:
            raw[sign_count_index : sign_count_index + 4] = new_value.to_bytes(4, "big")
            changed = True
            log.mark(f"{path}: set signCount {current} -> {new_value}")

    if not changed:
        return None
    return b64url_encode(bytes(raw))


def _mutate_attestation_object(
    encoded: str,
    mutation: MutationConfig,
    log: MutationLog,
    path: str,
) -> str | None:
    if cbor is None:
        log.error(f"{path}: fido2.cbor unavailable, attestation mutation skipped")
        return None

    try:
        obj = _cbor_decode(b64url_decode(encoded))
    except Exception as exc:
        log.error(f"{path}: attestationObject decode failed: {exc}")
        return None

    if not isinstance(obj, dict):
        log.error(f"{path}: attestationObject was not a CBOR map")
        return None

    changed = False
    if mutation.attestation_fmt:
        obj["fmt"] = mutation.attestation_fmt
        changed = True
        log.mark(f"{path}: attestation fmt -> {mutation.attestation_fmt}")

    att_stmt = obj.get("attStmt")
    if not isinstance(att_stmt, dict):
        att_stmt = {}
        obj["attStmt"] = att_stmt

    if mutation.clear_attestation_x5c and "x5c" in att_stmt:
        del att_stmt["x5c"]
        changed = True
        log.mark(f"{path}: removed attStmt.x5c")

    if mutation.inject_untrusted_x5c:
        att_stmt["x5c"] = [b"invalid-cert-chain"]
        changed = True
        log.mark(f"{path}: injected synthetic untrusted x5c")

    if mutation.attestation_fmt == "none":
        obj["attStmt"] = {}
        changed = True
        log.mark(f"{path}: forced empty attStmt for fmt=none")

    if not changed:
        return None

    try:
        encoded_new = _cbor_encode(obj)
    except Exception as exc:
        log.error(f"{path}: attestationObject encode failed: {exc}")
        return None
    return b64url_encode(encoded_new)


def _cbor_decode(blob: bytes) -> Any:
    if hasattr(cbor, "decode"):
        return cbor.decode(blob)
    if hasattr(cbor, "loads"):
        return cbor.loads(blob)
    raise RuntimeError("fido2.cbor decode function not found")


def _cbor_encode(obj: Any) -> bytes:
    if hasattr(cbor, "encode"):
        return cbor.encode(obj)
    if hasattr(cbor, "dumps"):
        return cbor.dumps(obj)
    raise RuntimeError("fido2.cbor encode function not found")
