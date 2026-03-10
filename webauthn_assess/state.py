from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .encoding import b64url_decode
from .persistence import atomic_write_json


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


@dataclass(slots=True)
class SubmissionRecord:
    timestamp: str
    method: str
    url: str
    mutated: bool
    original_json: dict[str, Any] | list[Any] | None
    final_json: dict[str, Any] | list[Any] | None
    parse_error: str | None = None


class StateStore:
    def __init__(self, path: Path, autosave: bool = True) -> None:
        self.path = path
        self.autosave = autosave
        self._data = self._load()

    def _default(self) -> dict[str, Any]:
        return {
            "version": 1,
            "updated_at": _utc_now(),
            "last_challenges": {"register": None, "auth": None},
            "last_sign_count": None,
            "last_registration": None,
            "last_assertion": None,
            "credentials": {},
            "virtual_credentials": [],
            "submissions": [],
            "responses": [],
        }

    def _load(self) -> dict[str, Any]:
        if not self.path.exists():
            return self._default()
        try:
            raw = self.path.read_text(encoding="utf-8")
            data = json.loads(raw)
        except Exception:
            return self._default()
        merged = self._default()
        merged.update(data)
        return merged

    def save(self) -> None:
        self._data["updated_at"] = _utc_now()
        atomic_write_json(self.path, self._data)

    def _autosave(self) -> None:
        if self.autosave:
            self.save()

    @property
    def data(self) -> dict[str, Any]:
        return self._data

    def previous_challenge(self, ceremony: str) -> str | None:
        challenges = self._data.get("last_challenges", {})
        return challenges.get(ceremony)

    def previous_sign_count(self) -> int | None:
        val = self._data.get("last_sign_count")
        return int(val) if isinstance(val, int) else None

    def any_credential_id(self) -> str | None:
        credentials = self._data.get("credentials", {})
        for cred_id in credentials:
            return cred_id
        return None

    def credential(self, credential_id: str) -> dict[str, Any] | None:
        return self._data.get("credentials", {}).get(credential_id)

    def virtual_credential(self, credential_id: str) -> dict[str, Any] | None:
        items = self._data.get("virtual_credentials", [])
        if not isinstance(items, list):
            return None
        for item in items:
            if not isinstance(item, dict):
                continue
            if item.get("credentialId") == credential_id:
                return item
        return None

    def clone_credential(self, credential_id: str, clone_id: str) -> bool:
        source = self.credential(credential_id)
        if source is not None:
            cloned = dict(source)
            cloned["cloned_from"] = credential_id
            cloned["stored_at"] = _utc_now()
            self._data.setdefault("credentials", {})[clone_id] = cloned
            self._autosave()
            return True

        virtual = self.virtual_credential(credential_id)
        if virtual is not None:
            cloned = dict(virtual)
            cloned["credentialId"] = clone_id
            cloned["cloned_from"] = credential_id
            cloned["stored_at"] = _utc_now()
            self._data.setdefault("virtual_credentials", []).append(cloned)
            self._autosave()
            return True

        return False

    def record_submission(self, submission: SubmissionRecord) -> None:
        submissions = self._data.setdefault("submissions", [])
        submissions.append(
            {
                "timestamp": submission.timestamp,
                "method": submission.method,
                "url": submission.url,
                "mutated": submission.mutated,
                "original_json": submission.original_json,
                "final_json": submission.final_json,
                "parse_error": submission.parse_error,
            }
        )
        if len(submissions) > 100:
            del submissions[:-100]
        self._autosave()

    def record_response(self, response: dict[str, Any]) -> None:
        responses = self._data.setdefault("responses", [])
        responses.append(response)
        if len(responses) > 100:
            del responses[:-100]
        self._autosave()

    def record_virtual_credentials(self, credentials: list[dict[str, Any]]) -> None:
        current = self._data.setdefault("virtual_credentials", [])
        by_id: dict[str, dict[str, Any]] = {}
        for item in current:
            if not isinstance(item, dict):
                continue
            cid = item.get("credentialId")
            if isinstance(cid, str):
                by_id[cid] = item
        for item in credentials:
            if not isinstance(item, dict):
                continue
            cid = item.get("credentialId")
            if not isinstance(cid, str):
                continue
            merged = dict(by_id.get(cid, {}))
            merged.update(item)
            merged["stored_at"] = _utc_now()
            by_id[cid] = merged
        self._data["virtual_credentials"] = list(by_id.values())
        self._autosave()

    def update_from_js_event(self, event: dict[str, Any]) -> None:
        changed = False
        stage = event.get("stage")
        ceremony = event.get("ceremony")
        if stage == "options":
            challenge = (
                event.get("options", {})
                .get("publicKey", {})
                .get("challenge")
            )
            if isinstance(challenge, str) and ceremony in {"register", "auth"}:
                self._data.setdefault("last_challenges", {})[ceremony] = challenge
                changed = True
            if changed:
                self._autosave()
            return

        if stage != "result":
            return

        credential = event.get("credential")
        if not isinstance(credential, dict):
            return

        cred_id = credential.get("id")
        if isinstance(cred_id, str):
            entry = {
                "id": cred_id,
                "rawId": credential.get("rawId"),
                "type": credential.get("type"),
                "response_keys": sorted(list(credential.get("response", {}).keys())),
                "stored_at": _utc_now(),
            }
            self._data.setdefault("credentials", {})[cred_id] = entry
            changed = True

        if ceremony == "register":
            self._data["last_registration"] = credential
            changed = True
        if ceremony == "auth":
            self._data["last_assertion"] = credential
            changed = True
            response = credential.get("response", {})
            auth_data = response.get("authenticatorData")
            if isinstance(auth_data, str):
                sign_count = _extract_sign_count(auth_data)
                if sign_count is not None:
                    self._data["last_sign_count"] = sign_count
                    changed = True
        if changed:
            self._autosave()


def _extract_sign_count(authenticator_data_b64url: str) -> int | None:
    try:
        raw = b64url_decode(authenticator_data_b64url)
    except Exception:
        return None
    if len(raw) < 37:
        return None
    return int.from_bytes(raw[33:37], "big")
