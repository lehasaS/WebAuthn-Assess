from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from copy import deepcopy
from typing import Any, Literal

CaptureSelector = Literal["last", "last-assertion", "last-registration"]


def select_submission(
    submissions: list[dict[str, Any]], selector: CaptureSelector
) -> dict[str, Any] | None:
    if selector == "last":
        return submissions[-1] if submissions else None
    if selector == "last-assertion":
        for item in reversed(submissions):
            if _has_response_field(item.get("final_json"), "signature"):
                return item
        return None
    if selector == "last-registration":
        for item in reversed(submissions):
            if _has_response_field(item.get("final_json"), "attestationObject"):
                return item
        return None
    return None


def replay_submission(
    submission: dict[str, Any],
    url_override: str | None = None,
    proxy: str | None = None,
    timeout_seconds: int = 30,
    method_override: str | None = None,
    header_overrides: dict[str, str] | None = None,
    cookie_override: str | None = None,
    json_overrides: dict[str, Any] | None = None,
    repeat_count: int = 1,
    interval_ms: int = 0,
) -> dict[str, Any]:
    url = url_override or submission.get("url")
    method = (method_override or submission.get("method", "POST")).upper()
    final_json = submission.get("final_json")

    if not isinstance(url, str) or not url:
        raise ValueError("Replay target URL is missing")
    if not isinstance(final_json, (dict, list)):
        raise ValueError("Replay payload is missing JSON body")

    body_obj = deepcopy(final_json)
    for path, value in (json_overrides or {}).items():
        _set_json_path(body_obj, path, value)

    headers = {"Content-Type": "application/json"}
    for key, value in (header_overrides or {}).items():
        headers[str(key)] = str(value)
    if cookie_override is not None:
        headers["Cookie"] = cookie_override

    attempts: list[dict[str, Any]] = []
    repeat_count = max(1, int(repeat_count))
    interval_s = max(0.0, interval_ms / 1000.0)

    for idx in range(repeat_count):
        payload = json.dumps(body_obj, separators=(",", ":")).encode("utf-8")
        attempts.append(
            _send_once(
                url=url,
                method=method,
                payload=payload,
                headers=headers,
                proxy=proxy,
                timeout_seconds=timeout_seconds,
                attempt=idx + 1,
            )
        )
        if idx + 1 < repeat_count and interval_s > 0:
            time.sleep(interval_s)

    final_attempt = attempts[-1]
    return {
        "ok": all(item.get("ok") for item in attempts),
        "status": final_attempt.get("status", 0),
        "url": url,
        "method": method,
        "request_headers": headers,
        "request_json": body_obj,
        "body_preview": final_attempt.get("body_preview"),
        "attempts": attempts,
        "repeat_count": repeat_count,
        "interval_ms": int(interval_ms),
    }


def _send_once(
    *,
    url: str,
    method: str,
    payload: bytes,
    headers: dict[str, str],
    proxy: str | None,
    timeout_seconds: int,
    attempt: int,
) -> dict[str, Any]:
    started = time.monotonic()
    req = urllib.request.Request(url=url, method=method, data=payload, headers=headers)

    handlers = []
    if proxy:
        handlers.append(urllib.request.ProxyHandler({"http": proxy, "https": proxy}))

    opener = urllib.request.build_opener(*handlers)
    try:
        with opener.open(req, timeout=timeout_seconds) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            return {
                "attempt": attempt,
                "ok": 200 <= resp.status < 300,
                "status": resp.status,
                "elapsed_ms": int((time.monotonic() - started) * 1000),
                "body_preview": body[:4000],
            }
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        return {
            "attempt": attempt,
            "ok": False,
            "status": exc.code,
            "elapsed_ms": int((time.monotonic() - started) * 1000),
            "body_preview": body[:4000],
        }
    except urllib.error.URLError as exc:
        return {
            "attempt": attempt,
            "ok": False,
            "status": 0,
            "elapsed_ms": int((time.monotonic() - started) * 1000),
            "body_preview": f"connection error: {exc}",
        }


def _set_json_path(root: Any, path: str, value: Any) -> None:
    parts = [part for part in path.split(".") if part]
    if not parts:
        raise ValueError("empty json override path")

    node = root
    for key in parts[:-1]:
        if not isinstance(node, dict):
            raise ValueError(f"cannot traverse non-object at '{key}' in path '{path}'")
        if key not in node or not isinstance(node[key], dict):
            node[key] = {}
        node = node[key]
    if not isinstance(node, dict):
        raise ValueError(f"cannot set path '{path}' on non-object")
    node[parts[-1]] = value


def _has_response_field(payload: Any, field: str) -> bool:
    if isinstance(payload, dict):
        response = payload.get("response")
        if isinstance(response, dict) and field in response:
            return True
        return any(_has_response_field(value, field) for value in payload.values())
    if isinstance(payload, list):
        return any(_has_response_field(item, field) for item in payload)
    return False
