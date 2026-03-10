from __future__ import annotations

import json
import urllib.error
import urllib.request
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
) -> dict[str, Any]:
    url = url_override or submission.get("url")
    method = submission.get("method", "POST")
    final_json = submission.get("final_json")

    if not isinstance(url, str) or not url:
        raise ValueError("Replay target URL is missing")
    if not isinstance(final_json, (dict, list)):
        raise ValueError("Replay payload is missing JSON body")

    payload = json.dumps(final_json, separators=(",", ":")).encode("utf-8")
    req = urllib.request.Request(
        url=url,
        method=method,
        data=payload,
        headers={"Content-Type": "application/json"},
    )

    handlers = []
    if proxy:
        handlers.append(urllib.request.ProxyHandler({"http": proxy, "https": proxy}))

    opener = urllib.request.build_opener(*handlers)
    try:
        with opener.open(req, timeout=timeout_seconds) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            return {
                "ok": 200 <= resp.status < 300,
                "status": resp.status,
                "url": url,
                "method": method,
                "body_preview": body[:2000],
            }
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        return {
            "ok": False,
            "status": exc.code,
            "url": url,
            "method": method,
            "body_preview": body[:2000],
        }
    except urllib.error.URLError as exc:
        return {
            "ok": False,
            "status": 0,
            "url": url,
            "method": method,
            "body_preview": f"connection error: {exc}",
        }


def _has_response_field(payload: Any, field: str) -> bool:
    if isinstance(payload, dict):
        response = payload.get("response")
        if isinstance(response, dict) and field in response:
            return True
        return any(_has_response_field(value, field) for value in payload.values())
    if isinstance(payload, list):
        return any(_has_response_field(item, field) for item in payload)
    return False
