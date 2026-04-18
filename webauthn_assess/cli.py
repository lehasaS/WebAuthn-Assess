from __future__ import annotations

import argparse
import json
import signal
import sys
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .config import AuthenticatorConfig, RunConfig
from .persistence import atomic_write_json
from .profiles import ProfileDefaults, get_profile, get_profile_defaults, profile_names
from .replay import replay_submission, select_submission
from .state import StateStore
from .terminal import colorize, resolve_color_enabled


_COLOR_ENABLED = False


def _set_color_mode(mode: str) -> None:
    global _COLOR_ENABLED
    _COLOR_ENABLED = resolve_color_enabled(mode, stream=sys.stdout)


def _tone(text: str, kind: str = "plain") -> str:
    palette = {
        "plain": {},
        "dim": {"dim": True},
        "info": {"fg": "cyan"},
        "accent": {"fg": "blue", "bold": True},
        "success": {"fg": "green", "bold": True},
        "warn": {"fg": "yellow", "bold": True},
        "error": {"fg": "red", "bold": True},
    }
    style = palette.get(kind, {})
    return colorize(text, enabled=_COLOR_ENABLED, **style)


def _emit(text: str, kind: str = "plain") -> None:
    print(_tone(text, kind))


def _emit_kv(label: str, value: Any, *, value_kind: str = "plain") -> None:
    print(f"{_tone(label + ':', 'accent')} {_tone(str(value), value_kind)}")


def _format_value_summary(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, (bool, int, float)):
        return str(value)
    if isinstance(value, str):
        if len(value) > 200:
            return value[:120] + "..." + value[-32:]
        return value
    if not isinstance(value, dict):
        return str(value)

    value_type = value.get("type")
    if value_type == "string":
        decoded_client = value.get("decoded_client_data")
        if isinstance(decoded_client, dict):
            parts = []
            for key in ("type", "origin", "challenge"):
                if key in decoded_client:
                    parts.append(f"{key}={decoded_client.get(key)}")
            if parts:
                return "clientData(" + ", ".join(parts) + ")"
        decoded_auth = value.get("decoded_authenticator_data")
        if isinstance(decoded_auth, dict):
            flags = decoded_auth.get("flags")
            up = decoded_auth.get("up")
            uv = decoded_auth.get("uv")
            sign_count = decoded_auth.get("sign_count")
            return (
                f"authData(flags={flags}, UP={up}, UV={uv}, signCount={sign_count})"
            )
        if "value" in value:
            text = str(value["value"])
            if len(text) > 200:
                return text[:120] + "..." + text[-32:]
            return text
        if "preview" in value:
            return str(value["preview"])
        sha = value.get("sha256")
        length = value.get("length")
        return f"string(len={length}, sha256={sha})"
    if value_type == "object":
        keys = value.get("keys")
        return f"object(keys={keys})"
    if value_type == "array":
        length = value.get("length")
        return f"array(len={length})"
    return str(value)


def _emit_mutation_diff(diff: dict[str, Any], *, indent: str = "  ", limit: int = 8) -> None:
    operations = diff.get("operations")
    if not isinstance(operations, list) or not operations:
        return
    shown = operations[:limit]
    for op in shown:
        if not isinstance(op, dict):
            continue
        path = op.get("path", "<unknown>")
        action = op.get("op", "replace")
        before = _format_value_summary(op.get("before"))
        after = _format_value_summary(op.get("after"))
        _emit(f"{indent}{action} {path}", "info")
        _emit(f"{indent}  before: {before}", "dim")
        _emit(f"{indent}  after : {after}", "dim")
    if len(operations) > limit:
        _emit(f"{indent}... {len(operations) - limit} more changes", "dim")


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    _set_color_mode(getattr(args, "color", "auto"))

    if args.command in {"register", "auth"}:
        return _run_browser_command(args)
    if args.command == "replay":
        return _run_replay(args)
    if args.command == "clone":
        return _run_clone(args)
    if args.command == "inspect-state":
        return _run_inspect_state(args)

    parser.print_help()
    return 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="webauthn-assess",
        description="Compact WebAuthn assessment tool using Chromium virtual authenticators",
    )
    parser.add_argument(
        "--color",
        choices=["auto", "always", "never"],
        default="auto",
        help="Terminal color mode for CLI output",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    register = subparsers.add_parser("register", help="Run registration ceremony capture/mutation")
    _add_browser_args(register, ceremony="register")

    auth = subparsers.add_parser("auth", help="Run authentication ceremony capture/mutation")
    _add_browser_args(auth, ceremony="auth")
    auth.add_argument(
        "--uv",
        choices=["on", "off", "spoof"],
        default=None,
        help="Authenticator state: set real UV state or request post-ceremony UV spoof mutation",
    )

    replay = subparsers.add_parser("replay", help="Replay a stored captured payload")
    replay.add_argument(
        "--capture",
        choices=["last", "last-assertion", "last-registration"],
        default="last-assertion",
        help="Select which stored payload to replay",
    )
    replay.add_argument("--url", dest="url_override", help="Override replay target URL")
    replay.add_argument("--proxy", help="Proxy URL for replay request")
    replay.add_argument("--timeout-seconds", type=int, default=30)
    replay.add_argument("--method", help="Override HTTP method (default: captured method)")
    replay.add_argument(
        "--header",
        action="append",
        default=[],
        help="Override/add replay header as KEY:VALUE (repeatable)",
    )
    replay.add_argument("--cookie", help="Override Cookie header")
    replay.add_argument(
        "--json-override",
        action="append",
        default=[],
        help="Override replay JSON body path as path.to.field=jsonValue (repeatable)",
    )
    replay.add_argument("--repeat", type=int, default=1, help="Replay count")
    replay.add_argument("--interval-ms", type=int, default=0, help="Replay interval milliseconds")
    replay.add_argument(
        "--state-path",
        type=Path,
        default=Path(".webauthn_assess/state.json"),
        help="State file path",
    )
    replay.add_argument("--output", type=Path, help="Write replay report JSON")

    clone = subparsers.add_parser("clone", help="Clone a stored credential entry in local state")
    clone.add_argument("--credential", required=True, help="Source credential ID")
    clone.add_argument("--clone-id", help="New credential ID")
    clone.add_argument(
        "--state-path",
        type=Path,
        default=Path(".webauthn_assess/state.json"),
        help="State file path",
    )

    inspect_state = subparsers.add_parser("inspect-state", help="Inspect stored state and credential metadata")
    inspect_state.add_argument(
        "--state-path",
        type=Path,
        default=Path(".webauthn_assess/state.json"),
        help="State file path",
    )
    inspect_state.add_argument("--json", action="store_true", help="Print full state JSON")

    return parser


def _add_browser_args(parser: argparse.ArgumentParser, ceremony: str) -> None:
    parser.add_argument("--url", required=True, help="Target page URL")
    parser.add_argument("--verbose", action="store_true", help="Enable live terminal logs")
    parser.add_argument(
        "--chromium-executable",
        help="Custom Chromium executable path (ignored when using --cdp-url/--attach-pid)",
    )
    parser.add_argument(
        "--cdp-url",
        help="Attach to an existing Chromium instance via CDP (e.g. http://127.0.0.1:9222)",
    )
    parser.add_argument(
        "--attach-pid",
        type=int,
        help="Resolve CDP URL from a running Chromium PID (requires --remote-debugging-port)",
    )
    parser.add_argument("--mode", choices=["normal", "mutation"], default="normal", help="Execution mode")
    parser.add_argument("--profile", choices=profile_names(), default="baseline", help="Mutation profile")
    parser.add_argument("--trigger-js", help="JavaScript snippet to trigger ceremony in page context")
    parser.add_argument("--wait-seconds", type=float, default=15.0, help="Wait window after page load")
    parser.add_argument(
        "--allow-retries",
        action="store_true",
        help="Disable profile defaults that stop on first meaningful failure (legacy convenience toggle)",
    )

    parser.add_argument("--max-attempts", type=int, help="Guard: max captured WebAuthn submissions before stop")
    parser.add_argument(
        "--stop-on-first-submission",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="Guard: stop as soon as first WebAuthn submission is captured",
    )
    parser.add_argument(
        "--stop-on-first-response",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="Guard: stop as soon as first correlated response is captured",
    )
    parser.add_argument(
        "--stop-on-response-error",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="Guard: stop when application-level response classification is rejected",
    )
    parser.add_argument(
        "--stop-on-first-cdp-event",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="Guard: stop on first CDP credentialAdded/credentialAsserted event",
    )

    parser.add_argument("--headless", action="store_true", help="Launch Chromium in headless mode")
    parser.add_argument(
        "--keep-open",
        action="store_true",
        help=(
            "Keep browser/context open after initial capture until interrupted "
            "(useful for manual follow-on interaction)"
        ),
    )
    parser.add_argument("--timeout-ms", type=int, default=30_000, help="Playwright timeout in milliseconds")
    parser.add_argument("--proxy", help="Proxy server URL for browser traffic")
    parser.add_argument("--output", type=Path, help="Write report JSON to this file")
    parser.add_argument(
        "--preload-credential",
        action="append",
        default=[],
        help="Credential ID from state.virtual_credentials to preload via CDP",
    )
    parser.add_argument(
        "--state-path",
        type=Path,
        default=Path(".webauthn_assess/state.json"),
        help="State file path",
    )

    parser.add_argument(
        "--protocol",
        choices=["ctap2", "u2f"],
        default="ctap2",
        help="Authenticator state: virtual authenticator protocol",
    )
    parser.add_argument(
        "--transport",
        choices=["usb", "nfc", "ble", "internal"],
        default="usb",
        help="Authenticator state: virtual authenticator transport",
    )
    parser.add_argument(
        "--resident-key",
        choices=["on", "off"],
        default="on",
        help="Authenticator state: resident key capability",
    )
    parser.add_argument(
        "--uv-support",
        choices=["on", "off"],
        default="on",
        help="Authenticator state: whether authenticator advertises UV capability",
    )
    parser.add_argument(
        "--uv-state",
        choices=["on", "off"],
        default="on",
        help="Authenticator state: real user verified state in virtual authenticator",
    )
    parser.add_argument(
        "--presence-sim",
        choices=["on", "off"],
        default="on",
        help="Authenticator state: automatic presence simulation",
    )

    parser.add_argument(
        "--rp-id-override",
        help="Pre-ceremony mutation: replace publicKey.rp.id / rpId before browser ceremony",
    )
    parser.add_argument(
        "--alg-override",
        type=int,
        help="Pre-ceremony mutation: replace publicKey.pubKeyCredParams algorithm list",
    )
    parser.add_argument(
        "--attestation-request-mode",
        choices=["none", "direct", "indirect", "enterprise"],
        help="Pre-ceremony mutation: override registration attestation request mode",
    )

    parser.add_argument(
        "--tamper-origin",
        help="Post-ceremony mutation: rewrite clientDataJSON.origin before submission",
    )
    parser.add_argument(
        "--tamper-challenge",
        help=(
            "Post-ceremony mutation: challenge mode "
            "(last-assertion,last-registration,stale,random,empty,null,missing,<explicit-value>)"
        ),
    )
    parser.add_argument(
        "--tamper-type",
        help="Post-ceremony mutation: rewrite clientDataJSON.type before submission",
    )
    parser.add_argument(
        "--force-uv",
        choices=["on", "off"],
        help="Post-ceremony mutation: force UV flag in authenticatorData",
    )
    parser.add_argument(
        "--force-up",
        choices=["on", "off"],
        help="Post-ceremony mutation: force UP flag in authenticatorData",
    )
    parser.add_argument(
        "--sign-count-mode",
        choices=["stall", "rollback"],
        help="Post-ceremony mutation: force signCount stall/rollback",
    )
    parser.add_argument(
        "--attestation-fmt",
        help="Post-ceremony mutation: override attestationObject fmt field",
    )
    parser.add_argument("--clear-x5c", action="store_true", help="Post-ceremony mutation: remove attStmt.x5c")
    parser.add_argument(
        "--inject-untrusted-x5c",
        action="store_true",
        help="Post-ceremony mutation: inject synthetic untrusted x5c chain",
    )
    parser.add_argument(
        "--duplicate-credential-id",
        action="store_true",
        help="Post-ceremony mutation: duplicate credential id from prior state",
    )

    if ceremony == "register":
        parser.add_argument(
            "--attestation",
            choices=["none", "self", "direct", "enterprise"],
            help="Shortcut for attestation mutation experiments",
        )


def _run_browser_command(args: argparse.Namespace) -> int:
    try:
        from .browser import WebAuthnRunner
    except ModuleNotFoundError as exc:
        if exc.name == "playwright":
            _emit(
                "playwright is not installed. Install dependencies and run: "
                "`pip install -e .` then `playwright install chromium`",
                "error",
            )
            return 1
        raise

    state = StateStore(args.state_path)
    mutation = get_profile(args.profile)
    profile_defaults = get_profile_defaults(args.profile)
    _apply_mutation_overrides(mutation, args)

    if args.cdp_url and args.attach_pid is not None:
        _emit("use either --cdp-url or --attach-pid, not both", "error")
        return 1

    cdp_url = args.cdp_url
    if args.attach_pid is not None:
        cdp_url, err = _resolve_cdp_url_from_pid(args.attach_pid)
        if not cdp_url:
            _emit(f"unable to attach to pid {args.attach_pid}: {err}", "error")
            return 1
        _emit(f"attach pid {args.attach_pid} -> {cdp_url}", "info")

    mode = args.mode
    if mode == "normal":
        mutation.enabled = False

    if args.command == "auth" and args.uv == "spoof":
        mode = "mutation"
        mutation.enabled = True
        mutation.force_uv_flag = True
        if mutation.force_up_flag is None:
            mutation.force_up_flag = True

    fallback_failure_defaults = ProfileDefaults(
        expected_outcome="expected-failure",
        max_attempts=1,
        stop_on_first_response=True,
        stop_on_response_error=True,
    )
    if _has_failure_oriented_override(args):
        profile_defaults = _merge_profile_defaults(profile_defaults, fallback_failure_defaults)

    stop_cfg = _resolve_stop_guards(args, mode, profile_defaults)

    effective_uv_support = args.uv_support == "on"
    effective_uv_state = args.uv_state == "on"
    if args.command == "auth" and args.uv in {"on", "off"}:
        effective_uv_state = args.uv == "on"

    if args.command == "auth" and mode == "normal" and effective_uv_support and not effective_uv_state:
        _emit(
            "warning: auth with UV capability enabled but real UV state off often causes "
            "Chromium virtual authenticators to raise NotAllowedError instead of returning "
            "a UV=false assertion; use --uv-support off for a clean non-UV-capable device "
            "test, or use mutation mode for post-ceremony UV tampering",
            "warn",
        )

    authenticator = AuthenticatorConfig(
        protocol=args.protocol,
        transport=args.transport,
        has_resident_key=(args.resident_key == "on"),
        has_user_verification=effective_uv_support,
        is_user_verified=effective_uv_state,
        automatic_presence_simulation=(args.presence_sim == "on"),
    )

    output_path = args.output or _default_report_path(args.command, args.profile)

    cfg = RunConfig(
        ceremony=args.command,
        url=args.url,
        mode=mode,
        color_mode=args.color,
        profile=args.profile,
        chromium_executable=(None if cdp_url else args.chromium_executable),
        cdp_url=cdp_url,
        verbose=args.verbose,
        trigger_js=args.trigger_js,
        wait_seconds=args.wait_seconds,
        max_attempts=stop_cfg["max_attempts"],
        stop_on_first_submission=stop_cfg["stop_on_first_submission"],
        stop_on_first_response=stop_cfg["stop_on_first_response"],
        stop_on_response_error=stop_cfg["stop_on_response_error"],
        stop_on_first_cdp_event=stop_cfg["stop_on_first_cdp_event"],
        keep_open=args.keep_open,
        headless=args.headless,
        timeout_ms=args.timeout_ms,
        proxy=args.proxy,
        output_path=output_path,
        state_path=args.state_path,
        preload_credential_ids=list(args.preload_credential or []),
        authenticator=authenticator,
        mutation=mutation,
    )

    try:
        with _graceful_interrupts():
            state.record_profile_run(
                {
                    "timestamp": datetime.now(UTC).isoformat(),
                    "command": args.command,
                    "profile": args.profile,
                    "mode": mode,
                    "url": args.url,
                    "defaults": {
                        "expected_outcome": profile_defaults.expected_outcome,
                        **stop_cfg,
                    },
                }
            )
            report = WebAuthnRunner(cfg, state).run()
    except KeyboardInterrupt:
        _emit_kv("report", output_path, value_kind="info")
        if args.keep_open:
            _emit("keep-open session ended by user; report was checkpointed", "warn")
            return 0
        _emit("interrupted; partial state/report was checkpointed", "warn")
        return 130
    except Exception as exc:
        _emit_kv("report", output_path, value_kind="info")
        _emit(f"run failed: {exc}", "error")
        return 1

    atomic_write_json(output_path, report)

    _emit_kv("report", output_path, value_kind="info")
    _emit_kv("profile", report.get("profile"), value_kind="info")
    _emit_kv("mode", report.get("mode"), value_kind="info")
    _emit_kv("js events", len(report.get("js_events", [])))
    _emit_kv("submissions", len(report.get("submissions", [])))
    mutated = sum(1 for s in report.get("submissions", []) if s.get("mutated"))
    _emit_kv(
        "mutated submissions",
        mutated,
        value_kind="warn" if mutated else "plain",
    )
    _emit_kv("responses", len(report.get("responses", [])))
    if report.get("capture_status"):
        capture_status = str(report["capture_status"])
        capture_kind = "success" if capture_status == "succeeded" else "warn"
        _emit_kv("capture status", capture_status, value_kind=capture_kind)
    if report.get("result_classification"):
        classification = str(report["result_classification"])
        classification_kind = (
            "success"
            if classification in {"accepted", "redirected"}
            else "error"
            if "rejected" in classification
            else "warn"
        )
        _emit_kv("result classification", classification, value_kind=classification_kind)
    if mutated:
        _emit("mutation operations (captured):", "accent")
        for submission in report.get("submissions", []):
            if not isinstance(submission, dict) or not submission.get("mutated"):
                continue
            request_id = submission.get("request_id", "<unknown>")
            method = submission.get("method", "")
            url = submission.get("url", "")
            _emit(f"  {request_id} {method} {url}", "info")
            diff = submission.get("mutation_diff")
            if isinstance(diff, dict):
                _emit_mutation_diff(diff, indent="    ")
    if report.get("errors"):
        _emit("errors:", "error")
        for err in report["errors"]:
            _emit(f"  - {err}", "error")
    return 0


def _run_replay(args: argparse.Namespace) -> int:
    state = StateStore(args.state_path)
    submissions = state.data.get("submissions", [])
    if not isinstance(submissions, list):
        _emit("state does not contain submissions", "error")
        return 1

    submission = select_submission(submissions, args.capture)
    if submission is None:
        _emit(f"no submission matched selector: {args.capture}", "error")
        return 1

    try:
        headers = _parse_header_overrides(args.header)
        json_overrides = _parse_json_overrides(args.json_override)
    except ValueError as exc:
        _emit(str(exc), "error")
        return 1

    _emit("replay plan:", "accent")
    _emit_kv("capture", args.capture, value_kind="info")
    _emit_kv("request id", submission.get("request_id"), value_kind="info")
    _emit_kv("method", args.method or submission.get("method", "POST"), value_kind="info")
    _emit_kv("target", args.url_override or submission.get("url"), value_kind="info")
    _emit_kv("repeat", args.repeat, value_kind="info")
    if json_overrides:
        _emit("JSON overrides:", "accent")
        for path, value in json_overrides.items():
            _emit(f"  {path} = {value}", "info")
    mutation_diff = submission.get("mutation_diff")
    if isinstance(mutation_diff, dict) and mutation_diff.get("changed"):
        _emit("captured mutation diff (from original run):", "accent")
        _emit_mutation_diff(mutation_diff, indent="  ")

    result = replay_submission(
        submission=submission,
        url_override=args.url_override,
        proxy=args.proxy,
        timeout_seconds=args.timeout_seconds,
        method_override=args.method,
        header_overrides=headers,
        cookie_override=args.cookie,
        json_overrides=json_overrides,
        repeat_count=args.repeat,
        interval_ms=args.interval_ms,
    )
    result["replayed_at"] = datetime.now(UTC).isoformat()
    result["capture"] = args.capture
    state.record_response(result)

    if args.output:
        atomic_write_json(args.output, {"submission": submission, "result": result})
        _emit_kv("replay report", args.output, value_kind="info")

    replay_kind = "success" if result.get("ok") else "error"
    _emit_kv(
        "replay status",
        f"{result['status']} ok={result['ok']}",
        value_kind=replay_kind,
    )
    _emit_kv("target", result["url"], value_kind="info")
    attempts = result.get("attempts", [])
    _emit_kv("attempts", len(attempts))
    if isinstance(attempts, list):
        for attempt in attempts:
            if not isinstance(attempt, dict):
                continue
            status = attempt.get("status")
            ok = bool(attempt.get("ok"))
            elapsed_ms = attempt.get("elapsed_ms")
            line = f"  attempt #{attempt.get('attempt')} status={status} ok={ok} elapsed_ms={elapsed_ms}"
            _emit(line, "success" if ok else "warn")
    return 0 if result["ok"] else 2


def _run_clone(args: argparse.Namespace) -> int:
    state = StateStore(args.state_path)
    clone_id = args.clone_id or f"{args.credential}-clone"
    ok = state.clone_credential(args.credential, clone_id)
    if not ok:
        _emit(f"credential not found: {args.credential}", "error")
        return 1
    _emit(f"cloned credential {args.credential} -> {clone_id}", "success")
    return 0


def _run_inspect_state(args: argparse.Namespace) -> int:
    state = StateStore(args.state_path)
    data = state.data
    if args.json:
        print(json.dumps(data, indent=2, sort_keys=True))
        return 0

    credentials = data.get("credentials", {})
    virtual = data.get("virtual_credentials", [])
    profile_history = data.get("profile_history", [])

    _emit_kv("state path", args.state_path, value_kind="info")
    _emit_kv("credentials", len(credentials) if isinstance(credentials, dict) else 0)
    if isinstance(credentials, dict):
        for cred_id, item in credentials.items():
            sign_count = item.get("signCount") if isinstance(item, dict) else None
            cloned_from = item.get("cloned_from") if isinstance(item, dict) else None
            _emit(
                f"  - id={cred_id} signCount={sign_count} cloned_from={cloned_from}",
                "info",
            )

    _emit_kv("virtual credentials", len(virtual) if isinstance(virtual, list) else 0)
    if isinstance(virtual, list):
        for item in virtual:
            if not isinstance(item, dict):
                continue
            _emit(
                "  - "
                f"credentialId={item.get('credentialId')} "
                f"rpId={item.get('rpId')} "
                f"signCount={item.get('signCount')} "
                f"cloned_from={item.get('cloned_from')}",
                "info",
            )
    if isinstance(credentials, dict) and credentials and isinstance(virtual, list) and not virtual:
        _emit(
            "warning: captured credential metadata exists, but no preloadable virtual "
            "credentials were stored; auth --preload-credential requires a "
            "virtual_credentials entry with privateKey material",
            "warn",
        )

    last_registration = data.get("last_registration")
    last_assertion = data.get("last_assertion")
    _emit_kv("last registration present", bool(last_registration))
    if isinstance(last_registration, dict):
        response = last_registration.get("response")
        keys = sorted(response.keys()) if isinstance(response, dict) else []
        _emit(
            "  - "
            f"id={last_registration.get('id')} "
            f"type={last_registration.get('type')} "
            f"response_keys={keys}",
            "dim",
        )
    _emit_kv("last assertion present", bool(last_assertion))
    if isinstance(last_assertion, dict):
        response = last_assertion.get("response")
        keys = sorted(response.keys()) if isinstance(response, dict) else []
        _emit(
            "  - "
            f"id={last_assertion.get('id')} "
            f"type={last_assertion.get('type')} "
            f"response_keys={keys}",
            "dim",
        )
    submissions_stored = data.get("submissions", [])
    responses_stored = data.get("responses", [])
    _emit_kv("submissions stored", len(submissions_stored))
    _emit_kv("responses stored", len(responses_stored))
    _emit_kv(
        "profile history entries",
        len(profile_history) if isinstance(profile_history, list) else 0,
    )
    if isinstance(submissions_stored, list) and submissions_stored:
        last = submissions_stored[-1]
        if isinstance(last, dict):
            _emit("last submission:", "accent")
            _emit(
                "  - "
                f"{last.get('request_id')} {last.get('method')} {last.get('url')} "
                f"mutated={last.get('mutated')}",
                "info",
            )
            diff = last.get("mutation_diff")
            if isinstance(diff, dict) and diff.get("changed"):
                _emit("  changes:", "accent")
                _emit_mutation_diff(diff, indent="    ", limit=5)
    if isinstance(profile_history, list) and profile_history:
        for item in profile_history[-10:]:
            if not isinstance(item, dict):
                continue
            _emit(
                "  - "
                f"{item.get('timestamp')} "
                f"{item.get('command')} "
                f"profile={item.get('profile')} "
                f"mode={item.get('mode')}",
                "dim",
            )
    return 0


def _apply_mutation_overrides(mutation, args: argparse.Namespace) -> None:
    explicit = False

    def set_attr(name: str, value: Any) -> None:
        nonlocal explicit
        if value is None:
            return
        setattr(mutation, name, value)
        explicit = True

    set_attr("tamper_origin", args.tamper_origin)
    set_attr("tamper_challenge", args.tamper_challenge)
    set_attr("tamper_type", args.tamper_type)
    set_attr("sign_count_mode", args.sign_count_mode)
    set_attr("attestation_fmt", args.attestation_fmt)
    set_attr("rp_id_override", args.rp_id_override)
    set_attr("algorithm_override", args.alg_override)
    set_attr("attestation_request_mode_override", args.attestation_request_mode)

    if getattr(args, "force_uv", None):
        mutation.force_uv_flag = args.force_uv == "on"
        explicit = True
    if getattr(args, "force_up", None):
        mutation.force_up_flag = args.force_up == "on"
        explicit = True
    if getattr(args, "clear_x5c", False):
        mutation.clear_attestation_x5c = True
        explicit = True
    if getattr(args, "inject_untrusted_x5c", False):
        mutation.inject_untrusted_x5c = True
        explicit = True
    if getattr(args, "duplicate_credential_id", False):
        mutation.duplicate_credential_id = True
        explicit = True

    attestation = getattr(args, "attestation", None)
    if attestation:
        explicit = True
        mutation.attestation_request_mode_override = attestation
        if attestation == "none":
            mutation.attestation_fmt = "none"
            mutation.clear_attestation_x5c = True
        if attestation == "self":
            mutation.attestation_fmt = "packed"
            mutation.inject_untrusted_x5c = True
        if attestation in {"direct", "enterprise"}:
            mutation.attestation_fmt = "packed"

    if explicit:
        mutation.enabled = True


def _default_report_path(ceremony: str, profile: str) -> Path:
    ts = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    name = f"{ts}-{ceremony}-{profile}.json"
    return Path(".webauthn_assess/reports") / name


def _has_failure_oriented_override(args: argparse.Namespace) -> bool:
    return bool(
        getattr(args, "tamper_origin", None)
        or getattr(args, "tamper_type", None)
        or getattr(args, "tamper_challenge", None)
        or getattr(args, "force_uv", None)
        or getattr(args, "force_up", None)
        or getattr(args, "clear_x5c", False)
        or getattr(args, "inject_untrusted_x5c", False)
        or getattr(args, "attestation", None)
    )


def _merge_profile_defaults(base: ProfileDefaults, override: ProfileDefaults) -> ProfileDefaults:
    return ProfileDefaults(
        expected_outcome=(
            override.expected_outcome
            if base.expected_outcome in {"unknown", "baseline"}
            else base.expected_outcome
        ),
        max_attempts=base.max_attempts if base.max_attempts is not None else override.max_attempts,
        stop_on_first_submission=base.stop_on_first_submission or override.stop_on_first_submission,
        stop_on_first_response=base.stop_on_first_response or override.stop_on_first_response,
        stop_on_response_error=base.stop_on_response_error or override.stop_on_response_error,
        stop_on_first_cdp_event=base.stop_on_first_cdp_event or override.stop_on_first_cdp_event,
    )


def _resolve_stop_guards(
    args: argparse.Namespace,
    mode: str,
    defaults: ProfileDefaults,
) -> dict[str, Any]:
    max_attempts = args.max_attempts if args.max_attempts is not None else defaults.max_attempts
    stop_on_first_submission = _resolve_bool_arg(
        args.stop_on_first_submission, defaults.stop_on_first_submission
    )
    stop_on_first_response = _resolve_bool_arg(
        args.stop_on_first_response, defaults.stop_on_first_response
    )
    stop_on_response_error = _resolve_bool_arg(
        args.stop_on_response_error, defaults.stop_on_response_error
    )
    stop_on_first_cdp_event = _resolve_bool_arg(
        args.stop_on_first_cdp_event, defaults.stop_on_first_cdp_event
    )

    if args.allow_retries:
        max_attempts = None
        stop_on_first_submission = False
        stop_on_first_response = False
        stop_on_response_error = False
        stop_on_first_cdp_event = False

    if mode != "mutation" and defaults.expected_outcome == "baseline":
        # Baseline should still stop after first completed correlated exchange.
        stop_on_first_response = True if args.stop_on_first_response is None else stop_on_first_response
        if max_attempts is None:
            max_attempts = 1

    return {
        "max_attempts": max_attempts,
        "stop_on_first_submission": stop_on_first_submission,
        "stop_on_first_response": stop_on_first_response,
        "stop_on_response_error": stop_on_response_error,
        "stop_on_first_cdp_event": stop_on_first_cdp_event,
    }


def _resolve_bool_arg(value: bool | None, default: bool) -> bool:
    if value is None:
        return default
    return bool(value)


def _parse_header_overrides(items: list[str]) -> dict[str, str]:
    out: dict[str, str] = {}
    for item in items:
        if ":" not in item:
            raise ValueError(f"invalid --header value '{item}', expected KEY:VALUE")
        key, value = item.split(":", 1)
        out[key.strip()] = value.strip()
    return out


def _parse_json_overrides(items: list[str]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for item in items:
        if "=" not in item:
            raise ValueError(
                f"invalid --json-override value '{item}', expected path.to.field=jsonValue"
            )
        path, raw = item.split("=", 1)
        path = path.strip()
        raw = raw.strip()
        if not path:
            raise ValueError("json override path cannot be empty")
        try:
            value = json.loads(raw)
        except Exception:
            value = raw
        out[path] = value
    return out


@contextmanager
def _graceful_interrupts():
    def _raise_interrupt(signum, _frame) -> None:
        raise KeyboardInterrupt(f"signal {signum}")

    prev_int = signal.getsignal(signal.SIGINT)
    prev_term = signal.getsignal(signal.SIGTERM)
    signal.signal(signal.SIGINT, _raise_interrupt)
    signal.signal(signal.SIGTERM, _raise_interrupt)
    try:
        yield
    finally:
        signal.signal(signal.SIGINT, prev_int)
        signal.signal(signal.SIGTERM, prev_term)


def _resolve_cdp_url_from_pid(pid: int) -> tuple[str | None, str | None]:
    cmdline_path = Path(f"/proc/{pid}/cmdline")
    if not cmdline_path.exists():
        return None, "process not found"

    try:
        raw = cmdline_path.read_bytes()
    except Exception as exc:
        return None, f"unable to read process cmdline: {exc}"

    tokens = [x.decode("utf-8", errors="replace") for x in raw.split(b"\x00") if x]
    if not tokens:
        return None, "empty process cmdline"

    if "--remote-debugging-pipe" in tokens:
        return None, "process uses --remote-debugging-pipe (no HTTP CDP endpoint)"

    address = "127.0.0.1"
    port: str | None = None
    for idx, token in enumerate(tokens):
        if token.startswith("--remote-debugging-port="):
            port = token.split("=", 1)[1].strip()
            continue
        if token == "--remote-debugging-port" and idx + 1 < len(tokens):
            port = tokens[idx + 1].strip()
            continue
        if token.startswith("--remote-debugging-address="):
            address = token.split("=", 1)[1].strip() or address
            continue
        if token == "--remote-debugging-address" and idx + 1 < len(tokens):
            address = tokens[idx + 1].strip() or address
            continue

    if not port:
        return None, "missing --remote-debugging-port on target process"
    if not port.isdigit() or int(port) <= 0:
        return None, f"invalid remote debugging port: {port!r}"

    return f"http://{address}:{int(port)}", None


if __name__ == "__main__":
    raise SystemExit(main())
