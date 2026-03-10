from __future__ import annotations

import argparse
import signal
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .config import AuthenticatorConfig, RunConfig
from .persistence import atomic_write_json
from .profiles import get_profile, profile_names
from .replay import replay_submission, select_submission
from .state import StateStore


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command in {"register", "auth"}:
        return _run_browser_command(args)
    if args.command == "replay":
        return _run_replay(args)
    if args.command == "clone":
        return _run_clone(args)

    parser.print_help()
    return 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="webauthn-assess",
        description="Compact WebAuthn assessment tool using Chromium virtual authenticators",
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
        help="Set UV state or spoof UV flag in mutation mode",
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
    parser.add_argument(
        "--mode", choices=["normal", "mutation"], default="normal", help="Execution mode"
    )
    parser.add_argument(
        "--profile",
        choices=profile_names(),
        default="baseline",
        help="Mutation profile",
    )
    parser.add_argument("--trigger-js", help="JavaScript snippet to trigger ceremony in page context")
    parser.add_argument("--wait-seconds", type=float, default=15.0, help="Wait window after page load")
    parser.add_argument(
        "--allow-retries",
        action="store_true",
        help="Do not auto-stop after first captured WebAuthn submission in mutation mode",
    )
    parser.add_argument("--headless", action="store_true", help="Launch Chromium in headless mode")
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

    parser.add_argument("--protocol", choices=["ctap2", "u2f"], default="ctap2")
    parser.add_argument("--transport", choices=["usb", "nfc", "ble", "internal"], default="usb")
    parser.add_argument("--resident-key", choices=["on", "off"], default="on")
    parser.add_argument("--uv-support", choices=["on", "off"], default="on")
    parser.add_argument("--uv-state", choices=["on", "off"], default="on")
    parser.add_argument("--presence-sim", choices=["on", "off"], default="on")

    parser.add_argument("--tamper-origin", help="Replace clientDataJSON.origin")
    parser.add_argument(
        "--tamper-challenge",
        help="Replace clientDataJSON.challenge with stale/random/or explicit value",
    )
    parser.add_argument("--tamper-type", help="Replace clientDataJSON.type")
    parser.add_argument("--force-uv", choices=["on", "off"], help="Force UV flag in authenticatorData")
    parser.add_argument("--force-up", choices=["on", "off"], help="Force UP flag in authenticatorData")
    parser.add_argument("--sign-count-mode", choices=["stall", "rollback"])
    parser.add_argument("--attestation-fmt", help="Override attestationObject fmt field")
    parser.add_argument("--clear-x5c", action="store_true", help="Remove attStmt.x5c")
    parser.add_argument("--inject-untrusted-x5c", action="store_true")
    parser.add_argument("--duplicate-credential-id", action="store_true")
    parser.add_argument("--rp-id-override", help="Override RP ID in JS options before signing")
    parser.add_argument("--alg-override", type=int, help="Override pubKeyCredParams algorithm")

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
            print(
                "playwright is not installed. Install dependencies and run: "
                "`pip install -e .` then `playwright install chromium`"
            )
            return 1
        raise

    state = StateStore(args.state_path)
    mutation = get_profile(args.profile)
    _apply_mutation_overrides(mutation, args)

    if args.cdp_url and args.attach_pid is not None:
        print("use either --cdp-url or --attach-pid, not both")
        return 1

    cdp_url = args.cdp_url
    if args.attach_pid is not None:
        cdp_url, err = _resolve_cdp_url_from_pid(args.attach_pid)
        if not cdp_url:
            print(f"unable to attach to pid {args.attach_pid}: {err}")
            return 1
        print(f"attach pid {args.attach_pid} -> {cdp_url}")

    mode = args.mode
    if mode == "normal":
        mutation.enabled = False

    if args.command == "auth" and args.uv == "spoof":
        mode = "mutation"
        mutation.enabled = True
        mutation.force_uv_flag = True
        if mutation.force_up_flag is None:
            mutation.force_up_flag = True

    authenticator = AuthenticatorConfig(
        protocol=args.protocol,
        transport=args.transport,
        has_resident_key=(args.resident_key == "on"),
        has_user_verification=(args.uv_support == "on"),
        is_user_verified=(args.uv_state == "on"),
        automatic_presence_simulation=(args.presence_sim == "on"),
    )

    if args.command == "auth" and args.uv in {"on", "off"}:
        authenticator.is_user_verified = args.uv == "on"

    output_path = args.output or _default_report_path(args.command, args.profile)

    cfg = RunConfig(
        ceremony=args.command,
        url=args.url,
        mode=mode,
        profile=args.profile,
        chromium_executable=(None if cdp_url else args.chromium_executable),
        cdp_url=cdp_url,
        verbose=args.verbose,
        trigger_js=args.trigger_js,
        wait_seconds=args.wait_seconds,
        stop_after_first_webauthn=(mode == "mutation" and not args.allow_retries),
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
            report = WebAuthnRunner(cfg, state).run()
    except KeyboardInterrupt:
        print(f"report: {output_path}")
        print("interrupted; partial state/report was checkpointed")
        return 130
    except Exception as exc:
        print(f"report: {output_path}")
        print(f"run failed: {exc}")
        return 1

    atomic_write_json(output_path, report)

    print(f"report: {output_path}")
    print(f"js events: {len(report.get('js_events', []))}")
    print(f"submissions: {len(report.get('submissions', []))}")
    mutated = sum(1 for s in report.get("submissions", []) if s.get("mutated"))
    print(f"mutated submissions: {mutated}")
    print(f"responses: {len(report.get('responses', []))}")
    if report.get("errors"):
        print("errors:")
        for err in report["errors"]:
            print(f"  - {err}")
    return 0


def _run_replay(args: argparse.Namespace) -> int:
    state = StateStore(args.state_path)
    submissions = state.data.get("submissions", [])
    if not isinstance(submissions, list):
        print("state does not contain submissions")
        return 1

    submission = select_submission(submissions, args.capture)
    if submission is None:
        print(f"no submission matched selector: {args.capture}")
        return 1

    result = replay_submission(
        submission=submission,
        url_override=args.url_override,
        proxy=args.proxy,
        timeout_seconds=args.timeout_seconds,
    )
    result["replayed_at"] = datetime.now(UTC).isoformat()
    result["capture"] = args.capture
    state.record_response(result)

    if args.output:
        atomic_write_json(args.output, {"submission": submission, "result": result})
        print(f"replay report: {args.output}")

    print(f"replay status: {result['status']} ok={result['ok']}")
    print(f"target: {result['url']}")
    return 0 if result["ok"] else 2


def _run_clone(args: argparse.Namespace) -> int:
    state = StateStore(args.state_path)
    clone_id = args.clone_id or f"{args.credential}-clone"
    ok = state.clone_credential(args.credential, clone_id)
    if not ok:
        print(f"credential not found: {args.credential}")
        return 1
    print(f"cloned credential {args.credential} -> {clone_id}")
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
