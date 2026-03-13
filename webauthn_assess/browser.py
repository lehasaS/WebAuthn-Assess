from __future__ import annotations

import json
import time
from copy import deepcopy
from dataclasses import asdict
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlparse

from playwright.sync_api import BrowserContext, CDPSession, Page, sync_playwright

from .config import RunConfig
from .encoding import b64url_decode
from .instrumentation import build_init_script
from .mutation import contains_webauthn_payload, mutate_json_payload
from .persistence import atomic_write_json
from .reporting import (
    build_mutation_diff,
    classify_application_response,
    extract_challenges,
    stable_body_fingerprint,
)
from .state import StateStore, SubmissionRecord
from .terminal import colorize, resolve_color_enabled


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _to_epoch_seconds(ts: str | None) -> float | None:
    if not isinstance(ts, str):
        return None
    try:
        return datetime.fromisoformat(ts).timestamp()
    except Exception:
        return None


class WebAuthnRunner:
    def __init__(self, run_config: RunConfig, state: StateStore) -> None:
        self.cfg = run_config
        self.state = state
        self._color_enabled = resolve_color_enabled(self.cfg.color_mode)
        self._request_ids: dict[str, str] = {}
        self._recent_cycles: list[dict[str, Any]] = []
        self._challenge_last_seen: dict[str, str] = {}
        self._seen_js_event_keys: set[str] = set()

    def _log(self, message: str, *, kind: str | None = None) -> None:
        if not self.cfg.verbose:
            return
        level = kind or self._infer_log_kind(message)
        prefix = colorize(
            "[webauthn-assess]",
            fg="cyan",
            bold=True,
            enabled=self._color_enabled,
        )
        body = self._style_log_message(message, level)
        print(f"{prefix} {body}", flush=True)

    def _infer_log_kind(self, message: str) -> str:
        lowered = message.lower()
        if lowered.startswith("error") or "error:" in lowered or "failed" in lowered:
            return "error"
        if lowered.startswith("stop requested") or "max attempts reached" in lowered:
            return "warn"
        if lowered.startswith("response "):
            if "app=accepted" in lowered:
                return "success"
            if "app=redirected" in lowered:
                return "success"
            if "app=rejected" in lowered:
                return "error"
            return "info"
        if lowered.startswith("submission "):
            return "submission"
        if lowered.startswith("mutation"):
            return "mutation"
        if lowered.startswith("checkpoint saved"):
            return "dim"
        if lowered.startswith("cdp event"):
            return "cdp"
        if lowered.startswith("console[warning"):
            return "warn"
        if lowered.startswith("console[error"):
            return "error"
        if lowered.startswith("console["):
            return "dim"
        return "info"

    def _style_log_message(self, message: str, kind: str) -> str:
        palette: dict[str, dict[str, Any]] = {
            "info": {"fg": "white"},
            "success": {"fg": "green", "bold": True},
            "warn": {"fg": "yellow", "bold": True},
            "error": {"fg": "red", "bold": True},
            "submission": {"fg": "blue", "bold": True},
            "mutation": {"fg": "magenta"},
            "cdp": {"fg": "cyan"},
            "dim": {"dim": True},
        }
        style = palette.get(kind, palette["info"])
        return colorize(message, enabled=self._color_enabled, **style)

    def _record_error(self, report: dict[str, Any], message: str) -> None:
        report["errors"].append(message)
        self._log(f"ERROR {message}", kind="error")
        self._flush_report(report, reason="error")

    def _request_stop(self, report: dict[str, Any], reason: str) -> None:
        if report.get("stop_reason"):
            return
        report["stop_reason"] = reason
        self._log(f"stop requested: {reason}")
        self._flush_report(report, reason="stop")

    def _flush_report(
        self, report: dict[str, Any], *, reason: str, final: bool = False
    ) -> None:
        if not self.cfg.output_path:
            return
        snapshot = deepcopy(report)
        if final and "finished_at" not in snapshot:
            snapshot["finished_at"] = _now()
        try:
            atomic_write_json(self.cfg.output_path, snapshot)
        except Exception as exc:
            if self.cfg.verbose:
                self._log(f"ERROR report checkpoint failed ({reason}): {exc}")
            return
        self._log(f"checkpoint saved ({reason}) -> {self.cfg.output_path}")

    def run(self) -> dict[str, Any]:
        report: dict[str, Any] = {
            "started_at": _now(),
            "ceremony": self.cfg.ceremony,
            "mode": self.cfg.mode,
            "profile": self.cfg.profile,
            "url": self.cfg.url,
            "authenticator_state": asdict(self.cfg.authenticator),
            "pre_ceremony_mutation": self.cfg.mutation.pre_ceremony_summary(),
            "post_ceremony_mutation": self.cfg.mutation.post_ceremony_summary(),
            "js_events": [],
            "js_hook_status": {},
            "capture_status": "unknown",
            "cdp_events": [],
            "submissions": [],
            "responses": [],
            "browser_console": [],
            "challenge_observations": [],
            "loop_detection": {"detected": False, "signature": None, "count": 0},
            "errors": [],
            "stop_reason": None,
            "result_classification": "unknown",
            "final_state": {},
        }
        self._flush_report(report, reason="start")

        authenticator_id: str | None = None
        browser = None
        context = None
        page = None
        cdp = None
        created_context = True
        run_exception: BaseException | None = None

        self._log(
            f"start ceremony={self.cfg.ceremony} mode={self.cfg.mode} "
            f"profile={self.cfg.profile} url={self.cfg.url}"
        )
        self._log_run_plan()

        try:
            with sync_playwright() as playwright:
                browser, context, page, created_context = self._open_browser_session(
                    playwright, report
                )
                try:
                    page.set_default_timeout(self.cfg.timeout_ms)
                    context.add_init_script(build_init_script(self.cfg.mutation, self.cfg.verbose))
                    page.add_init_script(build_init_script(self.cfg.mutation, self.cfg.verbose))

                    self._install_page_debug_hooks(page, report)
                    self._install_network_hooks(context, report)
                    self._install_response_hook(context, report)

                    cdp = context.new_cdp_session(page)
                    try:
                        authenticator_id = self._setup_virtual_authenticator(cdp, report)
                    except Exception as exc:
                        self._record_error(report, f"CDP setup failed: {exc}")

                    if authenticator_id:
                        self._attach_cdp_event_listeners(cdp, page, report)

                    try:
                        self._log("navigating to target page")
                        page.goto(self.cfg.url, wait_until="domcontentloaded")
                        self._log("navigation complete")
                    except Exception as exc:
                        self._record_error(report, f"Navigation failed: {exc}")
                    else:
                        if self.cfg.trigger_js:
                            try:
                                self._log("executing trigger JS")
                                page.evaluate(self.cfg.trigger_js)
                                self._log("trigger JS returned")
                            except Exception as exc:
                                self._record_error(report, f"Trigger JS failed: {exc}")

                        self._log(f"waiting {self.cfg.wait_seconds:.1f}s for ceremony activity")
                        self._wait_for_activity(page, report)

                        self._refresh_capture_state(
                            page, report, reason="post-capture", log_summary=True
                        )
                        if self.cfg.keep_open:
                            self._keep_open_until_interrupt(page, report)
                            self._classify_result(report)
                            self._flush_report(report, reason="keep-open-final")
                finally:
                    interrupted_keep_open = bool(
                        report.get("keep_open", {}).get("interrupted_by_user")
                    )
                    if interrupted_keep_open and self.cfg.keep_open:
                        self._log(
                            "keep-open interrupted; skipping blocking Playwright cleanup calls"
                        )
                    else:
                        if authenticator_id and cdp is not None:
                            self._collect_virtual_credentials(cdp, authenticator_id, report)
                            try:
                                cdp.send(
                                    "WebAuthn.removeVirtualAuthenticator",
                                    {"authenticatorId": authenticator_id},
                                )
                                self._log(f"removed virtual authenticator {authenticator_id}")
                            except Exception:
                                pass

                        if self.cfg.cdp_url and not created_context:
                            if page is not None:
                                try:
                                    page.close()
                                except Exception:
                                    pass
                        else:
                            if context is not None:
                                try:
                                    context.close()
                                except Exception:
                                    pass
                        if browser is not None:
                            try:
                                browser.close()
                                self._log("browser session closed")
                            except Exception:
                                pass
        except BaseException as exc:
            run_exception = exc
            self._record_error(report, f"Run aborted: {type(exc).__name__}: {exc}")
        finally:
            report["finished_at"] = _now()
            try:
                self.state.save()
            except Exception as exc:
                self._record_error(report, f"State save failed: {exc}")
            self._flush_report(report, reason="final", final=True)
            self._log(
                f"finished submissions={len(report['submissions'])} "
                f"responses={len(report['responses'])} errors={len(report['errors'])}"
            )
        if run_exception is not None:
            raise run_exception
        return report

    def _log_run_plan(self) -> None:
        auth = self.cfg.authenticator
        self._log(
            "authenticator state: "
            f"protocol={auth.protocol} transport={auth.transport} "
            f"resident_key={auth.has_resident_key} uv_support={auth.has_user_verification} "
            f"uv_state={auth.is_user_verified} presence_sim={auth.automatic_presence_simulation}",
            kind="info",
        )
        self._log(
            "stop guards: "
            f"max_attempts={self.cfg.max_attempts} "
            f"first_submission={self.cfg.stop_on_first_submission} "
            f"first_response={self.cfg.stop_on_first_response} "
            f"response_error={self.cfg.stop_on_response_error} "
            f"first_cdp={self.cfg.stop_on_first_cdp_event} "
            f"keep_open={self.cfg.keep_open}",
            kind="info",
        )
        pre_items = {
            key: value
            for key, value in self.cfg.mutation.pre_ceremony_summary().items()
            if value is not None
        }
        post_items = {
            key: value
            for key, value in self.cfg.mutation.post_ceremony_summary().items()
            if value not in (None, False)
        }
        if self.cfg.mode == "mutation" and self.cfg.mutation.enabled:
            self._log("active attack profile details:", kind="mutation")
            if pre_items:
                self._log(
                    "  pre-ceremony mutations: "
                    + ", ".join(f"{k}={v}" for k, v in sorted(pre_items.items())),
                    kind="mutation",
                )
            if post_items:
                self._log(
                    "  post-ceremony mutations: "
                    + ", ".join(f"{k}={v}" for k, v in sorted(post_items.items())),
                    kind="mutation",
                )
            if not pre_items and not post_items:
                self._log("  mutation mode enabled but no concrete mutation fields are set", kind="warn")
        else:
            self._log("mutation stage: disabled (capture/baseline mode)", kind="dim")
        self._log(
            "user action: complete the login flow in browser (password + authenticator prompts) "
            f"within {self.cfg.wait_seconds:.1f}s",
            kind="info",
        )

    def _open_browser_session(self, playwright, report: dict[str, Any]):
        if self.cfg.cdp_url:
            report["attach_mode"] = "cdp"
            report["attached_cdp_url"] = self.cfg.cdp_url
            self._log(f"attaching over CDP: {self.cfg.cdp_url}")
            browser = playwright.chromium.connect_over_cdp(
                self.cfg.cdp_url,
                timeout=self.cfg.timeout_ms,
            )
            created_context = False
            try:
                context = browser.new_context(ignore_https_errors=True)
                created_context = True
                self._log("created isolated context on attached browser")
            except Exception as exc:
                self._record_error(
                    report,
                    "Unable to create isolated context on attached browser; "
                    f"reusing existing context: {exc}",
                )
                if browser.contexts:
                    context = browser.contexts[0]
                    self._log("reusing existing browser context")
                else:
                    raise RuntimeError("Attached browser has no available contexts")
            page = context.new_page()
            self._log("created page in attached browser")
            return browser, context, page, created_context

        report["attach_mode"] = "launch"
        launch_kwargs: dict[str, Any] = {"headless": self.cfg.headless}
        if self.cfg.proxy:
            launch_kwargs["proxy"] = {"server": self.cfg.proxy}
        if self.cfg.chromium_executable:
            launch_kwargs["executable_path"] = self.cfg.chromium_executable
            report["chromium_executable"] = self.cfg.chromium_executable
            self._log(f"launching Chromium executable: {self.cfg.chromium_executable}")
        else:
            self._log("launching bundled Chromium")
        browser = playwright.chromium.launch(**launch_kwargs)
        context = browser.new_context(ignore_https_errors=True)
        page = context.new_page()
        self._log("created new browser/context/page")
        return browser, context, page, True

    def _setup_virtual_authenticator(
        self, cdp: CDPSession, report: dict[str, Any]
    ) -> str:
        cdp.send("WebAuthn.enable")
        self._log("CDP WebAuthn domain enabled")
        result = cdp.send(
            "WebAuthn.addVirtualAuthenticator",
            {"options": self.cfg.authenticator.to_cdp_options()},
        )
        authenticator_id = result["authenticatorId"]
        report["authenticator_id"] = authenticator_id
        self._log(f"added virtual authenticator id={authenticator_id}")

        try:
            cdp.send(
                "WebAuthn.setAutomaticPresenceSimulation",
                {
                    "authenticatorId": authenticator_id,
                    "enabled": self.cfg.authenticator.automatic_presence_simulation,
                },
            )
        except Exception:
            pass

        try:
            cdp.send(
                "WebAuthn.setUserVerified",
                {
                    "authenticatorId": authenticator_id,
                    "isUserVerified": self.cfg.authenticator.is_user_verified,
                },
            )
        except Exception:
            pass

        if self.cfg.preload_credential_ids:
            self._preload_virtual_credentials(cdp, authenticator_id, report)

        return authenticator_id

    def _attach_cdp_event_listeners(
        self, cdp: CDPSession, page: Page, report: dict[str, Any]
    ) -> None:
        def _record(name: str):
            def _handler(payload: dict[str, Any]) -> None:
                report["cdp_events"].append({"event": name, "payload": payload, "ts": _now()})
                self._capture_js_snapshot(page, report, reason="js-events")
                self._flush_report(report, reason="cdp-event")
                if self.cfg.stop_on_first_cdp_event:
                    self._request_stop(report, f"captured first CDP event: {name}")
                if self.cfg.verbose:
                    self._log(f"cdp event {name}")

            return _handler

        cdp.on("WebAuthn.credentialAdded", _record("WebAuthn.credentialAdded"))
        cdp.on("WebAuthn.credentialAsserted", _record("WebAuthn.credentialAsserted"))
        cdp.on("WebAuthn.credentialDeleted", _record("WebAuthn.credentialDeleted"))
        cdp.on("WebAuthn.credentialUpdated", _record("WebAuthn.credentialUpdated"))

    def _collect_virtual_credentials(
        self, cdp: CDPSession, authenticator_id: str, report: dict[str, Any]
    ) -> None:
        try:
            result = cdp.send(
                "WebAuthn.getCredentials",
                {"authenticatorId": authenticator_id},
            )
            credentials = result.get("credentials", [])
            if isinstance(credentials, list):
                report["virtual_credentials"] = credentials
                self.state.record_virtual_credentials(
                    [c for c in credentials if isinstance(c, dict)]
                )
                self._flush_report(report, reason="virtual-credentials")
                self._log(f"snapshot virtual credentials count={len(credentials)}")
        except Exception as exc:
            self._record_error(report, f"Unable to query virtual credentials: {exc}")

    def _preload_virtual_credentials(
        self, cdp: CDPSession, authenticator_id: str, report: dict[str, Any]
    ) -> None:
        preloaded: list[str] = []
        for credential_id in self.cfg.preload_credential_ids:
            item, matched_id = self.state.virtual_credential_with_id(credential_id)
            if item is None:
                available = self.state.virtual_credential_ids()
                captured_sources: list[str] = []
                if self.state.credential(credential_id) is not None:
                    captured_sources.append("credentials")
                last_registration = self.state.data.get("last_registration")
                if isinstance(last_registration, dict):
                    if credential_id in {
                        last_registration.get("id"),
                        last_registration.get("rawId"),
                    }:
                        captured_sources.append("last_registration")
                last_assertion = self.state.data.get("last_assertion")
                if isinstance(last_assertion, dict):
                    if credential_id in {
                        last_assertion.get("id"),
                        last_assertion.get("rawId"),
                    }:
                        captured_sources.append("last_assertion")
                hint = (
                    f" available_ids={len(available)} state_path={self.cfg.state_path}"
                )
                if available:
                    sample = ", ".join(available[:3])
                    hint = f"{hint} sample=[{sample}]"
                if captured_sources:
                    sources = ",".join(captured_sources)
                    hint = (
                        f"{hint} captured_only=[{sources}] "
                        "note=credential metadata was captured but no preloadable "
                        "virtual credential/privateKey was stored"
                    )
                self._record_error(
                    report,
                    f"Preload credential not found in state: {credential_id}.{hint}",
                )
                continue
            if matched_id and matched_id != credential_id:
                self._log(
                    f"preload credential id normalized: requested={credential_id} matched={matched_id}"
                )

            credential = {k: v for k, v in item.items() if k in {
                "credentialId",
                "isResidentCredential",
                "rpId",
                "privateKey",
                "userHandle",
                "signCount",
                "largeBlob",
            }}
            if not credential.get("rpId"):
                host = urlparse(self.cfg.url).hostname
                if host:
                    credential["rpId"] = host
            if not credential.get("credentialId") or not credential.get("privateKey"):
                self._record_error(
                    report,
                    f"Preload credential '{credential_id}' missing credentialId/privateKey",
                )
                continue
            try:
                cdp.send(
                    "WebAuthn.addCredential",
                    {
                        "authenticatorId": authenticator_id,
                        "credential": credential,
                    },
                )
                preloaded.append(credential_id)
                self._log(f"preloaded credential {credential_id}")
            except Exception as exc:
                self._record_error(
                    report,
                    f"Failed to preload credential '{credential_id}': {exc}",
                )
        if preloaded:
            report["preloaded_credentials"] = preloaded
            self._log(f"preloaded credentials count={len(preloaded)}")

    def _install_page_debug_hooks(self, page: Page, report: dict[str, Any]) -> None:
        def on_console(message) -> None:
            text = message.text
            is_js_hook_log = "[webauthn-assess-js]" in text
            if is_js_hook_log:
                self._capture_js_snapshot(page, report, reason="js-events")
            if "[webauthn-assess-js]" not in text and not self.cfg.verbose:
                return
            entry = {
                "timestamp": _now(),
                "type": message.type,
                "text": text,
                "location": message.location,
            }
            report["browser_console"].append(entry)
            if self.cfg.verbose:
                self._log(f"console[{message.type}] {text}")
            self._flush_report(report, reason="console")

        def on_page_error(exc) -> None:
            text = str(exc)
            entry = {"timestamp": _now(), "type": "pageerror", "text": text}
            report["browser_console"].append(entry)
            self._record_error(report, f"Page error: {text}")

        page.on("console", on_console)
        page.on("pageerror", on_page_error)

    def _collect_js_events(self, page: Page) -> list[dict[str, Any]]:
        collected: list[dict[str, Any]] = []
        for frame in page.frames:
            try:
                events = frame.evaluate(
                    "() => (window.__webauthnAssess ? window.__webauthnAssess.getEvents() : [])"
                )
            except Exception:
                continue
            if not isinstance(events, list):
                continue
            for event in events:
                if not isinstance(event, dict):
                    continue
                out = dict(event)
                if "frame" not in out:
                    out["frame"] = {"href": frame.url}
                collected.append(out)
        return collected

    def _collect_js_status(self, page: Page) -> dict[str, Any]:
        statuses: list[dict[str, Any]] = []
        for frame in page.frames:
            try:
                status = frame.evaluate(
                    "() => (window.__webauthnAssess ? window.__webauthnAssess.getStatus() : {})"
                )
            except Exception:
                continue
            if not isinstance(status, dict) or not status:
                continue
            out = dict(status)
            out["frame_url"] = frame.url
            statuses.append(out)

        if not statuses:
            return {}

        top_status = next((s for s in statuses if s.get("isTop") is True), statuses[0])
        merged = dict(top_status)
        merged["frames"] = statuses
        return merged

    def _js_event_key(self, event: dict[str, Any]) -> str:
        seq = event.get("seq")
        ts = event.get("ts")
        stage = event.get("stage")
        method = event.get("method")
        if isinstance(seq, (int, float)) and isinstance(ts, (int, float)):
            return f"{int(seq)}:{int(ts)}:{stage}:{method}"
        try:
            return json.dumps(event, sort_keys=True, separators=(",", ":"))
        except Exception:
            return repr(event)

    def _capture_js_snapshot(self, page: Page, report: dict[str, Any], *, reason: str) -> None:
        events = self._collect_js_events(page)
        new_events: list[dict[str, Any]] = []
        for event in events:
            key = self._js_event_key(event)
            if key in self._seen_js_event_keys:
                continue
            self._seen_js_event_keys.add(key)
            new_events.append(event)

        if new_events:
            report["js_events"].extend(new_events)
            for event in new_events:
                self.state.update_from_js_event(event)
                if self.cfg.verbose:
                    self._log_js_event(event)
            self._flush_report(report, reason=reason)

        status = self._collect_js_status(page)
        if status:
            report["js_hook_status"] = status

    def _attach_browser_event_correlation(self, report: dict[str, Any]) -> None:
        js_results = [
            event for event in report.get("js_events", [])
            if event.get("stage") == "result" and isinstance(event.get("credential"), dict)
        ]
        if not js_results:
            return
        for submission in report.get("submissions", []):
            ts = _to_epoch_seconds(submission.get("timestamp"))
            if ts is None:
                continue
            match = None
            best_delta = None
            for event in js_results:
                event_ts = event.get("ts")
                if not isinstance(event_ts, (int, float)):
                    continue
                delta = abs(ts - (float(event_ts) / 1000.0))
                if best_delta is None or delta < best_delta:
                    best_delta = delta
                    match = event
            if match is not None:
                submission["browser_credential"] = match.get("credential")
                submission["browser_method"] = match.get("method")

    def _assess_js_capture(self, report: dict[str, Any]) -> None:
        js_events = report.get("js_events", [])
        cdp_events = report.get("cdp_events", [])
        call_events = [e for e in js_events if e.get("stage") == "call"]
        result_events = [e for e in js_events if e.get("stage") == "result"]
        error_events = [e for e in js_events if e.get("stage") == "error"]
        report["js_capture_summary"] = {
            "calls": len(call_events),
            "results": len(result_events),
            "errors": len(error_events),
        }

        had_ceremony = any(
            e.get("event") in {"WebAuthn.credentialAdded", "WebAuthn.credentialAsserted"}
            for e in cdp_events
        )
        if had_ceremony and not result_events:
            report["capture_status"] = "failed"
            self._record_error(
                report,
                "JS hook capture failed: CDP observed WebAuthn ceremony but no JS result events were captured",
            )
            return
        if result_events or call_events:
            report["capture_status"] = "succeeded"
            return
        if had_ceremony:
            report["capture_status"] = "partial"
            return
        report["capture_status"] = "none"

    def _capture_final_state(self, page: Page, report: dict[str, Any]) -> None:
        try:
            final_state = page.evaluate(
                """() => {
                    const bodyText = (document.body && document.body.innerText) ? document.body.innerText : "";
                    let component = null;
                    const selectors = [
                      "[component]",
                      "[data-component]",
                      "ak-stage-authenticator-validate-webauthn",
                      "ak-stage-authenticator-validate",
                      "ak-stage-authenticator-webauthn-register"
                    ];
                    for (const sel of selectors) {
                      const node = document.querySelector(sel);
                      if (!node) continue;
                      component = node.getAttribute("component") || node.getAttribute("data-component") || node.tagName.toLowerCase();
                      break;
                    }
                    const errorNode = document.querySelector("[role='alert'], .error, .pf-m-danger, .pf-c-alert");
                    return {
                      page_url: location.href,
                      page_title: document.title || null,
                      component,
                      error_text: errorNode ? (errorNode.textContent || "").trim() : null,
                      body_preview: bodyText.slice(0, 1200),
                    };
                }"""
            )
            if isinstance(final_state, dict):
                report["final_state"] = final_state
        except Exception as exc:
            self._record_error(report, f"Final state capture failed: {exc}")

    def _classify_result(self, report: dict[str, Any]) -> None:
        submissions = report.get("submissions", [])
        responses = report.get("responses", [])
        loop_info = report.get("loop_detection", {})
        final_state = report.get("final_state", {})

        if not submissions:
            report["result_classification"] = "unknown due to capture failure"
            return
        if not responses:
            if report.get("stop_reason"):
                report["result_classification"] = "unknown (stopped before response)"
            else:
                report["result_classification"] = "unknown (no correlated response)"
            return

        last = responses[-1]
        app_status = last.get("application_status")
        if app_status == "redirected":
            report["result_classification"] = "redirected"
            return
        if app_status == "accepted":
            page_url = final_state.get("page_url")
            if isinstance(page_url, str) and page_url != self.cfg.url:
                report["result_classification"] = "redirected"
            else:
                report["result_classification"] = "accepted"
            return
        if app_status == "rejected":
            if loop_info.get("detected"):
                report["result_classification"] = "rejected with retry"
            else:
                report["result_classification"] = "rejected"
            return
        report["result_classification"] = "unknown"

    def _wait_for_activity(self, page: Page, report: dict[str, Any]) -> None:
        deadline = time.monotonic() + max(0.0, self.cfg.wait_seconds)
        while time.monotonic() < deadline:
            self._capture_js_snapshot(page, report, reason="js-events")
            if report.get("stop_reason"):
                break
            remaining_ms = int((deadline - time.monotonic()) * 1000)
            if remaining_ms <= 0:
                break
            page.wait_for_timeout(min(250, remaining_ms))
        self._capture_js_snapshot(page, report, reason="js-events")

    def _refresh_capture_state(
        self,
        page: Page,
        report: dict[str, Any],
        *,
        reason: str,
        log_summary: bool = False,
        capture_final_state: bool = True,
    ) -> None:
        self._capture_js_snapshot(page, report, reason="js-events")
        self._attach_browser_event_correlation(report)
        self._assess_js_capture(report)
        if capture_final_state:
            self._capture_final_state(page, report)
        self._classify_result(report)
        self._flush_report(report, reason=reason)
        if log_summary:
            self._log(f"captured {len(report['js_events'])} JS events")

    def _keep_open_until_interrupt(self, page: Page, report: dict[str, Any]) -> None:
        report["keep_open"] = {
            "enabled": True,
            "active": True,
            "started_at": _now(),
            "interrupted_by_user": False,
        }
        self._log("keep-open enabled; press Ctrl+C to end the session")
        self._flush_report(report, reason="keep-open-start")
        try:
            while True:
                page.wait_for_timeout(250)
                self._capture_js_snapshot(page, report, reason="js-events")
        except KeyboardInterrupt:
            report["keep_open"]["interrupted_by_user"] = True
            self._log("keep-open session interrupted by user")
        except BaseException as exc:
            self._log(f"keep-open session ended: {exc}")
        finally:
            info = report.setdefault("keep_open", {})
            info["active"] = False
            info["ended_at"] = _now()
            self._flush_report(report, reason="keep-open-end")

    def _request_key(self, request) -> str:
        impl = getattr(request, "_impl_obj", None)
        guid = getattr(impl, "_guid", None)
        if isinstance(guid, str) and guid:
            return guid
        return f"request-{id(request)}"

    def _request_frame_context(self, request) -> dict[str, Any] | None:
        try:
            frame = request.frame
        except Exception:
            return None
        if frame is None:
            return None
        out = {"url": frame.url}
        try:
            out["name"] = frame.name
        except Exception:
            out["name"] = None
        return out

    def _request_page(self, request) -> Page | None:
        try:
            frame = request.frame
        except Exception:
            return None
        if frame is None:
            return None
        try:
            return frame.page
        except Exception:
            return None

    def _install_network_hooks(
        self, context: BrowserContext, report: dict[str, Any]
    ) -> None:
        def handle_route(route, request) -> None:
            try:
                method = request.method.upper()
                if method not in {"POST", "PUT", "PATCH"}:
                    route.continue_()
                    return

                body = request.post_data
                if not body:
                    route.continue_()
                    return

                parsed_json: dict[str, Any] | list[Any] | None = None
                parse_error: str | None = None
                try:
                    parsed_json = json.loads(body)
                except Exception as exc:
                    parse_error = str(exc)
                    route.continue_()
                    return

                if not isinstance(parsed_json, (dict, list)):
                    route.continue_()
                    return

                if not contains_webauthn_payload(parsed_json):
                    route.continue_()
                    return

                if report.get("stop_reason") and not self.cfg.keep_open:
                    # Guard against frontend auto-retries after we've decided to stop.
                    route.abort()
                    return

                req_page = self._request_page(request)
                if req_page is not None:
                    self._capture_js_snapshot(req_page, report, reason="js-events")

                original = deepcopy(parsed_json)
                final_payload = parsed_json
                details: list[str] = []
                errors: list[str] = []
                mutated = False
                if self.cfg.mode == "mutation" and self.cfg.mutation.enabled:
                    final_payload, log = mutate_json_payload(
                        final_payload,
                        mutation=self.cfg.mutation,
                        state=self.state,
                        ceremony=self.cfg.ceremony,
                    )
                    mutated = log.changed
                    details = log.details
                    errors = log.errors

                request_key = self._request_key(request)
                request_id = f"req-{len(report['submissions']) + 1:04d}"
                self._request_ids[request_key] = request_id
                mutation_diff = build_mutation_diff(original, final_payload)

                submission = {
                    "timestamp": _now(),
                    "request_id": request_id,
                    "url": request.url,
                    "method": method,
                    "frame": self._request_frame_context(request),
                    "request_headers": dict(request.headers),
                    "request_body": body,
                    "mutated": mutated,
                    "mutation_details": details,
                    "mutation_errors": errors,
                    "mutation_diff": mutation_diff,
                    "original_json": original,
                    "final_json": final_payload,
                }
                report["submissions"].append(submission)
                self.state.record_submission(
                    SubmissionRecord(
                        timestamp=submission["timestamp"],
                        request_id=request_id,
                        method=method,
                        url=request.url,
                        mutated=mutated,
                        request_headers=submission["request_headers"],
                        request_body=submission["request_body"],
                        frame=submission["frame"],
                        original_json=original,
                        final_json=final_payload,
                        mutation_details=details,
                        mutation_errors=errors,
                        mutation_diff=mutation_diff,
                        parse_error=parse_error,
                    )
                )
                self._flush_report(report, reason="submission")
                self._log(f"submission {request_id} {method} {request.url} mutated={mutated}")

                if mutated and details:
                    self._log(f"mutation details: {'; '.join(details)}")
                if errors:
                    self._log(f"mutation errors: {'; '.join(errors)}")
                if mutated and mutation_diff.get("changed"):
                    self._log_mutation_diff(mutation_diff)

                if self.cfg.stop_on_first_submission:
                    self._request_stop(report, "captured first WebAuthn submission")
                max_attempts = self.cfg.max_attempts
                if isinstance(max_attempts, int) and max_attempts > 0:
                    if len(report["submissions"]) >= max_attempts:
                        report["max_attempts_reached"] = True
                        if len(report.get("responses", [])) >= max_attempts:
                            self._request_stop(report, f"max attempts reached ({max_attempts})")
                        elif self.cfg.verbose:
                            self._log(
                                "max attempts reached at submission boundary; waiting for correlated response"
                            )

                if mutated:
                    final_body = json.dumps(final_payload, separators=(",", ":"))
                    headers = dict(request.headers)
                    for key in list(headers):
                        if key.lower() == "content-length":
                            del headers[key]
                    route.continue_(post_data=final_body, headers=headers)
                    return

                route.continue_()
            except Exception as exc:
                self._record_error(report, f"Route interception error: {exc}")
                route.continue_()

        context.route("**/*", handle_route)

    def _install_response_hook(
        self, context: BrowserContext, report: dict[str, Any]
    ) -> None:
        def handle_response(response) -> None:
            try:
                request = response.request
                request_key = self._request_key(request)
                request_id = self._request_ids.get(request_key)
                if request_id is None:
                    return

                try:
                    body = response.text()
                except BaseException:
                    body = None

                outcome = classify_application_response(response.status, body)
                body_preview = body[:4000] if isinstance(body, str) else None

                entry = {
                    "timestamp": _now(),
                    "request_id": request_id,
                    "url": response.url,
                    "status": response.status,
                    "ok": response.ok,
                    "method": request.method.upper(),
                    "response_headers": dict(response.headers),
                    "body_preview": body_preview,
                    "transport_success": outcome.transport_success,
                    "application_status": outcome.application_status,
                    "application_error_strings": outcome.error_strings,
                    "application_component": outcome.component,
                }
                report["responses"].append(entry)
                self.state.record_response(entry)

                if isinstance(outcome.parsed_json, (dict, list)):
                    challenges = extract_challenges(outcome.parsed_json)
                    for challenge in challenges:
                        observation = {
                            "timestamp": _now(),
                            "request_id": request_id,
                            "url": response.url,
                            "challenge": challenge,
                            "reissued": False,
                        }
                        previous = self._challenge_last_seen.get(response.url)
                        if previous is not None and previous != challenge:
                            observation["reissued"] = True
                        self._challenge_last_seen[response.url] = challenge
                        report["challenge_observations"].append(observation)

                self._update_loop_detection(report, entry)
                self._flush_report(report, reason="response")
                self._log(
                    "response "
                    f"{request_id} {entry['method']} {response.url} "
                    f"status={response.status} app={outcome.application_status}"
                )

                if self.cfg.stop_on_first_response:
                    self._request_stop(report, "captured first correlated response")
                if self.cfg.stop_on_response_error and outcome.application_status == "rejected":
                    self._request_stop(report, "response classified as application rejection")
                max_attempts = self.cfg.max_attempts
                if (
                    isinstance(max_attempts, int)
                    and max_attempts > 0
                    and len(report.get("submissions", [])) >= max_attempts
                    and len(report.get("responses", [])) >= max_attempts
                ):
                    self._request_stop(report, f"max attempts reached ({max_attempts})")
            except BaseException:
                return

        context.on("response", handle_response)

    def _update_loop_detection(self, report: dict[str, Any], response_entry: dict[str, Any]) -> None:
        component = response_entry.get("application_component")
        errors = response_entry.get("application_error_strings") or []
        error_key = "|".join(errors) if isinstance(errors, list) else ""
        fingerprint = self._loop_body_fingerprint(response_entry.get("body_preview"))
        signature = (
            response_entry.get("url"),
            component,
            error_key,
            self.cfg.profile,
            fingerprint,
        )
        now_mono = time.monotonic()
        self._recent_cycles.append({"ts": now_mono, "signature": signature})
        window = max(0.1, self.cfg.loop_detection_window_seconds)
        self._recent_cycles = [
            item for item in self._recent_cycles if now_mono - item["ts"] <= window
        ]
        count = sum(1 for item in self._recent_cycles if item["signature"] == signature)
        if count >= max(2, self.cfg.loop_detection_threshold):
            report["loop_detection"] = {
                "detected": True,
                "signature": {
                    "url": signature[0],
                    "component": signature[1],
                    "error": signature[2],
                    "profile": signature[3],
                },
                "count": count,
            }
            self._request_stop(report, "frontend auto-retry loop detected")

    def _loop_body_fingerprint(self, body_preview: Any) -> str:
        if not isinstance(body_preview, str):
            return stable_body_fingerprint(body_preview)
        try:
            parsed = json.loads(body_preview)
        except Exception:
            return stable_body_fingerprint(body_preview)
        normalized = self._normalize_loop_value(parsed)
        return stable_body_fingerprint(
            json.dumps(normalized, sort_keys=True, separators=(",", ":"))
        )

    def _normalize_loop_value(self, value: Any) -> Any:
        if isinstance(value, dict):
            out: dict[str, Any] = {}
            for key, item in value.items():
                lowered = key.lower()
                if lowered in {"challenge", "timestamp", "last_used", "issued_at"}:
                    out[key] = "<dynamic>"
                    continue
                out[key] = self._normalize_loop_value(item)
            return out
        if isinstance(value, list):
            return [self._normalize_loop_value(item) for item in value]
        return value

    def _log_mutation_diff(self, diff: dict[str, Any]) -> None:
        operations = diff.get("operations")
        if not isinstance(operations, list) or not operations:
            return
        self._log(f"mutation diff operations={len(operations)}", kind="mutation")
        for op in operations[:8]:
            if not isinstance(op, dict):
                continue
            path = op.get("path", "<unknown>")
            action = op.get("op", "replace")
            before = self._format_diff_value(op.get("before"))
            after = self._format_diff_value(op.get("after"))
            self._log(f"  {action} {path}", kind="mutation")
            self._log(f"    before: {before}", kind="dim")
            self._log(f"    after : {after}", kind="dim")
        if len(operations) > 8:
            self._log(f"  ... {len(operations) - 8} more changes omitted", kind="dim")

    def _format_diff_value(self, value: Any) -> str:
        if value is None:
            return "null"
        if isinstance(value, (bool, int, float)):
            return str(value)
        if isinstance(value, str):
            if len(value) > 220:
                return value[:140] + "..." + value[-40:]
            return value
        if not isinstance(value, dict):
            return str(value)

        value_type = value.get("type")
        if value_type == "string":
            decoded_client = value.get("decoded_client_data")
            if isinstance(decoded_client, dict):
                details = []
                for key in ("type", "origin", "challenge"):
                    if key in decoded_client:
                        details.append(f"{key}={decoded_client[key]}")
                if details:
                    return "clientData(" + ", ".join(details) + ")"
            decoded_auth = value.get("decoded_authenticator_data")
            if isinstance(decoded_auth, dict):
                return (
                    "authData("
                    f"UP={decoded_auth.get('up')}, "
                    f"UV={decoded_auth.get('uv')}, "
                    f"signCount={decoded_auth.get('sign_count')})"
                )
            if "value" in value:
                text = str(value["value"])
                if len(text) > 220:
                    return text[:140] + "..." + text[-40:]
                return text
            if "preview" in value:
                return str(value["preview"])
            return f"string(len={value.get('length')}, sha256={value.get('sha256')})"
        if value_type == "object":
            return f"object(keys={value.get('keys')})"
        if value_type == "array":
            return f"array(len={value.get('length')})"
        return str(value)

    def _log_js_event(self, event: dict[str, Any]) -> None:
        stage = event.get("stage")
        ceremony = event.get("ceremony")
        method = event.get("method")
        source = event.get("source")
        prefix = f"js event {stage}/{ceremony} method={method} source={source}"
        if stage == "call":
            options = event.get("options")
            if isinstance(options, dict):
                public_key = options.get("publicKey")
                if isinstance(public_key, dict):
                    rp_id = public_key.get("rpId")
                    uv = public_key.get("userVerification")
                    challenge = public_key.get("challenge")
                    challenge_len = len(challenge) if isinstance(challenge, str) else None
                    prefix += (
                        f" rpId={rp_id} userVerification={uv} challenge_len={challenge_len}"
                    )
            self._log(prefix, kind="info")
            return

        if stage == "result":
            credential = event.get("credential")
            if isinstance(credential, dict):
                cred_id = credential.get("id")
                auth_data = (
                    credential.get("response", {}).get("authenticatorData")
                    if isinstance(credential.get("response"), dict)
                    else None
                )
                prefix += f" credential_id={cred_id}"
                summary = self._decode_auth_data_summary(auth_data)
                if summary:
                    prefix += f" {summary}"
            self._log(prefix, kind="success")
            return

        if stage == "error":
            error = event.get("error")
            if isinstance(error, dict):
                prefix += f" error={error.get('name')}: {error.get('message')}"
            self._log(prefix, kind="error")
            return

        self._log(prefix, kind="dim")

    def _decode_auth_data_summary(self, auth_data_b64url: Any) -> str | None:
        if not isinstance(auth_data_b64url, str):
            return None
        try:
            raw = b64url_decode(auth_data_b64url)
        except Exception:
            return None
        if len(raw) < 37:
            return None
        flags = raw[32]
        sign_count = int.from_bytes(raw[33:37], "big")
        up = bool(flags & 0x01)
        uv = bool(flags & 0x04)
        return f"flags=0x{flags:02x} UP={up} UV={uv} signCount={sign_count}"
