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
from .instrumentation import build_init_script
from .mutation import contains_webauthn_payload, mutate_json_payload
from .persistence import atomic_write_json
from .state import StateStore, SubmissionRecord


def _now() -> str:
    return datetime.now(UTC).isoformat()


class WebAuthnRunner:
    def __init__(self, run_config: RunConfig, state: StateStore) -> None:
        self.cfg = run_config
        self.state = state

    def _log(self, message: str) -> None:
        if not self.cfg.verbose:
            return
        print(f"[webauthn-assess] {message}", flush=True)

    def _record_error(self, report: dict[str, Any], message: str) -> None:
        report["errors"].append(message)
        self._log(f"ERROR {message}")
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
            "authenticator": asdict(self.cfg.authenticator),
            "mutation": asdict(self.cfg.mutation),
            "js_events": [],
            "cdp_events": [],
            "submissions": [],
            "responses": [],
            "errors": [],
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

        try:
            with sync_playwright() as playwright:
                browser, context, page, created_context = self._open_browser_session(
                    playwright, report
                )
                try:
                    page.set_default_timeout(self.cfg.timeout_ms)
                    page.add_init_script(build_init_script(self.cfg.mutation))

                    self._install_network_hooks(context, report)
                    self._install_response_hook(context, report)

                    cdp = context.new_cdp_session(page)
                    try:
                        authenticator_id = self._setup_virtual_authenticator(cdp, report)
                    except Exception as exc:
                        self._record_error(report, f"CDP setup failed: {exc}")

                    if authenticator_id:
                        self._attach_cdp_event_listeners(cdp, report)

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

                        report["js_events"] = self._collect_js_events(page)
                        for event in report["js_events"]:
                            self.state.update_from_js_event(event)
                        self._flush_report(report, reason="js-events")
                        self._log(f"captured {len(report['js_events'])} JS ceremony events")
                        if self.cfg.verbose:
                            for event in report["js_events"]:
                                stage = event.get("stage")
                                ceremony = event.get("ceremony")
                                seq = event.get("seq")
                                self._log(f"js event seq={seq} ceremony={ceremony} stage={stage}")
                finally:
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
            # This command can be unsupported in older Chrome versions.
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
            # Optional command.
            pass

        if self.cfg.preload_credential_ids:
            self._preload_virtual_credentials(cdp, authenticator_id, report)

        return authenticator_id

    def _attach_cdp_event_listeners(self, cdp: CDPSession, report: dict[str, Any]) -> None:
        def _record(name: str):
            def _handler(payload: dict[str, Any]) -> None:
                report["cdp_events"].append({"event": name, "payload": payload, "ts": _now()})
                self._flush_report(report, reason="cdp-event")
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
            item = self.state.virtual_credential(credential_id)
            if item is None:
                self._record_error(report, f"Preload credential not found in state: {credential_id}")
                continue

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

    def _collect_js_events(self, page: Page) -> list[dict[str, Any]]:
        try:
            events = page.evaluate(
                "() => (window.__webauthnAssess ? window.__webauthnAssess.getEvents() : [])"
            )
            if isinstance(events, list):
                return [e for e in events if isinstance(e, dict)]
        except Exception:
            return []
        return []

    def _wait_for_activity(self, page: Page, report: dict[str, Any]) -> None:
        deadline = time.monotonic() + max(0.0, self.cfg.wait_seconds)
        while time.monotonic() < deadline:
            if report.get("stop_reason"):
                break
            remaining_ms = int((deadline - time.monotonic()) * 1000)
            if remaining_ms <= 0:
                break
            page.wait_for_timeout(min(250, remaining_ms))

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
                try:
                    parsed_json = json.loads(body)
                except Exception:
                    route.continue_()
                    return

                if not isinstance(parsed_json, (dict, list)):
                    route.continue_()
                    return

                if not contains_webauthn_payload(parsed_json):
                    route.continue_()
                    return

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

                submission = {
                    "timestamp": _now(),
                    "url": request.url,
                    "method": method,
                    "mutated": mutated,
                    "mutation_details": details,
                    "mutation_errors": errors,
                    "original_json": original,
                    "final_json": final_payload,
                }
                report["submissions"].append(submission)
                self.state.record_submission(
                    SubmissionRecord(
                        timestamp=submission["timestamp"],
                        method=method,
                        url=request.url,
                        mutated=mutated,
                        original_json=original,
                        final_json=final_payload,
                    )
                )
                self._flush_report(report, reason="submission")
                self._log(
                    f"submission {method} {request.url} mutated={mutated}"
                )
                if self.cfg.stop_after_first_webauthn:
                    self._request_stop(
                        report,
                        "captured first WebAuthn submission in mutation mode",
                    )
                if mutated and details:
                    self._log(f"mutation details: {'; '.join(details)}")
                if errors:
                    self._log(f"mutation errors: {'; '.join(errors)}")

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
                return

        context.route("**/*", handle_route)

    def _install_response_hook(
        self, context: BrowserContext, report: dict[str, Any]
    ) -> None:
        def handle_response(response) -> None:
            try:
                method = response.request.method.upper()
                if method not in {"POST", "PUT", "PATCH"}:
                    return
                content_type = response.headers.get("content-type", "")
                if "json" not in content_type.lower():
                    return
                try:
                    body = response.text()
                except BaseException:
                    body = None

                entry = {
                    "timestamp": _now(),
                    "url": response.url,
                    "status": response.status,
                    "ok": response.ok,
                    "method": method,
                    "body_preview": (body[:2000] if isinstance(body, str) else None),
                }
                report["responses"].append(entry)
                self.state.record_response(entry)
                self._flush_report(report, reason="response")
                self._log(
                    f"response {method} {response.url} status={response.status} ok={response.ok}"
                )
            except BaseException:
                return

        context.on("response", handle_response)
