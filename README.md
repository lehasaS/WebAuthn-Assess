# webauthn-assess

Compact Python WebAuthn assessment tool that combines:
- Chromium CDP virtual authenticators (browser-visible authenticator layer)
- Playwright (automation + CDP session)
- `python-fido2` (CBOR/WebAuthn structure parsing and mutation helpers)

## Features

- Standards-compliant baseline mode (`--mode normal`)
- Mutation mode (`--mode mutation`) with profile-driven tampering
- Virtual authenticator configuration:
  - protocol (`ctap2`/`u2f`)
  - transport (`usb`/`nfc`/`ble`/`internal`)
  - resident key, UV capability, current user-verified state, presence simulation
- Ceremony capture:
  - intercepted `navigator.credentials.create/get` options
  - browser-produced credential objects
  - serialized JSON request bodies to backend
  - backend JSON responses
- Mutation hooks:
  - pre-signing options mutation in page context (RP ID/algorithm)
  - post-signing request payload mutation (clientData/authenticatorData/attestationObject)
  - replay of previously captured JSON payloads
- Local state store for challenges, credentials, sign counter, submissions, responses

## Requirements

- Python 3.11+
- `playwright`
- `fido2`
- `cryptography`
- Chromium installed for Playwright

## Install

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .
playwright install chromium
```

## Documentation

- Architecture, design, and protocol notes: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)
- Pentest testing methodology and interpretation: [docs/TESTING_METHODOLOGY.md](docs/TESTING_METHODOLOGY.md)

## CLI

### Baseline

```bash
webauthn-assess register --url https://target/app --mode normal
webauthn-assess auth --url https://target/app --mode normal
```

### Browser selection / attach

```bash
# Launch a specific Chromium binary (example: Burp Browser)
webauthn-assess auth --url https://target/app --chromium-executable /home/kali/BurpSuitePro/burpbrowser/145.0.7632.45/chrome

# Attach to an already running Chromium with remote debugging enabled
webauthn-assess auth --url https://target/app --cdp-url http://127.0.0.1:9222

# Resolve CDP endpoint from PID (requires --remote-debugging-port on that process)
webauthn-assess auth --url https://target/app --attach-pid 12345

# Node Playwright tests use BURP_CHROMIUM_PATH (defaults to Burp path in playwright.config.js)
BURP_CHROMIUM_PATH=/custom/chrome npx playwright test
```

### Mutation examples

```bash
webauthn-assess register --url https://target/app --mode mutation --profile attestation-none
webauthn-assess register --url https://target/app --mode mutation --profile attestation-untrusted
webauthn-assess auth --url https://target/app --mode mutation --profile uv-downgrade
webauthn-assess auth --url https://target/app --mode mutation --tamper-origin https://evil.example
webauthn-assess auth --url https://target/app --mode mutation --profile challenge-replay
webauthn-assess auth --url https://target/app --mode mutation --profile counter-stall
webauthn-assess auth --url https://target/app --mode mutation --profile counter-rollback
webauthn-assess auth --url https://target/app --mode mutation --profile rp-id-mismatch
webauthn-assess register --url https://target/app --mode mutation --profile alg-unexpected
```

### Replay / clone helpers

```bash
webauthn-assess replay --capture last-assertion
webauthn-assess clone --credential <credential-id>
```

## Useful flags

- `--trigger-js "<script>"`: run JS after load to trigger app ceremony
- `--wait-seconds 20`: wait window for ceremony capture
- Mutation mode uses profile-specific stop guards by default (use `--allow-retries` to disable them)
- `--headless`: run without UI
- `--keep-open`: keep browser/context open after initial capture until `Ctrl+C`
- `--verbose`: stream live request/response and mutation logs in terminal
- `--proxy http://127.0.0.1:8080`: route traffic through local proxy/Burp
- `--output report.json`: explicit report file path
- `--preload-credential <credentialId>`: preload a stored CDP credential into the virtual authenticator
- `--chromium-executable /path/to/chrome`: launch with a specific Chromium binary
- `--cdp-url http://127.0.0.1:9222`: attach to existing Chromium via CDP
- `--attach-pid 12345`: derive CDP URL from process cmdline

Authenticator knobs:
- `--protocol ctap2|u2f`
- `--transport usb|nfc|ble|internal`
- `--resident-key on|off`
- `--uv-support on|off`
- `--uv-state on|off`
- `--presence-sim on|off`

Termination/loop guards:
- `--max-attempts`
- `--stop-on-first-submission` / `--no-stop-on-first-submission`
- `--stop-on-first-response` / `--no-stop-on-first-response`
- `--stop-on-response-error` / `--no-stop-on-response-error`
- `--stop-on-first-cdp-event` / `--no-stop-on-first-cdp-event`
- `--allow-retries` (disables profile defaults)

Pre-ceremony mutation knobs:
- `--rp-id-override`
- `--alg-override`
- `--attestation-request-mode`

Post-ceremony mutation knobs:
- `--tamper-origin`
- `--tamper-challenge` (`last-assertion,last-registration,stale,random,empty,null,missing,<explicit>`)
- `--tamper-type`
- `--force-uv on|off`
- `--force-up on|off`
- `--sign-count-mode stall|rollback`
- `--attestation-fmt`
- `--clear-x5c`
- `--inject-untrusted-x5c`
- `--duplicate-credential-id`

## Profiles

- `baseline`
- `attestation-none`
- `attestation-untrusted`
- `uv-downgrade`
- `origin-mismatch`
- `challenge-replay`
- `counter-stall`
- `counter-rollback`
- `rp-id-mismatch`
- `alg-unexpected`
- `credential-clone`

## Output and state

- State: `.webauthn_assess/state.json`
- Default reports: `.webauthn_assess/reports/<timestamp>-<command>-<profile>.json`
- CDP credential snapshots are kept in `state.json` under `virtual_credentials`
- State and report files are checkpointed incrementally (atomic writes) during runs.
- `Ctrl+C` (`SIGINT`) and `SIGTERM` trigger graceful shutdown with partial data preserved.
- `SIGKILL` cannot be trapped by any process; last checkpoint may be the most recent recoverable data.

Reports include:
- JS ceremony events
- JS hook install status / capture status
- CDP authenticator events
- correlated request/response ids with headers/body previews
- original vs final request JSON bodies
- mutation details/errors and structured diffs
- transport/application-level response classification
- final state capture (URL/component/error text preview)
- loop detection and challenge reissue observations

## Assessment checklist (recommended order)

1. Baseline register (`--mode normal --profile baseline`).
2. Baseline auth with `--preload-credential`.
3. Run failure-oriented integrity tests:
   - `origin-mismatch`
   - `tamper-type`
   - challenge tamper (`random`, `empty`, `null`, `missing`)
4. Run policy tests:
   - UV semantics (`--uv off`, `uv-downgrade`)
   - RP-ID/origin scoping (`rp-id-mismatch`)
   - attestation policy (`attestation-none`, `attestation-untrusted`)
   - algorithm policy (`alg-unexpected`)
5. Replay analysis with `replay --repeat --interval-ms` as needed.
6. Inspect collected state with `inspect-state`.

## Result interpretation

- `accepted`: assertion/attestation accepted and flow progressed.
- `rejected`: backend rejected the WebAuthn submission.
- `rejected with retry`: rejection plus frontend retry loop detected.
- `redirected`: accepted and navigated to a different post-auth URL.
- `unknown`: capture insufficient to assert an outcome.

A common pattern is HTTP `200` with JSON `response_errors`; this is classified as application-level rejection, not success.

## How it works (and why)

1. Browser-visible authenticator:
The tool uses Chromium CDP `WebAuthn` virtual authenticators, so `navigator.credentials.*` runs through a real browser WebAuthn ceremony path.

2. Capture + optional mutation:
Outgoing JSON bodies are intercepted before they reach the backend.
In mutation mode, credential fields (for example `clientDataJSON.origin`) are modified after signing unless the profile explicitly targets pre-signing options.

3. Verification signal:
If a mutated assertion is accepted, that usually indicates broken server-side verification.
If it is rejected, that indicates signature/input binding checks are working for that case.

4. State continuity:
Virtual credentials created in one run are stored in `state.json` and can be preloaded in later runs with `--preload-credential`.
Without preload, a new run starts with a fresh virtual authenticator and auth can fail due to missing credentials.

## Interpreting results correctly

- HTTP `200` is not always success.
Some IdPs return `200` with JSON `response_errors` and keep the same auth stage, which means rejection.

- Mutation retries can look like loops.
Many frontends retry WebAuthn after a failed assertion.
By default, mutation mode now stops after the first captured WebAuthn submission.
Use `--allow-retries` when you intentionally want to observe repeated retries.

- Strong evidence of a vulnerability:
The mutated request is accepted and the flow advances as authenticated (no validation error path).
