# WebAuthn Assess Architecture and Protocol Notes

## Purpose and design intent

`webauthn-assess` is designed as an assessment instrument, not a synthetic protocol simulator.

The key design decision is to keep the browser ceremony real by using Chromium's CDP virtual authenticator API. Mutations are then applied in controlled stages so findings map cleanly to server-side validation classes.

## Layered architecture

### Layer 1: Browser and authenticator control

Primary modules:
- `webauthn_assess/browser.py`
- `webauthn_assess/config.py`

Responsibilities:
- Launch Chromium or attach to existing Chromium via CDP.
- Enable CDP `WebAuthn` domain.
- Add/remove virtual authenticators.
- Configure authenticator capabilities:
  - protocol (`ctap2` / `u2f`)
  - transport (`usb`, `nfc`, `ble`, `internal`)
  - resident key support
  - UV support and runtime verified state
  - automatic presence simulation
- Preload stored credentials into virtual authenticators for auth testing continuity.

Security relevance:
- Keeps WebAuthn operations browser-mediated and origin-scoped.
- Avoids overfitting by not replacing the browser's signing path for baseline testing.

### Layer 2: JS instrumentation and ceremony capture

Primary module:
- `webauthn_assess/instrumentation.py`

Responsibilities:
- Inject wrappers for `navigator.credentials.create()` / `get()` before app scripts execute.
- Install wrappers on both:
  - `navigator.credentials`
  - `CredentialsContainer.prototype`
- Capture per-call telemetry:
  - method and ceremony type
  - input options (`publicKey`)
  - output credential object (serialized)
  - frame context
  - source marker (`browser` vs synthetic path)
- Emit optional browser console diagnostics (`[webauthn-assess-js]`).

Security relevance:
- Provides evidence of what the browser actually produced before any outbound tampering.
- Enables capture-failure detection when CDP confirms ceremony but JS result capture is absent.

### Layer 3: interception, mutation, and correlation

Primary modules:
- `webauthn_assess/browser.py`
- `webauthn_assess/mutation.py`
- `webauthn_assess/reporting.py`

Responsibilities:
- Intercept outbound JSON submissions carrying WebAuthn payloads.
- Assign stable `request_id` and persist request metadata:
  - URL, method, frame, headers, body, timestamp
- Apply stage-appropriate post-ceremony mutation (when enabled).
- Persist response metadata correlated by `request_id`:
  - status, headers, body preview, app-level outcome classification
- Compute structured mutation diffs between browser-produced JSON and submitted JSON.

Security relevance:
- Distinguishes transport success from application acceptance.
- Produces auditable evidence of exactly what changed and what was accepted/rejected.

### Layer 4: state and persistence

Primary modules:
- `webauthn_assess/state.py`
- `webauthn_assess/persistence.py`

Responsibilities:
- Persist local state:
  - credentials
  - virtual credential snapshots
  - last registration/assertion payloads
  - submissions/responses
  - profile history
- Incremental checkpointing with atomic writes.
- Graceful interruption support (`SIGINT` / `SIGTERM`) with partial artifact preservation.

Security relevance:
- Prevents data loss during long, failure-oriented test runs.
- Supports reproducible replay and clone-lineage analysis.

## Mutation stage model

Mutations are intentionally separated into three stages:

1. Authenticator/browser state
- Affects virtual authenticator capabilities and runtime state.
- Examples: UV support, resident key support, userVerified state.

2. Pre-ceremony request mutation
- Alters `publicKey` options before browser ceremony execution.
- Examples: RP ID override, algorithm list override, attestation request mode override.

3. Post-ceremony submission mutation
- Alters serialized payload after browser ceremony and before submission.
- Examples: `clientDataJSON.origin` tamper, `authenticatorData` flag tamper, attestation statement edits.

Why this matters:
- Stage 2 tests policy and negotiation behavior.
- Stage 3 tests server verification integrity (signature/input binding checks).
- Stage 1 tests assumptions around authenticator capability/assurance semantics.

## Request/response lifecycle

1. Browser ceremony initiated by page app code.
2. JS hook records call/options.
3. Browser interacts with CDP virtual authenticator and returns credential.
4. JS hook records result credential.
5. Outbound request intercepted.
6. Optional mutation applied and diff computed.
7. Submission persisted with `request_id`.
8. Response captured and correlated by `request_id`.
9. Application-level outcome classified (`accepted` / `rejected` / etc.).
10. Final state snapshot captured from DOM + URL.

## Outcome model

The tool classifies outcomes independently from HTTP status:

- `accepted`
- `rejected`
- `rejected with retry`
- `redirected`
- `unknown` variants when capture is incomplete

A response can be `HTTP 200` and still be `rejected` if application body indicates a validation error (`response_errors`, explicit `ok: false`, etc.).

## Loop prevention and retry handling

For failure-oriented profiles, defaults bias toward stopping after first meaningful submission/response pair.

Controls include:
- `--max-attempts`
- `--stop-on-first-submission`
- `--stop-on-first-response`
- `--stop-on-response-error`
- `--stop-on-first-cdp-event`

Loop detection fingerprints repeated rejection cycles and normalizes dynamic challenge-like fields to avoid missing retries caused by fresh challenge issuance.

## Protocol implementation notes

This tool does not replace the relying party verifier. It assesses verifier behavior by perturbing browser-generated artifacts.

Core fields and semantics exercised:
- `clientDataJSON`:
  - `type`, `challenge`, `origin`, `crossOrigin`
- `authenticatorData`:
  - RP ID hash binding
  - flags (UP/UV)
  - signCount monotonicity
- `attestationObject` (registration):
  - format (`fmt`)
  - attestation statement fields (`attStmt`, `x5c`)
- assertion signature tuple (auth):
  - signature over `authenticatorData || SHA256(clientDataJSON)`

Assessment focus is whether server verifies/binds these correctly under tampering and replay pressure.

## Boundaries and limitations

- Current interception logic targets JSON-bearing request bodies for POST/PUT/PATCH paths.
- Flows submitting via non-JSON forms may require additional parsers.
- Browser policy failures (e.g., invalid pre-ceremony RP scope) can fail before outbound submission by design.
- The tool provides evidence capture and mutation control; vulnerability determination still requires analyst interpretation against policy requirements.

## Extension guidance

Recommended extension points:
- Add profile-specific outcome assertions (policy expectations).
- Add deeper response parsers for framework-specific error envelopes.
- Add non-JSON transport handlers for multipart/form-urlencoded apps.
- Add optional HAR export and screenshot capture for reporting packs.

