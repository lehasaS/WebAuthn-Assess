# WebAuthn Assessment Testing Methodology

## Audience

This guide is for pentesters and security researchers running controlled WebAuthn assessments with `webauthn-assess`.

## Scope and legal safety

Run only against targets you are authorized to test.

Recommended guardrails:
- Use dedicated test accounts and isolated tenants/environments.
- Coordinate rate limits and lockout behavior with defenders.
- Keep replay and retry tests bounded (`--max-attempts`, `--repeat`).

## Assessment goals

For each test case, establish:
- Did browser ceremony occur?
- What did browser produce?
- What was mutated/replayed?
- What did server return (app-level)?
- Did application accept/reject/retry/redirect?

## Prerequisites

- One working baseline credential enrollment path.
- A stable login flow URL and known RP/origin expectations.
- Optional proxy for traffic visibility (Burp/local proxy).
- Tool installed with Playwright Chromium available.

## Data handling and evidence quality

Always keep raw artifacts:
- report JSON (`--output`)
- state JSON (`--state-path`)
- proxy history (if used)
- timestamps and command lines used

For each finding candidate, record:
- profile + exact command
- mutation diff (`mutation_diff`)
- correlated request/response IDs
- final classification and stop reason

## Recommended run order

1. Baseline registration

```bash
webauthn-assess register --url "$URL_REGISTER" --mode normal --profile baseline --verbose --output outputs/register-baseline.json
```

2. Baseline authentication using stored credential

```bash
webauthn-assess auth --url "$URL_AUTH" --mode normal --profile baseline --preload-credential "$CRED_ID" --verbose --output outputs/auth-baseline.json
```

3. Integrity tamper tests (expected reject)

```bash
webauthn-assess auth --url "$URL_AUTH" --mode mutation --profile origin-mismatch --preload-credential "$CRED_ID" --output outputs/auth-origin-mismatch.json
webauthn-assess auth --url "$URL_AUTH" --mode mutation --tamper-type webauthn.create --preload-credential "$CRED_ID" --output outputs/auth-type-mismatch.json
```

4. Challenge handling tests

```bash
webauthn-assess auth --url "$URL_AUTH" --mode mutation --tamper-challenge random --preload-credential "$CRED_ID" --output outputs/auth-challenge-random.json
webauthn-assess auth --url "$URL_AUTH" --mode mutation --tamper-challenge empty --preload-credential "$CRED_ID" --output outputs/auth-challenge-empty.json
webauthn-assess auth --url "$URL_AUTH" --mode mutation --tamper-challenge null --preload-credential "$CRED_ID" --output outputs/auth-challenge-null.json
```

5. UV/UP semantics tests

```bash
webauthn-assess auth --url "$URL_AUTH" --mode mutation --profile uv-downgrade --preload-credential "$CRED_ID" --output outputs/auth-uv-downgrade.json
webauthn-assess auth --url "$URL_AUTH" --mode mutation --uv spoof --preload-credential "$CRED_ID" --output outputs/auth-uv-spoof.json
```

6. RP and algorithm policy tests

```bash
webauthn-assess auth --url "$URL_AUTH" --mode mutation --profile rp-id-mismatch --preload-credential "$CRED_ID" --output outputs/auth-rpid-mismatch.json
webauthn-assess register --url "$URL_REGISTER" --mode mutation --profile alg-unexpected --output outputs/register-alg-unexpected.json
```

7. Attestation policy tests

```bash
webauthn-assess register --url "$URL_REGISTER" --mode mutation --profile attestation-none --output outputs/register-att-none.json
webauthn-assess register --url "$URL_REGISTER" --mode mutation --profile attestation-untrusted --output outputs/register-att-untrusted.json
```

8. Replay and transport-assumption tests

```bash
webauthn-assess replay --capture last-assertion --url "$API_ENDPOINT" --repeat 2 --interval-ms 500 --output outputs/replay-last-assertion.json
```

9. State sanity check

```bash
webauthn-assess inspect-state --state-path .webauthn_assess/state.json
```

## What to expect in secure implementations

Typical secure behavior:
- Tampered `clientDataJSON.origin` rejected.
- Tampered challenge rejected.
- Type mismatch rejected.
- RP ID mismatch rejected pre-ceremony or by verifier.
- UV/UP policy mismatches rejected when policy requires stronger assurance.
- Replays rejected or challenge reissued with no session advancement.
- Sign counter anomalies at least logged, often rejected depending on policy.

## What often indicates vulnerability

Strong signals:
- Mutated assertion accepted and session advances.
- Tampered `origin` or `challenge` accepted.
- Signature-relevant bytes altered post-ceremony yet accepted.
- Replayed assertion accepted against a fresh challenge.
- Policy claims (UV/device provenance) not enforced in verifier behavior.

Policy-dependent signals (not always vulnerabilities):
- accepting `attestation: none`
- allowing certain algorithms by design

Validate these against documented business/assurance requirements before reporting.

## Interpreting outcome fields

Key report fields:
- `capture_status`: whether JS ceremony evidence was captured reliably.
- `submissions[]`: original and final payload, request metadata, mutation details.
- `responses[]`: transport + application classification and error strings.
- `result_classification`: final verdict (`accepted`, `rejected`, `rejected with retry`, `redirected`, `unknown`).
- `stop_reason`: why the run terminated.
- `loop_detection`: retry-loop detection metadata.
- `challenge_observations`: challenge reissue evidence.

## Retry-loop strategy

Default negative profiles are intentionally conservative and usually stop after first meaningful response.

When intentionally studying retries:
- enable retries with `--allow-retries`
- keep wait bounded
- rely on loop detection evidence

Example:

```bash
webauthn-assess auth --url "$URL_AUTH" --mode mutation --profile origin-mismatch --allow-retries --wait-seconds 20 --output outputs/auth-origin-loop-study.json
```

## Reporting template (quick)

For each case:
- Test objective
- Command and profile
- Mutation diff summary
- Request/response correlation IDs
- Server/app outcome
- Security impact
- Remediation guidance

## Suggested remediation language

- Verify assertion signature over exact `authenticatorData || SHA256(clientDataJSON)` bytes submitted.
- Enforce strict `origin`, `rpId`, `challenge`, and `type` validation.
- Enforce policy-driven UV/UP requirements at verifier time.
- Treat challenge as single-use and expire aggressively.
- Track signCount and investigate clone indicators.

