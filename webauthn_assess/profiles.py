from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass

from .config import MutationConfig


PROFILE_MAP: dict[str, MutationConfig] = {
    "baseline": MutationConfig(enabled=False),
    "attestation-none": MutationConfig(
        enabled=True,
        attestation_fmt="none",
        clear_attestation_x5c=True,
    ),
    "attestation-untrusted": MutationConfig(
        enabled=True,
        attestation_fmt="packed",
        inject_untrusted_x5c=True,
    ),
    "uv-downgrade": MutationConfig(
        enabled=True,
        force_uv_flag=False,
        force_up_flag=True,
    ),
    "origin-mismatch": MutationConfig(
        enabled=True,
        tamper_origin="https://evil.example",
    ),
    "challenge-replay": MutationConfig(
        enabled=True,
        tamper_challenge="stale",
    ),
    "counter-stall": MutationConfig(
        enabled=True,
        sign_count_mode="stall",
    ),
    "counter-rollback": MutationConfig(
        enabled=True,
        sign_count_mode="rollback",
    ),
    "rp-id-mismatch": MutationConfig(
        enabled=True,
        rp_id_override="invalid.example",
    ),
    "alg-unexpected": MutationConfig(
        enabled=True,
        algorithm_override=-257,  # RS256
    ),
    "credential-clone": MutationConfig(
        enabled=True,
        duplicate_credential_id=True,
    ),
}


@dataclass(slots=True)
class ProfileDefaults:
    expected_outcome: str = "unknown"
    max_attempts: int | None = None
    stop_on_first_submission: bool = False
    stop_on_first_response: bool = False
    stop_on_response_error: bool = False
    stop_on_first_cdp_event: bool = False


PROFILE_DEFAULTS: dict[str, ProfileDefaults] = {
    "baseline": ProfileDefaults(
        expected_outcome="baseline",
        max_attempts=1,
        stop_on_first_response=True,
    ),
    "origin-mismatch": ProfileDefaults(
        expected_outcome="expected-failure",
        max_attempts=1,
        stop_on_first_response=True,
        stop_on_response_error=True,
    ),
    "rp-id-mismatch": ProfileDefaults(
        expected_outcome="expected-failure",
        max_attempts=1,
        stop_on_first_submission=True,
        stop_on_first_response=True,
        stop_on_response_error=True,
        stop_on_first_cdp_event=True,
    ),
    "uv-downgrade": ProfileDefaults(
        expected_outcome="expected-failure",
        max_attempts=1,
        stop_on_first_response=True,
        stop_on_response_error=True,
    ),
    "attestation-none": ProfileDefaults(
        expected_outcome="policy-dependent",
        max_attempts=1,
        stop_on_first_response=True,
    ),
    "attestation-untrusted": ProfileDefaults(
        expected_outcome="expected-failure",
        max_attempts=1,
        stop_on_first_response=True,
        stop_on_response_error=True,
    ),
    "challenge-replay": ProfileDefaults(
        expected_outcome="expected-failure",
        max_attempts=2,
        stop_on_first_response=True,
        stop_on_response_error=True,
    ),
    "counter-stall": ProfileDefaults(
        expected_outcome="expected-failure",
        max_attempts=1,
        stop_on_first_response=True,
        stop_on_response_error=True,
    ),
    "counter-rollback": ProfileDefaults(
        expected_outcome="expected-failure",
        max_attempts=1,
        stop_on_first_response=True,
        stop_on_response_error=True,
    ),
    "alg-unexpected": ProfileDefaults(
        expected_outcome="policy-dependent",
        max_attempts=1,
        stop_on_first_response=True,
    ),
    "credential-clone": ProfileDefaults(
        expected_outcome="expected-failure",
        max_attempts=1,
        stop_on_first_response=True,
        stop_on_response_error=True,
    ),
}


def profile_names() -> list[str]:
    return sorted(PROFILE_MAP.keys())


def get_profile(name: str) -> MutationConfig:
    if name not in PROFILE_MAP:
        available = ", ".join(profile_names())
        raise ValueError(f"Unknown profile '{name}'. Available: {available}")
    return deepcopy(PROFILE_MAP[name])


def get_profile_defaults(name: str) -> ProfileDefaults:
    defaults = PROFILE_DEFAULTS.get(name)
    if defaults is None:
        return ProfileDefaults()
    return deepcopy(defaults)
