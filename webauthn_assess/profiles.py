from __future__ import annotations

from copy import deepcopy

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


def profile_names() -> list[str]:
    return sorted(PROFILE_MAP.keys())


def get_profile(name: str) -> MutationConfig:
    if name not in PROFILE_MAP:
        available = ", ".join(profile_names())
        raise ValueError(f"Unknown profile '{name}'. Available: {available}")
    return deepcopy(PROFILE_MAP[name])
