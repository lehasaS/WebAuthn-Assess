from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal


CeremonyType = Literal["register", "auth"]
RunMode = Literal["normal", "mutation"]


@dataclass(slots=True)
class AuthenticatorConfig:
    protocol: Literal["ctap2", "u2f"] = "ctap2"
    transport: Literal["usb", "nfc", "ble", "internal"] = "usb"
    has_resident_key: bool = True
    has_user_verification: bool = True
    is_user_verified: bool = True
    automatic_presence_simulation: bool = True

    def to_cdp_options(self) -> dict[str, Any]:
        return {
            "protocol": self.protocol,
            "transport": self.transport,
            "hasResidentKey": self.has_resident_key,
            "hasUserVerification": self.has_user_verification,
            "isUserVerified": self.is_user_verified,
            "automaticPresenceSimulation": self.automatic_presence_simulation,
        }


@dataclass(slots=True)
class MutationConfig:
    enabled: bool = False
    tamper_origin: str | None = None
    tamper_challenge: str | None = None
    tamper_type: str | None = None
    force_uv_flag: bool | None = None
    force_up_flag: bool | None = None
    sign_count_mode: Literal["stall", "rollback"] | None = None
    attestation_fmt: str | None = None
    clear_attestation_x5c: bool = False
    inject_untrusted_x5c: bool = False
    duplicate_credential_id: bool = False
    rp_id_override: str | None = None
    algorithm_override: int | None = None

    def as_script_options(self) -> dict[str, Any]:
        return {
            "enabled": self.enabled,
            "rpIdOverride": self.rp_id_override,
            "algorithmOverride": self.algorithm_override,
        }


@dataclass(slots=True)
class RunConfig:
    ceremony: CeremonyType
    url: str
    mode: RunMode = "normal"
    profile: str = "baseline"
    chromium_executable: str | None = None
    cdp_url: str | None = None
    verbose: bool = False
    trigger_js: str | None = None
    wait_seconds: float = 15.0
    stop_after_first_webauthn: bool = False
    headless: bool = False
    timeout_ms: int = 30_000
    proxy: str | None = None
    output_path: Path | None = None
    state_path: Path = field(default_factory=lambda: Path(".webauthn_assess/state.json"))
    preload_credential_ids: list[str] = field(default_factory=list)
    authenticator: AuthenticatorConfig = field(default_factory=AuthenticatorConfig)
    mutation: MutationConfig = field(default_factory=MutationConfig)
