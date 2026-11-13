"""All checks RAVEN can run, in the order they run."""

from __future__ import annotations

from typing import List, Optional, Sequence

from raven_api.checks.access import AuthEnforcement, RateLimitSignals, SlowResponses
from raven_api.checks.base import Check
from raven_api.checks.content import SensitiveData, VerboseErrors
from raven_api.checks.cors import CorsPolicy
from raven_api.checks.headers import CookieFlags, SecurityHeaders, TechnologyDisclosure
from raven_api.checks.methods import HttpMethods
from raven_api.checks.transport import TransportSecurity
from raven_api.checks.validation import InputValidation, ResponseContract

CHECK_CLASSES = [
    TransportSecurity,
    SecurityHeaders,
    TechnologyDisclosure,
    CookieFlags,
    CorsPolicy,
    HttpMethods,
    AuthEnforcement,
    InputValidation,
    ResponseContract,
    SensitiveData,
    SlowResponses,
    VerboseErrors,  # last: reads every response the other checks collected
    RateLimitSignals,
]

PROFILES = {
    # passive: reads the normal responses only, plus TLS
    "quick": {"RAV-T01", "RAV-H01", "RAV-H02", "RAV-H03", "RAV-V02", "RAV-D01", "RAV-P01", "RAV-E01", "RAV-R01"},
    "standard": None,  # everything
}


def select_checks(profile: str = "standard", only: Optional[Sequence[str]] = None, skip: Optional[Sequence[str]] = None) -> List[Check]:
    wanted = PROFILES.get(profile)
    only_set = {x.strip().upper() for x in only or [] if x.strip()}
    skip_set = {x.strip().upper() for x in skip or [] if x.strip()}
    known = {c.id for c in CHECK_CLASSES}
    unknown = (only_set | skip_set) - known
    if unknown:
        raise ValueError(f"Unknown check id(s): {', '.join(sorted(unknown))}. Run `raven checks` to see them all.")
    chosen = []
    for cls in CHECK_CLASSES:
        if only_set and cls.id not in only_set:
            continue
        if not only_set and wanted is not None and cls.id not in wanted:
            continue
        if cls.id in skip_set:
            continue
        chosen.append(cls())
    return chosen


__all__ = ["CHECK_CLASSES", "PROFILES", "select_checks", "Check"]
