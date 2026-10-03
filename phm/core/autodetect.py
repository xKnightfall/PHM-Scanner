"""Target auto-detection for `phm analyze`.

Detection should be transparent. PHM scores multiple possible meanings,
chooses the highest-confidence plan, and stores alternatives for the report.
"""

from __future__ import annotations

import codecs
import ipaddress
import re
from dataclasses import dataclass, field
from pathlib import Path

from phm.core.models import Category
from phm.sources.common import is_domain, normalize_domain
from phm.sources.github.adapter import parse_repo_slug

_EMAIL_RE = re.compile(r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@([A-Za-z0-9-]+\.)+[A-Za-z]{2,63}$")
_HASH_RE = re.compile(r"^(?:[A-Fa-f0-9]{32}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{56}|[A-Fa-f0-9]{64}|[A-Fa-f0-9]{96}|[A-Fa-f0-9]{128})$")
_USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,39}$")
_BASE64ISH_RE = re.compile(r"^[A-Za-z0-9+/\s_-]+={0,2}$")
_HEXISH_RE = re.compile(r"^(?:0x)?[0-9A-Fa-f\s:.-]{4,}$")
_COMMON_ROT13_WORDS = {"hello", "flag", "secret", "password", "admin", "token", "attack", "defend"}
_COORD_RE = re.compile(r"^\s*(-?\d{1,3}(?:\.\d+)?)\s*[,; ]\s*(-?\d{1,3}(?:\.\d+)?)\s*$")


@dataclass(slots=True)
class AnalysisPlan:
    """A small plan for automatically running an analysis."""

    target: str
    target_type: str
    category: Category
    plugins: list[str] | None = None
    use_crypto_engine: bool = False
    confidence: float = 0.0
    reason: str = ""
    notes: list[str] = field(default_factory=list)
    alternatives: list[dict[str, object]] = field(default_factory=list)


def plan_analysis(target: str) -> AnalysisPlan:
    """Return the highest-confidence analysis plan and alternatives."""

    candidates = score_interpretations(target)
    best = candidates[0]
    plan = _plan_from_candidate(target.strip(), best)
    plan.alternatives = [
        {"target_type": item["target_type"], "confidence": item["confidence"], "reason": item["reason"]}
        for item in candidates[1:5]
    ]
    return plan


def score_interpretations(target: str) -> list[dict[str, object]]:
    """Score plausible target interpretations."""

    raw = target.strip()
    candidates: list[dict[str, object]] = []

    def add(target_type: str, category: Category, confidence: float, reason: str, plugins=None, use_crypto_engine: bool = False, notes=None) -> None:
        candidates.append(
            {
                "target_type": target_type,
                "category": category,
                "confidence": round(confidence, 2),
                "reason": reason,
                "plugins": plugins,
                "use_crypto_engine": use_crypto_engine,
                "notes": notes or [],
            }
        )

    path = Path(raw)
    coordinate_match = _COORD_RE.fullmatch(raw)
    if coordinate_match:
        latitude, longitude = map(float, coordinate_match.groups())
        if -90 <= latitude <= 90 and -180 <= longitude <= 180:
            add("coordinates", Category.GEOSPATIAL, 0.99, "latitude/longitude pair", ["geolocation_lookup"])
    if path.exists() and path.is_file():
        add("file", Category.FILE, 0.99, "local file path exists", ["file_analysis"])

    if parse_repo_slug(raw):
        add("github_repository", Category.TECHNICAL, 0.96, "GitHub repository URL or owner/repo slug", ["github_repo_analysis"])

    if raw.startswith(("http://", "https://")):
        host = normalize_domain(raw)
        plugins = ["technology_fingerprint"]
        if is_domain(host):
            plugins = ["dns_lookup", "rdap_lookup", "ssl_lookup", "technology_fingerprint", "asn_lookup"]
        add("url", Category.TECHNICAL, 0.93, "HTTP/HTTPS URL", plugins)

    try:
        ipaddress.ip_address(raw.strip("[]"))
        add("ip_address", Category.TECHNICAL, 0.96, "valid IP address", None)
    except ValueError:
        pass

    if _EMAIL_RE.fullmatch(raw):
        add("email", Category.PERSONAL, 0.95, "email address pattern", ["email_lookup"])

    if _HASH_RE.fullmatch(raw):
        add("hash", Category.CRYPTO, 0.92, "known hex digest length", ["hash_identifier"])

    if not raw.startswith(("http://", "https://")) and is_domain(raw):
        add("domain", Category.TECHNICAL, 0.9, "domain name pattern", None)

    encoded_score = _encoded_score(raw)
    if encoded_score:
        add("encoded_or_ciphertext", Category.CRYPTO, encoded_score, "encoded/ciphertext-like input", None, True)

    rot_score = _rot13_score(raw)
    if rot_score:
        add("rot13_text", Category.CRYPTO, rot_score, "ROT13 text is plausible", None, True)

    if _USERNAME_RE.fullmatch(raw):
        # Usernames are inherently ambiguous. Keep confidence moderate and expose alternatives.
        add(
            "username",
            Category.PERSONAL,
            0.74 if len(raw) <= 16 else 0.66,
            "username-like input",
            ["username_lookup", "github_user_lookup"],
            False,
            ["Username detection is ambiguous. Results are leads, not proof of identity."],
        )

    add("plain_text", Category.CRYPTO, 0.2, "fallback plain text interpretation", None, True)

    # Deduplicate by target_type, keep strongest score.
    by_type: dict[str, dict[str, object]] = {}
    for candidate in candidates:
        key = str(candidate["target_type"])
        if key not in by_type or float(candidate["confidence"] or 0) > float(by_type[key]["confidence"] or 0):
            by_type[key] = candidate
    return sorted(by_type.values(), key=lambda item: float(item["confidence"]), reverse=True)


def _plan_from_candidate(target: str, candidate: dict[str, object]) -> AnalysisPlan:
    return AnalysisPlan(
        target=target,
        target_type=str(candidate["target_type"]),
        category=candidate["category"],  # type: ignore[arg-type]
        plugins=candidate.get("plugins"),  # type: ignore[arg-type]
        use_crypto_engine=bool(candidate.get("use_crypto_engine")),
        confidence=float(candidate.get("confidence", 0.0)),
        reason=str(candidate.get("reason", "")),
        notes=list(candidate.get("notes", [])),  # type: ignore[arg-type]
    )


def _encoded_score(value: str) -> float | None:
    compact = re.sub(r"\s+", "", value.strip())
    if len(compact) < 4:
        return None
    if _HEXISH_RE.fullmatch(value) and len(re.sub(r"[^0-9A-Fa-f]", "", value)) % 2 == 0:
        return 0.82
    if len(compact) >= 8 and re.fullmatch(r"[A-Z2-7]+=*", compact):
        return 0.78
    if len(compact) % 4 in {0, 2, 3} and _BASE64ISH_RE.fullmatch(value):
        if any(ch in value for ch in "=+/ _-"):
            return 0.8
        if len(compact) >= 12:
            return 0.66
    if "%" in value or "&quot;" in value or "&#" in value:
        return 0.78
    return None


def _rot13_score(value: str) -> float | None:
    text = value.strip()
    if len(text) < 4 or not re.fullmatch(r"[A-Za-z\s{}_.!?,:-]+", text):
        return None
    decoded = codecs.decode(text, "rot_13")
    words = [word.strip("{}_.!?,:-").lower() for word in decoded.split()]
    if any(word in _COMMON_ROT13_WORDS for word in words):
        return 0.68
    # Short alphabetic strings may still be ROT-like, but keep lower than username.
    if text.isalpha() and 4 <= len(text) <= 12:
        return 0.52
    return None
