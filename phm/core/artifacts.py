"""Shared artifact system for PHM.

Artifacts are the connective tissue between modules. A plugin may start with one
artifact type and produce evidence containing other artifacts. The artifact layer
normalizes those observables so future modules can compose naturally:

    binary -> strings -> URLs -> domains -> DNS/RDAP/CRT.SH
    image  -> GPS     -> coordinates -> geospatial enrichment

This module is deterministic and deliberately lightweight. It does not replace
specialized parsers; it provides common observable extraction and canonical IDs.
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from phm.core.models import InvestigationReport, to_primitive


class ArtifactType(str, Enum):
    DOMAIN = "domain"
    IP = "ip"
    URL = "url"
    EMAIL = "email"
    USERNAME = "username"
    PHONE = "phone"
    CERTIFICATE = "certificate"
    API_KEY = "api_key"
    TOKEN = "token"
    UUID = "uuid"
    FILE = "file"
    BINARY = "binary"
    IMAGE = "image"
    DOCUMENT = "document"
    ARCHIVE = "archive"
    HASH = "hash"
    DNS_RECORD = "dns_record"
    COOKIE = "cookie"
    JWT = "jwt"
    JS_ENDPOINT = "javascript_endpoint"
    GITHUB_REPO = "github_repo"
    COORDINATE = "coordinate"
    STRING = "string"
    UNKNOWN = "unknown"


@dataclass(slots=True)
class Artifact:
    """Normalized observable produced or consumed by PHM modules."""

    type: ArtifactType
    value: str
    confidence: float = 1.0
    source_plugin: str | None = None
    source_finding: str | None = None
    source_evidence: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def id(self) -> str:
        digest = hashlib.sha256(f"{self.type.value}:{self.value}".encode("utf-8")).hexdigest()[:16]
        return f"artifact:{self.type.value}:{digest}"


_URL_RE = re.compile(r"https?://[^\s'\"<>]+")
_EMAIL_RE = re.compile(r"\b[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}\b")
_DOMAIN_RE = re.compile(r"(?<![A-Za-z0-9_-])(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}(?![A-Za-z0-9_-])")
_FILE_SUFFIXES = {"txt", "xml", "json", "html", "htm", "js", "css", "git", "bin", "png", "jpg", "jpeg", "gif", "zip", "pdf"}

def _valid_domain(value: str) -> bool:
    """Validate a hostname structurally, without substring filtering labels."""
    if any(separator in value for separator in ("/", "\\", ":")):
        return False
    labels = value.rstrip('.').split('.')
    if len(labels) < 2 or any(not label or len(label) > 63 for label in labels): return False
    if any(label.isdigit() for label in labels[:-1]): return False
    if any(not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label) for label in labels): return False
    final = labels[-1].lower()
    # Reject complete file-like final labels and compact suffix combinations
    # produced by concatenated filename/signature text (binpk/binpng). Do not
    # inspect arbitrary substrings in ordinary hostname labels.
    if final in _FILE_SUFFIXES: return False
    if any(final == suffix + tail for suffix in _FILE_SUFFIXES for tail in ("pk", "png", "jpg", "gif")):
        return False
    return len(value.rstrip('.')) <= 253
_GITHUB_REPO_RE = re.compile(r"github\.com[:/]([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)")
_HASH_RE = re.compile(r"\b(?:[A-Fa-f0-9]{32}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{56}|[A-Fa-f0-9]{64}|[A-Fa-f0-9]{96}|[A-Fa-f0-9]{128})\b")
_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")
_UUID_RE = re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}\b")
_API_KEY_RE = re.compile(r"(?i)\b(?:api[_-]?key|client[_-]?secret|access[_-]?token|auth[_-]?token|secret)\b\s*[:=]\s*['\"]?([A-Za-z0-9_./+=-]{20,})")
_TOKEN_RE = re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9_]{36,}|glpat-[A-Za-z0-9_-]{20,}|xox[baprs]-[A-Za-z0-9-]{10,}|AIza[0-9A-Za-z_-]{35})\b")
_CERT_RE = re.compile(r"-----BEGIN [A-Z ]*CERTIFICATE-----")
_JS_ENDPOINT_RE = re.compile(r"[\"']((?:/[A-Za-z0-9_./{}:-]+){1,}(?:\?[A-Za-z0-9_=&{}.-]+)?)['\"]")
_COORD_RE = re.compile(r"(?<!\d)([-+]?\d{1,2}\.\d{3,})\s*,\s*([-+]?\d{1,3}\.\d{3,})(?!\d)")
_PHONE_RE = re.compile(r"(?<!\w)(?:\+?\d[\d .()\-]{7,}\d)(?!\w)")

_RESERVED_DOMAINS = {"github.com", "api.github.com", "www.github.com", "example.com", "example.org", "example.net"}


def canonicalize_artifact(artifact_type: ArtifactType, value: str) -> str:
    value = str(value).strip().strip("'\"<>[]{}(),;")
    if artifact_type in {ArtifactType.DOMAIN, ArtifactType.EMAIL, ArtifactType.GITHUB_REPO}:
        value = value.lower().rstrip(".")
    if artifact_type == ArtifactType.IP:
        try:
            value = str(ipaddress.ip_address(value.strip("[]")))
        except ValueError:
            pass
    if artifact_type == ArtifactType.URL:
        value = value.rstrip(".,);]")
    if artifact_type == ArtifactType.HASH:
        value = value.lower()
    if artifact_type in {ArtifactType.API_KEY, ArtifactType.TOKEN}:
        if len(value) > 10:
            value = f"{value[:4]}...{value[-4:]}"
        else:
            value = "<redacted>"
    if artifact_type == ArtifactType.COORDINATE:
        value = re.sub(r"\s+", "", value)
    return value


def hash_type(value: str) -> str:
    """Best-effort hash family by encoded length/prefix."""

    value = value.strip()
    if value.startswith("$2a$") or value.startswith("$2b$") or value.startswith("$2y$"):
        return "bcrypt"
    if value.startswith("$argon2"):
        return "argon2"
    lengths = {32: "md5_or_ntlm", 40: "sha1", 56: "sha224", 64: "sha256", 96: "sha384", 128: "sha512"}
    return lengths.get(len(value), "unknown_hash")


def extract_artifacts(
    value: Any,
    *,
    source_plugin: str | None = None,
    source_finding: str | None = None,
    source_evidence: str | None = None,
    confidence: float = 0.75,
) -> list[Artifact]:
    """Extract common artifacts from arbitrary text-like data."""

    # Structured evidence is handled by the producing analyzer. Stringifying
    # arbitrary dictionaries turns field adjacency (for example `bin` + `png`)
    # into fake hostnames. Lists remain scanable because link/resource evidence
    # is commonly represented as a list of strings.
    if isinstance(value, dict):
        return []
    text = " ".join(map(str, value)) if isinstance(value, (list, tuple, set)) else str(value)
    artifacts: list[Artifact] = []

    def add(artifact_type: ArtifactType, raw_value: str, artifact_confidence: float = confidence, metadata: dict[str, Any] | None = None) -> None:
        canonical = canonicalize_artifact(artifact_type, raw_value)
        if not canonical:
            return
        artifacts.append(
            Artifact(
                type=artifact_type,
                value=canonical,
                confidence=artifact_confidence,
                source_plugin=source_plugin,
                source_finding=source_finding,
                source_evidence=source_evidence,
                metadata=metadata or {},
            )
        )

    urls = _URL_RE.findall(text)
    for url in urls:
        add(ArtifactType.URL, url, 0.9)
    repos = _GITHUB_REPO_RE.findall(text)
    for repo in repos:
        add(ArtifactType.GITHUB_REPO, repo, 0.95)
    # Generic domain extraction runs on text outside URLs/repository paths.
    residual = text
    for url in urls:
        residual = residual.replace(url, " ")
    residual = re.sub(r"(?i)github\.com[:/]?[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", " ", residual)
    for email in _EMAIL_RE.findall(text):
        add(ArtifactType.EMAIL, email, 0.9)
    for match in _DOMAIN_RE.finditer(residual):
        if (match.start() and residual[match.start() - 1] in '/\\') or (match.end() < len(residual) and residual[match.end()] in '/\\'):
            continue
        domain = canonicalize_artifact(ArtifactType.DOMAIN, match.group(0))
        if _valid_domain(domain):
            add(ArtifactType.DOMAIN, domain, 0.82)
    for token in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text):
        try:
            add(ArtifactType.IP, str(ipaddress.ip_address(token)), 0.88)
        except ValueError:
            pass
    for token in _JWT_RE.findall(text):
        add(ArtifactType.JWT, token, 0.86)
    for value in _UUID_RE.findall(text):
        add(ArtifactType.UUID, value, 0.8)
    for value in _TOKEN_RE.findall(text):
        add(ArtifactType.TOKEN, value, 0.82)
    for value in _API_KEY_RE.findall(text):
        add(ArtifactType.API_KEY, value, 0.72)
    if _CERT_RE.search(text):
        add(ArtifactType.CERTIFICATE, "PEM certificate block", 0.85)
    for endpoint in _JS_ENDPOINT_RE.findall(text):
        if len(endpoint) > 1 and not endpoint.startswith("//"):
            add(ArtifactType.JS_ENDPOINT, endpoint, 0.6)
    for digest in _HASH_RE.findall(text):
        add(ArtifactType.HASH, digest, 0.88, {"hash_type": hash_type(digest)})
    for lat, lon in _COORD_RE.findall(text):
        try:
            lat_f = float(lat)
            lon_f = float(lon)
            if -90 <= lat_f <= 90 and -180 <= lon_f <= 180:
                add(ArtifactType.COORDINATE, f"{lat_f:.6f},{lon_f:.6f}", 0.78)
        except ValueError:
            pass
    known_ip_text = set()
    for candidate in re.findall(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])", text):
        try:
            ipaddress.ip_address(candidate); known_ip_text.add(candidate)
        except ValueError:
            pass
    for phone in _PHONE_RE.findall(text):
        if phone.strip() in known_ip_text or phone.replace(" ", "") in known_ip_text or re.fullmatch(r"[+-]?\d+\.\d+", phone.strip()):
            continue
        digits = re.sub(r"\D", "", phone)
        if 8 <= len(digits) <= 15:
            add(ArtifactType.PHONE, phone, 0.55, {"digits": digits})

    return _dedupe_artifacts(artifacts)


def artifacts_from_report(report: InvestigationReport) -> list[dict[str, Any]]:
    """Extract and deduplicate artifacts from report findings and raw data."""

    collected: list[Artifact] = []
    collected.append(Artifact(type=ArtifactType.UNKNOWN, value=report.target, confidence=1.0, metadata={"role": "target", "category": report.category.value}))

    for result in report.results:
        for finding in result.findings:
            for evidence in finding.evidence:
                collected.extend(
                    extract_artifacts(
                        evidence.value,
                        source_plugin=result.plugin,
                        source_finding=finding.title,
                        source_evidence=evidence.source,
                        confidence=finding.confidence,
                    )
                )
        # Do not scan raw provider responses wholesale. DNS/RDAP/geolocation
        # payloads contain documentation hosts, timestamps, and coordinates that
        # are not useful recursive leads. Plugins promote useful values through evidence.

    return [to_primitive(artifact) | {"id": artifact.id, "type": artifact.type.value} for artifact in _dedupe_artifacts(collected)]


def _dedupe_artifacts(artifacts: list[Artifact]) -> list[Artifact]:
    by_key: dict[tuple[ArtifactType, str], Artifact] = {}
    for artifact in artifacts:
        key = (artifact.type, artifact.value)
        if key not in by_key or artifact.confidence > by_key[key].confidence:
            by_key[key] = artifact
        else:
            existing = by_key[key]
            existing.metadata.setdefault("additional_sources", [])
            existing.metadata["additional_sources"].append(
                {
                    "source_plugin": artifact.source_plugin,
                    "source_finding": artifact.source_finding,
                    "source_evidence": artifact.source_evidence,
                    "confidence": artifact.confidence,
                }
            )
    return sorted(by_key.values(), key=lambda item: (item.type.value, item.value))
