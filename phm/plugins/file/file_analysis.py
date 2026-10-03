"""Native file triage plugin."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from phm.analysis.file.native import analyze_file
from phm.core.artifacts import ArtifactType
from phm.core.models import Category, Detection, Evidence, Finding, Severity, TargetContext
from phm.core.plugin import BasePlugin
from phm.core.registry import registry


@registry.register
class FileAnalysisPlugin(BasePlugin):
    name = "file_analysis"
    category = Category.FILE
    module = "file"
    capability = "native_file_triage"
    consumes = (ArtifactType.FILE.value, ArtifactType.BINARY.value, ArtifactType.IMAGE.value, ArtifactType.DOCUMENT.value, ArtifactType.ARCHIVE.value)
    produces = (ArtifactType.HASH.value, ArtifactType.STRING.value, ArtifactType.URL.value, ArtifactType.EMAIL.value, ArtifactType.DOMAIN.value)
    description = "Native offline file triage: magic bytes, hashes, entropy, and string extraction."
    passive = True
    local_first = True
    network_required = False
    external_tool_required = False

    def detect(self, target: TargetContext) -> Detection:
        path = Path(target.value)
        ok = path.exists() and path.is_file()
        return Detection(ok, 0.96 if ok else 0.0, "local file exists" if ok else "target is not a local file")

    def collect(self, target: TargetContext) -> dict[str, Any]:
        return analyze_file(target.value, max_strings=int(target.options.get("max_strings", 200)))

    def analyze(self, target: TargetContext, raw: dict[str, Any]) -> list[Finding]:
        signatures = raw.get("signatures", [])
        hashes = raw.get("hashes", {})
        strings = raw.get("strings", [])
        severity = Severity.INFO
        if raw.get("extension_matches_signature") is False:
            severity = Severity.MEDIUM
        if raw.get("entropy", 0) >= 7.2 and signatures and signatures[0].get("artifact_type") == "binary":
            severity = Severity.MEDIUM
        if raw.get("potential_secrets") or raw.get("embedded_executables") or raw.get("suspicious_patterns"):
            severity = Severity.MEDIUM

        evidence = [
            Evidence(source="file.path", value=raw.get("path")),
            Evidence(source="file.size", value=raw.get("size")),
            Evidence(source="file.entropy", value=raw.get("entropy")),
            Evidence(source="file.extension", value=raw.get("extension")),
            Evidence(source="file.extension_matches_signature", value=raw.get("extension_matches_signature")),
            Evidence(source="file.hashes", value=hashes),
        ]
        for signature in signatures:
            evidence.append(Evidence(source="file.signature", value=signature))
        evidence.append(Evidence(source="file.iocs", value=raw.get("iocs", {})))
        evidence.append(Evidence(source="file.language_hints", value=raw.get("language_hints", [])))
        evidence.append(Evidence(source="file.embedded_archives", value=raw.get("embedded_archives", [])))
        evidence.append(Evidence(source="file.embedded_executables", value=raw.get("embedded_executables", [])))
        evidence.append(Evidence(source="file.image_info", value=raw.get("image_info", {})))
        evidence.append(Evidence(source="file.archive_info", value=raw.get("archive_info", {})))
        evidence.append(Evidence(source="file.potential_secrets", value=raw.get("potential_secrets", [])))
        evidence.append(Evidence(source="file.suspicious_patterns", value=raw.get("suspicious_patterns", [])))
        if raw.get("binary_info"):
            evidence.append(Evidence(source="file.binary_info", value=raw.get("binary_info")))
        for string in strings[:40]:
            evidence.append(Evidence(source="file.string", value=string))

        description = "Performed native file triage without external tools."
        if signatures:
            description += f" Primary signature: {signatures[0].get('name')}"
        else:
            description += " No known magic-byte signature was identified."

        findings = [Finding(
                title="Native file triage",
                description=description,
                category=self.category,
                plugin=self.name,
                confidence=0.9 if signatures else 0.65,
                severity=severity,
                evidence=evidence,
                metadata={
                    "primary_signature": signatures[0] if signatures else None,
                    "string_count": len(strings),
                    "ioc_counts": {key: len(value) for key, value in raw.get("iocs", {}).items()},
                    "embedded_archive_count": len(raw.get("embedded_archives", [])),
                    "embedded_executable_count": len(raw.get("embedded_executables", [])),
                    "secret_indicator_count": len(raw.get("potential_secrets", [])),
                    "suspicious_pattern_count": len(raw.get("suspicious_patterns", [])),
                    "binary_info": raw.get("binary_info", {}),
                    "external_tools_used": False,
                },
            )
        ]
        decoded = [item for item in raw.get("decoded_candidates", []) if item.get("value")]
        if decoded:
            findings.append(Finding(title="Decoded candidate extracted from file", description="A file string was passed through the bounded crypto engine; the best candidates are now available as investigation artifacts.", category=self.category, plugin=self.name, confidence=max(float(item.get("confidence",0)) for item in decoded), severity=Severity.LOW, evidence=[Evidence(source="file.decoded_candidate", value=item) for item in decoded[:20]], metadata={"recursive": True, "candidate_count": len(decoded)}))
        return findings

    def report(self, target: TargetContext, raw: dict[str, Any], findings: list[Finding], errors: list[str] | None = None):
        return self._result(target, raw, findings, errors)
