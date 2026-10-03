"""Reporting engine for PHM outputs."""

from __future__ import annotations

import csv
import io
import json
from abc import ABC, abstractmethod
from html import escape
from pathlib import Path

from phm import __version__
from phm.core.models import InvestigationReport, PluginResult, to_primitive


class Reporter(ABC):
    """Reporter base class."""

    format_name: str

    @abstractmethod
    def render(self, report: InvestigationReport) -> str:
        """Render an investigation report."""


class JSONReporter(Reporter):
    format_name = "json"

    def render(self, report: InvestigationReport) -> str:
        return json.dumps(to_primitive(report), indent=2, sort_keys=True, default=str)


def _safe_evidence(evidence_items, max_items: int = 3) -> list[str]:
    """Return concise evidence strings for non-verbose terminal output."""

    output: list[str] = []
    for evidence in evidence_items:
        if str(evidence.source) in {"http.server_header"}:
            continue
        value = evidence.value
        if value is None or value == "" or value == [] or value == {}:
            continue
        if isinstance(value, dict):
            if "name" in value:
                text = str(value["name"])
            elif "full_name" in value:
                text = str(value["full_name"])
            elif "hostname" in value:
                text = str(value["hostname"])
            else:
                continue
        elif isinstance(value, list):
            if not value:
                continue
            text = f"{len(value)} item(s)"
        else:
            text = str(value)
        if len(text) > 140:
            text = text[:137] + "..."
        label = str(evidence.source).replace(".", " ").replace(":", " ")
        output.append(f"  {label}: {text}")
        if len(output) >= max_items:
            break
    return output


class TerminalReporter(Reporter):
    format_name = "terminal"

    def render(self, report: InvestigationReport) -> str:
        verbose = bool(report.metadata.get("display", {}).get("verbose")) if isinstance(report.metadata, dict) else False
        lines: list[str] = []
        lines.append(f"╭─ PHM {__version__} • Investigation {'─' * 24}╮")
        lines.append("╰──────────────────────────────────────────────╯")
        lines.append("")
        lines.append("TARGET")
        lines.append(f"  {self._short(report.target, 120)}")

        plan = report.metadata.get("analysis_plan") if isinstance(report.metadata, dict) else None
        if isinstance(plan, dict):
            detected = plan.get("target_type", "unknown")
            confidence = plan.get("confidence")
            if verbose and isinstance(confidence, int | float):
                lines.append(f"Detected: {detected} ({round(float(confidence) * 100)}%)")
            else:
                lines.append("Detected:")
                lines.append(f"  {detected}")
            alternatives = plan.get("alternatives") or []
            if alternatives:
                lines.append("Other possible interpretations:")
                for alt in alternatives[:3]:
                    if verbose:
                        try:
                            pct = round(float(alt.get("confidence", 0)) * 100)
                            lines.append(f"  - {alt.get('target_type', 'unknown')} ({pct}%)")
                        except Exception:
                            lines.append(f"  - {alt.get('target_type', 'unknown')}")
                    else:
                        lines.append(f"  - {alt.get('target_type', 'unknown')}")

        if not report.results:
            lines.append(report.metadata.get("message", "No results."))
            return "\n".join(lines)

        self._append_summary(lines, report)
        self._append_pivots(lines, report)
        self._append_findings(lines, report, verbose)
        self._append_next_steps(lines, report)
        return "\n".join(lines)

    def _append_summary(self, lines: list[str], report: InvestigationReport) -> None:
        summary = report.metadata.get("summary", {}) if isinstance(report.metadata, dict) else {}
        fields = summary.get("fields", []) if isinstance(summary, dict) else []
        interesting = summary.get("interesting", []) if isinstance(summary, dict) else []
        if not fields and not interesting:
            return
        lines.append("")
        lines.append("SUMMARY")
        for item in fields[:10]:
            label = item.get("label", "Item")
            value = self._short(str(item.get("value", "")), 100)
            lines.append(f"  {label:<14} {value}")
        if interesting:
            lines.append("")
            lines.append("INTERESTING")
            for item in interesting[:8]: lines.append(f"  [!] {self._short(str(item), 100)}")
        artifacts = report.metadata.get("artifacts", [])
        if artifacts:
            lines.append("")
            lines.append("ARTIFACTS")
            for artifact in artifacts[:12]:
                lines.append(f"  └─ {artifact.get('type', 'artifact')}: {self._short(str(artifact.get('value','')), 90)}")
            if len(artifacts) > 12: lines.append(f"  ... and {len(artifacts)-12} more")

    @staticmethod
    def _short(value: str, limit: int = 100) -> str:
        value = " ".join(value.split())
        return value if len(value) <= limit else value[:limit-3] + "..."

    def _append_pivots(self, lines: list[str], report: InvestigationReport) -> None:
        pivots = report.metadata.get('pivots', []) if isinstance(report.metadata, dict) else []
        if not pivots: return
        lines.append('')
        lines.append('PIVOTS')
        for pivot in pivots[:12]:
            lines.append(f"  └─ {self._short(str(pivot.get('source')), 45)} → {self._short(str(pivot.get('relationship')), 80)}")
        if len(pivots) > 12: lines.append(f'  ... and {len(pivots)-12} more')

    def _append_findings(self, lines: list[str], report: InvestigationReport, verbose: bool) -> None:
        lines.append("")
        lines.append("FINDINGS")
        shown = 0
        for result in report.results:
            if verbose:
                lines.append(f"[{result.status.upper()}] {result.plugin}")
                for error in result.errors:
                    lines.append(f"  ! {error}")
            elif result.errors:
                lines.append(f"- Some checks failed in {result.plugin}. Re-run with --verbose for details.")
            for finding in result.findings:
                shown += 1
                prefix = "  [!]" if finding.severity.value in {"medium", "high"} else "  [+]"
                if verbose:
                    conf = round(finding.confidence * 100)
                    lines.append(f"{prefix} {finding.title} ({conf}%)")
                else:
                    lines.append(f"{prefix} {finding.title}")
                lines.append(f"      {self._short(finding.description, 110)}")
                if verbose:
                    for evidence in finding.evidence:
                        lines.append(f"    evidence: {evidence.source} = {evidence.value}")
                else:
                    for evidence in _safe_evidence(finding.evidence, max_items=3):
                        lines.append(f"  {evidence}")
        if shown == 0:
            lines.append("No findings.")

    def _append_next_steps(self, lines: list[str], report: InvestigationReport) -> None:
        next_steps = report.metadata.get("next_steps", []) if isinstance(report.metadata, dict) else []
        if not next_steps:
            return
        lines.append("")
        lines.append("NEXT")
        for index, step in enumerate(next_steps[:6], start=1):
            title = step.get("title", "Review findings")
            why = step.get("why", "This may help continue the investigation.")
            priority = step.get("priority", "medium")
            lines.append(f"{index}. {title} [{priority}]")
            lines.append(f"   {why}")
            if step.get("command"):
                lines.append(f"   Try: {step['command']}")


class CSVReporter(Reporter):
    format_name = "csv"

    def render(self, report: InvestigationReport) -> str:
        buffer = io.StringIO()
        writer = csv.DictWriter(
            buffer,
            fieldnames=["category", "target", "plugin", "status", "title", "confidence", "severity", "description"],
        )
        writer.writeheader()
        for result in report.results:
            if not result.findings:
                writer.writerow(
                    {
                        "category": report.category.value,
                        "target": report.target,
                        "plugin": result.plugin,
                        "status": result.status,
                        "title": "",
                        "confidence": "",
                        "severity": "",
                        "description": "; ".join(result.errors),
                    }
                )
            for finding in result.findings:
                writer.writerow(
                    {
                        "category": report.category.value,
                        "target": report.target,
                        "plugin": result.plugin,
                        "status": result.status,
                        "title": finding.title,
                        "confidence": finding.confidence,
                        "severity": finding.severity.value,
                        "description": finding.description,
                    }
                )
        return buffer.getvalue()


class MarkdownReporter(Reporter):
    format_name = "markdown"

    def render(self, report: InvestigationReport) -> str:
        lines = [f"# PHM Report: `{report.category.value}`", "", f"**Target:** `{report.target}`", ""]
        for result in report.results:
            lines.extend([f"## {result.plugin} ({result.status})", ""])
            for error in result.errors:
                lines.append(f"> Error: {error}")
            if not result.findings:
                lines.extend(["No findings.", ""])
                continue
            for finding in result.findings:
                lines.extend(
                    [
                        f"### {finding.title}",
                        "",
                        f"- Confidence: `{finding.confidence:.2f}`",
                        f"- Severity: `{finding.severity.value}`",
                        f"- Description: {finding.description}",
                        "",
                    ]
                )
                if finding.evidence:
                    lines.append("Evidence:")
                    for evidence in finding.evidence:
                        lines.append(f"- `{evidence.source}`: `{evidence.value}`")
                    lines.append("")
        next_steps = report.metadata.get("next_steps", []) if isinstance(report.metadata, dict) else []
        if next_steps:
            lines.extend(["## Suggested next steps", ""])
            for index, step in enumerate(next_steps, start=1):
                lines.append(f"{index}. **{step.get('title', 'Review findings')}** — {step.get('why', '')}")
                if step.get("command"):
                    lines.append(f"   - Try: `{step['command']}`")
            lines.append("")
        return "\n".join(lines)


class HTMLReporter(Reporter):
    format_name = "html"

    def render(self, report: InvestigationReport) -> str:
        body = [
            "<!doctype html><html><head><meta charset='utf-8'>",
            "<title>PHM Report</title>",
            "<style>body{font-family:system-ui;margin:2rem;background:#0f1220;color:#e8eaf6}"
            ".card{border:1px solid #30364d;border-radius:12px;padding:1rem;margin:1rem 0;background:#171b2e}"
            ".muted{color:#aab}.ok{color:#7ee787}.error{color:#ff7b72}code{background:#222842;padding:.15rem .35rem;border-radius:4px}</style>",
            "</head><body>",
            f"<h1>PHM Report: {escape(report.category.value)}</h1>",
            f"<p class='muted'>Target: <code>{escape(report.target)}</code></p>",
        ]
        for result in report.results:
            body.append(f"<section class='card'><h2>{escape(result.plugin)} <span class='{escape(result.status)}'>{escape(result.status)}</span></h2>")
            for error in result.errors:
                body.append(f"<p class='error'>{escape(error)}</p>")
            if not result.findings:
                body.append("<p>No findings.</p></section>")
                continue
            for finding in result.findings:
                body.append(f"<h3>{escape(finding.title)}</h3>")
                body.append(f"<p>{escape(finding.description)}</p>")
                body.append(f"<p class='muted'>confidence={finding.confidence:.2f}; severity={escape(finding.severity.value)}</p>")
                if finding.evidence:
                    body.append("<ul>")
                    for evidence in finding.evidence:
                        body.append(f"<li><code>{escape(evidence.source)}</code>: {escape(str(evidence.value))}</li>")
                    body.append("</ul>")
            body.append("</section>")
        next_steps = report.metadata.get("next_steps", []) if isinstance(report.metadata, dict) else []
        if next_steps:
            body.append("<section class='card'><h2>Suggested next steps</h2><ol>")
            for step in next_steps:
                body.append(f"<li><strong>{escape(step.get('title', 'Review findings'))}</strong><br><span class='muted'>{escape(step.get('why', ''))}</span>")
                if step.get("command"):
                    body.append(f"<br><code>{escape(step['command'])}</code>")
                body.append("</li>")
            body.append("</ol></section>")
        body.append("</body></html>")
        return "\n".join(body)


REPORTERS: dict[str, Reporter] = {
    reporter.format_name: reporter
    for reporter in [TerminalReporter(), JSONReporter(), CSVReporter(), MarkdownReporter(), HTMLReporter()]
}


def render_report(report: InvestigationReport, output_format: str = "terminal") -> str:
    try:
        reporter = REPORTERS[output_format]
    except KeyError as exc:
        known = ", ".join(sorted(REPORTERS))
        raise ValueError(f"Unsupported report format '{output_format}'. Known formats: {known}") from exc
    return reporter.render(report)


def write_report(rendered: str, path: str | Path) -> None:
    Path(path).write_text(rendered, encoding="utf-8")
