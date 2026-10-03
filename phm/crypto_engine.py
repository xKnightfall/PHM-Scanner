"""Smart cryptography/encoding engine.

The engine is deliberately deterministic: no AI, no model calls. It performs
bounded graph traversal over registered crypto transform plugins, ranks decode
candidates with confidence scoring, and returns a decoding graph for reporting.
"""

from __future__ import annotations

import base64
import bz2
import gzip
import json
import lzma
import re
import zlib
from dataclasses import dataclass, field
from typing import Any, Callable, Protocol

from phm.core.artifacts import artifacts_from_report
from phm.core.models import Category, Detection, Evidence, Finding, InvestigationReport, PluginResult, Severity, TargetContext
from phm.core.recommendations import build_next_steps
from phm.core.registry import registry
from phm.core.summary import build_summary


@dataclass(slots=True)
class TransformCandidate:
    """One possible crypto transform output."""

    value: str
    confidence: float
    metadata: dict[str, Any] = field(default_factory=dict)


class CryptoTransformPlugin(Protocol):
    """Protocol implemented by crypto plugins used by SmartCryptoEngine."""

    name: str

    def detect(self, target: TargetContext): ...

    def decode_candidates(self, value: str, options: dict[str, Any] | None = None) -> list[TransformCandidate]: ...


@dataclass(slots=True)
class DecodeNode:
    id: int
    value: str
    path: list[str]
    confidence: float
    text_score: float
    parent: int | None = None
    transform: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


_COMMON_WORDS = {
    "the",
    "and",
    "that",
    "have",
    "for",
    "not",
    "with",
    "you",
    "this",
    "but",
    "flag",
    "ctf",
    "password",
    "secret",
    "token",
    "hello",
    "world",
}

_STRUCTURED_PATTERNS = [
    re.compile(r"^\s*\{.*\}\s*$", re.S),
    re.compile(r"^\s*\[.*\]\s*$", re.S),
    re.compile(r"<\?xml|<html|</[a-z]+>", re.I),
    re.compile(r"https?://|\b[a-z0-9.-]+\.[a-z]{2,}\b", re.I),
    re.compile(r"\bselect\b.+\bfrom\b|\binsert\s+into\b|\bcreate\s+table\b", re.I | re.S),
    re.compile(r"\b(import|from|def|class|function|const|let|var)\b", re.I),
    re.compile(r"-----BEGIN [A-Z ]+(?:KEY|CERTIFICATE)-----"),
    re.compile(r"^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$"),
]


def score_text(value: str) -> float:
    """Estimate whether decoded output looks like meaningful plaintext."""

    if not value:
        return 0.0
    printable = sum(1 for ch in value if ch.isprintable() or ch in "\r\n\t") / len(value)
    replacement_penalty = min(0.35, value.count("\ufffd") / max(1, len(value)))
    alpha_space = sum(1 for ch in value if ch.isalpha() or ch.isspace() or ch in "{}[]()_-:;,.!?@#$%&*/+=<>\"'") / len(value)
    words = [word.strip("{}[]()_-:;,.!?@#$%&*/+=<>\"'").lower() for word in value.split()]
    word_hits = sum(1 for word in words if word in _COMMON_WORDS)
    word_score = min(1.0, word_hits / 3) if words else 0.0
    length_bonus = min(0.12, len(value) / 500)
    structured_bonus = 0.0
    if any(pattern.search(value) for pattern in _STRUCTURED_PATTERNS):
        structured_bonus = 0.16
    try:
        json.loads(value)
        structured_bonus = max(structured_bonus, 0.22)
    except Exception:
        pass
    score = 0.50 * printable + 0.23 * alpha_space + 0.14 * word_score + length_bonus + structured_bonus - replacement_penalty
    return max(0.0, min(1.0, score))


def _node_confidence(text_score: float, path: list[str], candidate_confidences: list[float]) -> float:
    if not path:
        return 0.25 * text_score
    avg_transform = sum(candidate_confidences) / max(1, len(candidate_confidences))
    depth_reward = min(0.16, 0.04 * len(path))
    return max(0.0, min(1.0, 0.52 * text_score + 0.36 * avg_transform + depth_reward))


class _BuiltinTransform:
    def __init__(self, name: str, detector: Callable[[str], bool], decoder: Callable[[str], list[TransformCandidate]], confidence: float = 0.75) -> None:
        self.name = name
        self._detector = detector
        self._decoder = decoder
        self._confidence = confidence

    def detect(self, target: TargetContext) -> Detection:
        try:
            ok = self._detector(target.value)
        except Exception:
            ok = False
        return Detection(ok, self._confidence if ok else 0.0, f"{self.name} candidate" if ok else "not applicable")

    def decode_candidates(self, value: str, options: dict[str, Any] | None = None) -> list[TransformCandidate]:
        return self._decoder(value)


_BASE91 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&()*+,./:;<=>?@[]^_`{|}~\""

def _decode_base91(value: str) -> list[TransformCandidate]:
    try:
        table = {c:i for i,c in enumerate(_BASE91)}; b=0; n=0; v=-1; out=bytearray()
        for c in value.strip():
            if c not in table: continue
            if v < 0: v=table[c]
            else:
                v += table[c]*91; b |= v << n; n += 13 if (v & 8191) > 88 else 14
                while n >= 8: out.append(b & 255); b >>= 8; n -= 8
                v=-1
        text=bytes(out).decode('utf-8',errors='replace')
        return [TransformCandidate(text,.7,{"encoding":"base91","text_score":score_text(text)})] if text else []
    except Exception: return []

def _builtin_transforms() -> list[_BuiltinTransform]:
    return [
        _BuiltinTransform("base91_decoder", lambda value: len(value.strip()) >= 8 and all(c in _BASE91 for c in value.strip()), _decode_base91, 0.67),
        _BuiltinTransform("base32_decoder", _is_base32, lambda value: _decode_text(value, lambda raw: base64.b32decode(_pad(raw), casefold=True)), 0.84),
        _BuiltinTransform("base85_decoder", _is_base85, lambda value: _decode_text(value, lambda raw: base64.b85decode(raw.encode())), 0.78),
        _BuiltinTransform("ascii85_decoder", lambda value: "<~" in value or "~>" in value, lambda value: _decode_text(value, lambda raw: base64.a85decode(raw.encode(), adobe="<~" in raw)), 0.78),
        _BuiltinTransform("base58_decoder", _is_base58, _decode_base58, 0.68),
        _BuiltinTransform("jwt_decoder", _is_jwt, _decode_jwt, 0.9),
        _BuiltinTransform("gzip_decoder", _looks_compressed_text, lambda value: _decode_compressed(value, gzip.decompress, "gzip"), 0.7),
        _BuiltinTransform("zlib_decoder", _looks_compressed_text, lambda value: _decode_compressed(value, zlib.decompress, "zlib"), 0.68),
        _BuiltinTransform("bz2_decoder", _looks_compressed_text, lambda value: _decode_compressed(value, bz2.decompress, "bz2"), 0.65),
        _BuiltinTransform("lzma_decoder", _looks_compressed_text, lambda value: _decode_compressed(value, lzma.decompress, "lzma"), 0.65),
        _BuiltinTransform("caesar_decoder", lambda value: bool(re.fullmatch(r"[A-Za-z\s{}_.!?,:'\"-]{4,}", value.strip())), _decode_caesar, 0.42),
        _BuiltinTransform("pem_detector", lambda value: "-----BEGIN " in value and "-----END " in value, lambda value: [TransformCandidate(value=value, confidence=0.95, metadata={"format": "pem"})], 0.95),
    ]


def _pad(value: str, block: int = 8) -> str:
    compact = re.sub(r"\s+", "", value)
    return compact + "=" * ((block - len(compact) % block) % block)


def _decode_text(value: str, decoder: Callable[[str], bytes]) -> list[TransformCandidate]:
    try:
        decoded = decoder(value).decode("utf-8", errors="replace")
        return [TransformCandidate(decoded, 0.82, {"text_score": score_text(decoded)})] if decoded else []
    except Exception:
        return []


def _is_base32(value: str) -> bool:
    compact = re.sub(r"\s+", "", value.strip().rstrip("="))
    return len(compact) >= 8 and bool(re.fullmatch(r"[A-Z2-7a-z]+", compact))


def _is_base85(value: str) -> bool:
    stripped = value.strip()
    return len(stripped) >= 5 and not any(ch.isspace() for ch in stripped) and any(ch in stripped for ch in "!#$%&()*+-;<=>?@^_`{|}~")


_B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def _is_base58(value: str) -> bool:
    stripped = value.strip()
    return 6 <= len(stripped) <= 400 and all(ch in _B58_ALPHABET for ch in stripped) and any(ch.isdigit() for ch in stripped)


def _decode_base58(value: str) -> list[TransformCandidate]:
    try:
        number = 0
        for char in value.strip():
            number = number * 58 + _B58_ALPHABET.index(char)
        data = number.to_bytes((number.bit_length() + 7) // 8, "big")
        decoded = data.decode("utf-8", errors="replace")
        if not decoded:
            return []
        return [TransformCandidate(decoded, 0.72, {"encoding": "base58", "text_score": score_text(decoded)})]
    except Exception:
        return []


def _is_jwt(value: str) -> bool:
    return bool(re.fullmatch(r"[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", value.strip()))


def _decode_jwt(value: str) -> list[TransformCandidate]:
    parts = value.strip().split(".")
    if len(parts) < 2:
        return []
    try:
        decoded_parts = []
        for part in parts[:2]:
            padded = part + "=" * ((4 - len(part) % 4) % 4)
            decoded_parts.append(json.loads(base64.urlsafe_b64decode(padded).decode("utf-8", errors="replace")))
        text = json.dumps({"header": decoded_parts[0], "payload": decoded_parts[1]}, indent=2, sort_keys=True)
        return [TransformCandidate(text, 0.95, {"format": "jwt", "text_score": score_text(text)})]
    except Exception:
        return []


def _looks_compressed_text(value: str) -> bool:
    return bool(re.fullmatch(r"[A-Za-z0-9+/=\s_-]{12,}", value.strip()))


def _decode_compressed(value: str, decompress: Callable[[bytes], bytes], name: str) -> list[TransformCandidate]:
    candidates: list[bytes] = []
    raw = value.strip()
    try:
        candidates.append(base64.b64decode(raw + "=" * ((4 - len(raw) % 4) % 4)))
    except Exception:
        pass
    try:
        candidates.append(bytes.fromhex(re.sub(r"[^0-9a-fA-F]", "", raw)))
    except Exception:
        pass
    outputs: list[TransformCandidate] = []
    for data in candidates:
        try:
            decoded = decompress(data).decode("utf-8", errors="replace")
            if decoded:
                outputs.append(TransformCandidate(decoded, 0.82, {"compression": name, "text_score": score_text(decoded)}))
        except Exception:
            continue
    return outputs


def _decode_caesar(value: str) -> list[TransformCandidate]:
    outputs: list[TransformCandidate] = []
    for shift in range(1, 26):
        decoded_chars = []
        for ch in value:
            if "a" <= ch <= "z":
                decoded_chars.append(chr((ord(ch) - ord("a") - shift) % 26 + ord("a")))
            elif "A" <= ch <= "Z":
                decoded_chars.append(chr((ord(ch) - ord("A") - shift) % 26 + ord("A")))
            else:
                decoded_chars.append(ch)
        decoded = "".join(decoded_chars)
        text_score = score_text(decoded)
        if text_score >= 0.72:
            outputs.append(TransformCandidate(decoded, 0.48 + text_score * 0.25, {"cipher": "caesar", "shift": shift, "text_score": text_score}))
    return sorted(outputs, key=lambda item: item.confidence, reverse=True)[:5]


class SmartCryptoEngine:
    """Bounded beam-search decoder over registered crypto plugins."""

    def __init__(self, max_depth: int = 4, beam_width: int = 8) -> None:
        self.max_depth = max_depth
        self.beam_width = beam_width

    def run(self, input_value: str, options: dict[str, Any] | None = None) -> InvestigationReport:
        options = options or {}
        max_depth = int(options.get("max_depth", self.max_depth))
        beam_width = int(options.get("beam_width", self.beam_width))
        plugins = [plugin for plugin in registry.by_category(Category.CRYPTO) if hasattr(plugin, "decode_candidates")]
        transforms = [*plugins, *_builtin_transforms()]

        graph: list[DecodeNode] = []
        root_score = score_text(input_value)
        root = DecodeNode(id=0, value=input_value, path=[], confidence=_node_confidence(root_score, [], []), text_score=root_score)
        graph.append(root)
        frontier = [root]
        best = root
        seen = {input_value}
        candidate_conf_by_node: dict[int, list[float]] = {0: []}

        next_id = 1
        for _depth in range(max_depth):
            expanded: list[DecodeNode] = []
            for node in frontier:
                context = TargetContext(value=node.value, category=Category.CRYPTO, options=options)
                for plugin in transforms:
                    detection = plugin.detect(context)
                    if not detection.applicable:
                        continue
                    try:
                        candidates = plugin.decode_candidates(node.value, options)
                    except Exception:
                        continue
                    for candidate in candidates:
                        value = candidate.value
                        if not value or value == node.value or value in seen:
                            continue
                        seen.add(value)
                        path = [*node.path, plugin.name]
                        inherited_confidences = candidate_conf_by_node.get(node.id, [])
                        candidate_confidences = [*inherited_confidences, candidate.confidence * detection.confidence]
                        text_score = score_text(value)
                        if text_score < float(options.get("min_branch_text_score", 0.25)) and candidate.confidence < 0.85:
                            continue
                        confidence = _node_confidence(text_score, path, candidate_confidences)
                        if confidence <= node.confidence and len(path) > 1 and text_score <= node.text_score:
                            continue
                        child = DecodeNode(
                            id=next_id,
                            value=value,
                            path=path,
                            parent=node.id,
                            transform=plugin.name,
                            text_score=text_score,
                            confidence=confidence,
                            metadata=candidate.metadata,
                        )
                        candidate_conf_by_node[next_id] = candidate_confidences
                        next_id += 1
                        graph.append(child)
                        expanded.append(child)
                        if child.confidence > best.confidence:
                            best = child
            if not expanded:
                break
            expanded.sort(key=lambda item: item.confidence, reverse=True)
            frontier = expanded[:beam_width]
            # Stop early when the best node is highly readable and the most recent
            # layer failed to produce an even better candidate.
            if best.confidence >= float(options.get("stop_confidence", 0.93)):
                break

        graph_data = [
            {
                "id": node.id,
                "parent": node.parent,
                "transform": node.transform,
                "path": node.path,
                "confidence": node.confidence,
                "text_score": node.text_score,
                "preview": node.value[:240],
                "metadata": node.metadata,
            }
            for node in graph
        ]

        finding = Finding(
            title="Smart crypto decode candidate",
            description="Best decoding path found by repeatable graph search.",
            category=Category.CRYPTO,
            plugin="smart_crypto_engine",
            confidence=best.confidence,
            severity=Severity.INFO,
            evidence=[
                Evidence(source="decode_path", value=" -> ".join(best.path) if best.path else "none"),
                Evidence(source="plaintext_candidate", value=best.value),
                Evidence(source="graph_nodes", value=len(graph)),
            ],
            metadata={"best_node_id": best.id, "graph": graph_data},
        )
        result = PluginResult(
            plugin="smart_crypto_engine",
            category=Category.CRYPTO,
            target="<crypto-input>",
            status="ok",
            findings=[finding],
            raw={"best": {"value": best.value, "path": best.path, "confidence": best.confidence}, "graph": graph_data},
        )
        report = InvestigationReport(target="<crypto-input>", category=Category.CRYPTO, results=[result], metadata={"engine": "beam_search"})
        report.metadata["artifacts"] = artifacts_from_report(report)
        report.metadata["summary"] = build_summary(report)
        report.metadata["next_steps"] = build_next_steps(report)
        return report
