"""CRT.SH Certificate Transparency source adapter."""

from __future__ import annotations

import json
import re
import urllib.parse
import urllib.request
from typing import Any

from phm.sources.base import SourceAdapter
from phm.sources.common import is_domain, normalize_domain


class CRTSHAdapter(SourceAdapter):
    """Query crt.sh JSON output for certificates and subdomain leads."""

    source_name = "crtsh"

    def lookup(self, domain: str, include_wildcard: bool = True, limit: int = 500) -> dict[str, Any]:
        normalized = normalize_domain(domain)
        if not is_domain(normalized):
            raise ValueError(f"not a valid domain: {domain}")
        query = f"%.{normalized}" if include_wildcard else normalized
        cache_key = f"lookup:{query}:{limit}"
        cached = self.cache_get(cache_key)
        if cached is not None:
            return cached

        url = f"https://crt.sh/?{urllib.parse.urlencode({'q': query, 'output': 'json'})}"
        result: dict[str, Any] = {
            "domain": normalized,
            "query": query,
            "url": url,
            "certificates": [],
            "subdomains": [],
            "metadata": {"source": self.source_name, "cached": False},
            "errors": [],
        }
        request = urllib.request.Request(url, headers={"User-Agent": "PHM-Scanner/0.1.5"})
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:  # noqa: S310 - fixed public CT endpoint
                text = response.read().decode("utf-8", errors="replace")
            rows = json.loads(text) if text.strip() else []
            if not isinstance(rows, list):
                rows = []
            seen_certs: set[str] = set()
            names: set[str] = set()
            for row in rows[:limit]:
                if not isinstance(row, dict):
                    continue
                cert_id = str(row.get("id") or row.get("min_cert_id") or "")
                dedupe_key = cert_id or f"{row.get('issuer_ca_id')}:{row.get('name_value')}:{row.get('not_before')}"
                if dedupe_key in seen_certs:
                    continue
                seen_certs.add(dedupe_key)
                cert = {
                    "id": cert_id,
                    "issuer_ca_id": row.get("issuer_ca_id"),
                    "issuer_name": row.get("issuer_name"),
                    "common_name": row.get("common_name"),
                    "name_value": row.get("name_value"),
                    "not_before": row.get("not_before"),
                    "not_after": row.get("not_after"),
                    "entry_timestamp": row.get("entry_timestamp"),
                }
                result["certificates"].append(cert)
                for name in self._extract_names(row.get("name_value", ""), normalized):
                    names.add(name)
                for name in self._extract_names(row.get("common_name", ""), normalized):
                    names.add(name)
            result["subdomains"] = sorted(names)
        except Exception as exc:  # noqa: BLE001 - external source should degrade gracefully
            result["errors"].append(f"CRT.SH lookup failed: {type(exc).__name__}: {exc}")

        self.cache_set(cache_key, result)
        return result

    @staticmethod
    def _extract_names(value: str, root_domain: str) -> list[str]:
        names: list[str] = []
        for raw in re.split(r"[\s,;]+", str(value)):
            name = raw.strip().lower().lstrip("*. ").rstrip(".")
            if not name or "@" in name:
                continue
            if name == root_domain or name.endswith(f".{root_domain}"):
                names.append(name)
        return names
