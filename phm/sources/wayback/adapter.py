"""Wayback Machine source adapter."""

from __future__ import annotations

import json
import urllib.parse
import urllib.request
from typing import Any

from phm.sources.base import SourceAdapter
from phm.sources.common import is_domain, normalize_domain


class WaybackAdapter(SourceAdapter):
    """Query Internet Archive CDX and availability APIs."""

    source_name = "wayback"

    def lookup(self, target: str, limit: int = 50) -> dict[str, Any]:
        domain = normalize_domain(target)
        if not is_domain(domain):
            raise ValueError(f"not a valid domain: {target}")
        cache_key = f"lookup:{domain}:{limit}"
        cached = self.cache_get(cache_key)
        if cached is not None:
            return cached

        cdx_params = {
            "url": f"{domain}/*",
            "output": "json",
            "fl": "timestamp,original,statuscode,mimetype,digest",
            "collapse": "digest",
            "limit": str(limit),
            "filter": "statuscode:200",
        }
        cdx_url = f"https://web.archive.org/cdx?{urllib.parse.urlencode(cdx_params)}"
        availability_url = f"https://archive.org/wayback/available?{urllib.parse.urlencode({'url': domain})}"
        result: dict[str, Any] = {
            "domain": domain,
            "cdx_url": cdx_url,
            "availability_url": availability_url,
            "snapshots": [],
            "closest": {},
            "timeline": {},
            "metadata": {"source": self.source_name, "cached": False},
            "errors": [],
        }
        try:
            result["closest"] = self._get_json(availability_url).get("archived_snapshots", {}).get("closest", {})
        except Exception as exc:  # noqa: BLE001
            result["errors"].append(f"Wayback availability failed: {type(exc).__name__}: {exc}")
        try:
            rows = self._get_json(cdx_url)
            if isinstance(rows, list) and rows:
                header = rows[0]
                for row in rows[1:]:
                    if not isinstance(row, list):
                        continue
                    snapshot = {header[index]: row[index] if index < len(row) else "" for index in range(len(header))}
                    snapshot["wayback_url"] = f"https://web.archive.org/web/{snapshot.get('timestamp', '')}/{snapshot.get('original', '')}"
                    result["snapshots"].append(snapshot)
            result["timeline"] = self._timeline(result["snapshots"])
        except Exception as exc:  # noqa: BLE001
            result["errors"].append(f"Wayback CDX failed: {type(exc).__name__}: {exc}")

        self.cache_set(cache_key, result)
        return result

    def _get_json(self, url: str) -> Any:
        request = urllib.request.Request(url, headers={"User-Agent": "PHM-Scanner/0.1.4"})
        with urllib.request.urlopen(request, timeout=self.timeout) as response:  # noqa: S310 - fixed public archive endpoints
            return json.loads(response.read().decode("utf-8", errors="replace"))

    @staticmethod
    def _timeline(snapshots: list[dict[str, Any]]) -> dict[str, int]:
        counts: dict[str, int] = {}
        for snapshot in snapshots:
            timestamp = str(snapshot.get("timestamp", ""))
            if len(timestamp) >= 4:
                year = timestamp[:4]
                counts[year] = counts.get(year, 0) + 1
        return dict(sorted(counts.items()))
