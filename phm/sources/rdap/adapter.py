"""RDAP source adapter.

RDAP is a structured, free supplement/replacement for traditional WHOIS. This
adapter uses rdap.org's bootstrap service for domain and IP lookups.
"""

from __future__ import annotations

import ipaddress
import json
import urllib.error
import urllib.request
from typing import Any

from phm.sources.base import SourceAdapter
from phm.sources.common import is_domain, normalize_domain


class RDAPAdapter(SourceAdapter):
    """Structured RDAP lookup through rdap.org."""

    source_name = "rdap"

    def lookup(self, target: str) -> dict[str, Any]:
        normalized = target.strip()
        endpoint_type = "domain"
        try:
            ip = ipaddress.ip_address(normalized.strip("[]"))
            normalized = str(ip)
            endpoint_type = "ip"
        except ValueError:
            normalized = normalize_domain(normalized)
            if not is_domain(normalized):
                raise ValueError(f"not a valid domain or IP target: {target}")

        cache_key = f"lookup:{endpoint_type}:{normalized}"
        cached = self.cache_get(cache_key)
        if cached is not None:
            return cached

        url = f"https://rdap.org/{endpoint_type}/{normalized}"
        result: dict[str, Any] = {
            "target": normalized,
            "type": endpoint_type,
            "url": url,
            "data": {},
            "summary": {},
            "metadata": {"source": self.source_name, "cached": False},
            "errors": [],
        }
        request = urllib.request.Request(url, headers={"User-Agent": "PHM-Scanner/0.1.5"})
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:  # noqa: S310 - fixed public RDAP endpoint
                data = json.loads(response.read().decode("utf-8", errors="replace"))
                result["data"] = data
                result["summary"] = self._summarize(data, endpoint_type)
        except urllib.error.HTTPError as exc:
            result["errors"].append(f"HTTP {exc.code}: {exc.reason}")
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError) as exc:
            result["errors"].append(f"RDAP lookup failed: {type(exc).__name__}: {exc}")

        self.cache_set(cache_key, result)
        return result

    @staticmethod
    def _summarize(data: dict[str, Any], endpoint_type: str) -> dict[str, Any]:
        events = {event.get("eventAction", ""): event.get("eventDate") for event in data.get("events", []) if isinstance(event, dict)}
        nameservers = [ns.get("ldhName") for ns in data.get("nameservers", []) if isinstance(ns, dict) and ns.get("ldhName")]
        entities = []
        for entity in data.get("entities", []) if isinstance(data.get("entities"), list) else []:
            if not isinstance(entity, dict):
                continue
            roles = entity.get("roles", [])
            handle = entity.get("handle")
            name = ""
            for vcard in entity.get("vcardArray", [None, []])[1] if isinstance(entity.get("vcardArray"), list) and len(entity.get("vcardArray")) > 1 else []:
                if isinstance(vcard, list) and vcard and vcard[0] in {"fn", "org"}:
                    name = vcard[3] if len(vcard) > 3 else name
                    break
            entities.append({"handle": handle, "roles": roles, "name": name})
        return {
            "object_class_name": data.get("objectClassName"),
            "handle": data.get("handle"),
            "ldh_name": data.get("ldhName"),
            "status": data.get("status", []),
            "events": events,
            "nameservers": nameservers,
            "entities": entities[:20],
            "network": {
                "name": data.get("name"),
                "country": data.get("country"),
                "start_address": data.get("startAddress"),
                "end_address": data.get("endAddress"),
                "ip_version": data.get("ipVersion"),
                "type": data.get("type"),
            }
            if endpoint_type == "ip"
            else {},
        }
