"""Public geolocation enrichment for place clues and coordinates."""
from __future__ import annotations
import json, re, urllib.parse, urllib.request
from phm.core.models import Category, Detection, Evidence, Finding, Severity, TargetContext
from phm.core.plugin import BasePlugin
from phm.core.registry import registry

_COORD = re.compile(r"(-?\d{1,3}(?:\.\d+)?)\s*[,; ]\s*(-?\d{1,3}(?:\.\d+)?)")

@registry.register
class GeolocationLookupPlugin(BasePlugin):
    name = "geolocation_lookup"
    category = Category.GEOSPATIAL
    module = "osint"
    capability = "public_place_geolocation"
    consumes = ("coordinates", "text", "file")
    produces = ("coordinates", "location")
    description = "Resolves coordinates and public place clues using OpenStreetMap Nominatim."
    passive = True
    local_first = True
    network_required = False
    external_tool_required = False

    def detect(self, target: TargetContext) -> Detection:
        value = target.value.strip()
        match = _COORD.fullmatch(value)
        if match:
            lat, lon = map(float, match.groups())
            return Detection(-90 <= lat <= 90 and -180 <= lon <= 180, .99, "latitude/longitude pair")
        return Detection(bool(value) and target.category == Category.GEOSPATIAL, .55, "geospatial investigation requested")

    def collect(self, target: TargetContext) -> dict:
        value = target.value.strip()
        match = _COORD.fullmatch(value)
        if match:
            lat, lon = map(float, match.groups())
            return {"query": value, "coordinates": {"latitude": lat, "longitude": lon}, "reverse": self._request(f"https://nominatim.openstreetmap.org/reverse?format=jsonv2&lat={lat}&lon={lon}&zoom=18")}
        query = urllib.parse.quote(value)
        return {"query": value, "candidates": self._request(f"https://nominatim.openstreetmap.org/search?format=jsonv2&limit=5&q={query}")}

    def _request(self, url):
        try:
            request = urllib.request.Request(url, headers={"User-Agent": "PHM-Scanner/0.1.4 (public OSINT research)"})
            with urllib.request.urlopen(request, timeout=8) as response:
                return json.loads(response.read().decode("utf-8"))
        except Exception as exc:  # public source failure must not stop an investigation
            return {"error": str(exc)}

    def analyze(self, target, raw):
        evidence = [Evidence(source="geolocation.query", value=raw.get("query"))]
        if raw.get("coordinates"): evidence.append(Evidence(source="geolocation.coordinates", value=raw["coordinates"]))
        if raw.get("reverse") and "error" not in raw["reverse"]: evidence.append(Evidence(source="geolocation.reverse", value={k: raw["reverse"].get(k) for k in ("display_name", "address", "type") if raw["reverse"].get(k)}))
        candidates = raw.get("candidates", [])
        for candidate in candidates[:5]: evidence.append(Evidence(source="geolocation.candidate", value={k: candidate.get(k) for k in ("display_name", "lat", "lon", "type")}))
        count = bool(raw.get("coordinates") or candidates)
        return [Finding(title="Public place geolocation", description="Resolved coordinates or public map candidates for the supplied clue." if count else "No public map result was returned; refine the place clue.", category=self.category, plugin=self.name, confidence=.9 if count else .3, severity=Severity.INFO, evidence=evidence, metadata={"map_links": [f"https://www.openstreetmap.org/?mlat={c.get('lat')}&mlon={c.get('lon')}" for c in candidates[:5] if c.get('lat') and c.get('lon')]})]

    def report(self, target, raw, findings, errors=None): return self._result(target, raw, findings, errors)
