"""HTTP technology fingerprinting plugin."""

from __future__ import annotations

import re
import urllib.parse
import urllib.error
import urllib.parse
import urllib.request
from http.cookies import SimpleCookie
from typing import Any

from phm.core.models import Category, Detection, Evidence, Finding, Severity, TargetContext
from phm.core.plugin import BasePlugin
from phm.core.registry import registry
from phm.plugins.technical.dns_lookup import _normalize_domain

_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?!-)([A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,63}\.?$")

SIGNATURES: dict[str, list[re.Pattern[str]]] = {
    "WordPress": [re.compile(r"wp-content|wp-includes", re.I), re.compile(r"<meta name=['\"]generator['\"] content=['\"]WordPress", re.I)],
    "Drupal": [re.compile(r"Drupal.settings|/sites/default/", re.I)],
    "Joomla": [re.compile(r"/media/system/js/|content=['\"]Joomla!", re.I)],
    "React": [re.compile(r"data-reactroot|__REACT_DEVTOOLS_GLOBAL_HOOK__|react(?:\.production)?\.min\.js", re.I)],
    "Next.js": [re.compile(r"/_next/static/|__NEXT_DATA__", re.I)],
    "Angular": [re.compile(r"ng-version|ng-app|angular(?:\.min)?\.js", re.I)],
    "Vue.js": [re.compile(r"data-v-|vue(?:\.runtime)?(?:\.global)?(?:\.prod)?\.js", re.I)],
    "jQuery": [re.compile(r"jquery[-.]\d|jquery\.min\.js", re.I)],
    "Bootstrap": [re.compile(r"bootstrap(?:\.bundle)?(?:\.min)?\.(?:css|js)", re.I)],
    "Cloudflare": [re.compile(r"cloudflare", re.I)],
    "Google Analytics": [re.compile(r"googletagmanager\.com|google-analytics\.com|gtag\(", re.I)],
}

HEADER_HINTS = {
    "cf-ray": "Cloudflare",
    "x-vercel-id": "Vercel",
    "x-nextjs-cache": "Next.js",
}

SAFE_HEADER_VALUE_RE = re.compile(r"^[A-Za-z0-9 ._+:/()-]{1,80}$")
SAFE_POWERED_BY = {
    "php": "PHP",
    "express": "Express",
    "asp.net": "ASP.NET",
    "next.js": "Next.js",
}
SAFE_SERVER_NAMES = {
    "nginx": "nginx",
    "apache": "Apache",
    "cloudflare": "Cloudflare",
    "openresty": "OpenResty",
    "microsoft-iis": "Microsoft IIS",
    "iis": "Microsoft IIS",
    "envoy": "Envoy",
    "caddy": "Caddy",
}


@registry.register
class TechnologyFingerprintPlugin(BasePlugin):
    name = "technology_fingerprint"
    category = Category.TECHNICAL
    description = "Fingerprint web technologies from HTTP headers and public HTML signatures."
    passive = True

    def detect(self, target: TargetContext) -> Detection:
        value = target.value.strip()
        if value.startswith(("http://", "https://")):
            return Detection(True, 0.9, "URL target")
        domain = _normalize_domain(value)
        ok = bool(_DOMAIN_RE.match(domain))
        return Detection(ok, 0.75 if ok else 0.0, "domain-like web target" if ok else "not a web target")

    def collect(self, target: TargetContext) -> dict[str, Any]:
        value = target.value.strip()
        urls = [value] if value.startswith(("http://", "https://")) else [f"https://{_normalize_domain(value)}", f"http://{_normalize_domain(value)}"]
        timeout = float(target.options.get("timeout", 8.0))
        last_error = ""
        for url in urls:
            request = urllib.request.Request(url, headers={"User-Agent": "PHM-Scanner/0.1.5"})
            try:
                with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310 - analyst-provided target
                    body = response.read(300_000).decode("utf-8", errors="replace")
                    headers = {key.lower(): value for key, value in response.headers.items()}
                    final_url = response.geturl()
                    extras = self._collect_common_web_files(final_url, timeout)
                    links = sorted({urllib.parse.urljoin(final_url, href) for href in re.findall(r'''(?i)href\s*=\s*[\"']([^\"']+)''', body) if not href.startswith(("javascript:", "mailto:"))})[:100]
                    return {
                        "url": final_url,
                        "links": links,
                        "status": response.status,
                        "headers": headers,
                        "html_excerpt": body[:120_000],
                        "content_length_sampled": len(body),
                        **extras,
                    }
            except (urllib.error.URLError, TimeoutError, OSError) as exc:
                last_error = f"{url}: {exc}"
        raise RuntimeError(f"HTTP fingerprinting failed: {last_error}")

    def analyze(self, target: TargetContext, raw: dict[str, Any]) -> list[Finding]:
        headers = raw.get("headers", {})
        html = raw.get("html_excerpt", "")
        technologies: dict[str, set[str]] = {}

        server_header = headers.get("server", "")
        safe_server = self._safe_server_technology(server_header)
        if safe_server:
            technologies.setdefault(safe_server, set()).add("safe_server_header")

        powered_by = headers.get("x-powered-by", "")
        safe_powered = self._safe_powered_by(powered_by)
        if safe_powered:
            technologies.setdefault(safe_powered, set()).add("safe_x_powered_by_header")

        generator = headers.get("x-generator", "")
        if generator and SAFE_HEADER_VALUE_RE.match(generator):
            technologies.setdefault(generator.strip(), set()).add("safe_x_generator_header")

        for header, label in HEADER_HINTS.items():
            if headers.get(header):
                technologies.setdefault(label, set()).add(f"header:{header}")

        combined = "\n".join([html, "\n".join(f"{k}: {v}" for k, v in headers.items() if k != "server")])
        for tech, patterns in SIGNATURES.items():
            for pattern in patterns:
                if pattern.search(combined):
                    technologies.setdefault(tech, set()).add(f"signature:{pattern.pattern[:60]}")

        web_details = self._web_details(raw)
        evidence = [
            Evidence(source="http.status", value=raw.get("status")),
            Evidence(source="http.url", value=raw.get("url")),
            Evidence(source="http.links", value=raw.get("links", [])),
            Evidence(source="http.security_headers", value=web_details.get("security_headers")),
            Evidence(source="http.cookies", value=web_details.get("cookies")),
            Evidence(source="http.csp", value=web_details.get("csp")),
            Evidence(source="html.comments", value=web_details.get("comments")),
            Evidence(source="javascript.endpoints", value=web_details.get("js_endpoints")),
            Evidence(source="http.interesting_parameters", value=web_details.get("interesting_parameters")),
            Evidence(source="http.authentication_clues", value=web_details.get("authentication_clues")),
            Evidence(source="http.robots", value=raw.get("robots_txt", {}).get("summary")),
            Evidence(source="http.sitemap", value=raw.get("sitemap_xml", {}).get("summary")),
            Evidence(source="http.security_txt", value=raw.get("security_txt", {}).get("summary")),
        ]
        if server_header:
            evidence.append(Evidence(source="http.server_header", value=server_header, metadata={"interpreted_as_technology": bool(safe_server)}))
        for tech, reasons in sorted(technologies.items()):
            evidence.append(Evidence(source="technology", value={"name": tech, "reasons": sorted(reasons)}))

        return [
            Finding(
                title="Web technology fingerprint",
                description=f"Detected {len(technologies)} technology/header signal(s) from public HTTP response data.",
                category=self.category,
                plugin=self.name,
                confidence=0.78 if technologies else 0.5,
                severity=Severity.INFO,
                evidence=evidence,
                metadata={"technologies": sorted(technologies), "web_details": web_details},
            )
        ]

    def _collect_common_web_files(self, final_url: str, timeout: float) -> dict[str, Any]:
        parsed = urllib.parse.urlparse(final_url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        return {
            "robots_txt": self._fetch_small(f"{base}/robots.txt", timeout, "robots"),
            "sitemap_xml": self._fetch_small(f"{base}/sitemap.xml", timeout, "sitemap"),
            "security_txt": self._fetch_small(f"{base}/.well-known/security.txt", timeout, "security.txt"),
        }

    @staticmethod
    def _fetch_small(url: str, timeout: float, kind: str) -> dict[str, Any]:
        try:
            request = urllib.request.Request(url, headers={"User-Agent": "PHM-Scanner/0.1.5"})
            with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310 - target-controlled public URL
                text = response.read(80_000).decode("utf-8", errors="replace")
            lines = [line.strip() for line in text.splitlines() if line.strip() and not line.lstrip().startswith("#")]
            interesting = [line for line in lines if any(token in line.lower() for token in ["admin", "api", "login", "private", "backup", "dev", "test", "disallow", "allow", "sitemap", "contact", "policy"])]
            return {"url": url, "status": response.status, "present": True, "summary": {"kind": kind, "lines": len(lines), "interesting": interesting[:20]}, "excerpt": text[:4000]}
        except Exception:
            return {"url": url, "present": False, "summary": {"kind": kind, "lines": 0, "interesting": []}}

    @staticmethod
    def _web_details(raw: dict[str, Any]) -> dict[str, Any]:
        headers = raw.get("headers", {})
        html = raw.get("html_excerpt", "")
        comments = re.findall(r"<!--(.*?)-->", html, flags=re.S)[:20]
        js_endpoints = sorted(set(re.findall(r"[\"']((?:/[A-Za-z0-9_./{}:-]+){1,}(?:\?[A-Za-z0-9_=&{}.-]+)?)['\"]", html)))[:80]
        parameters = sorted(set(re.findall(r"[?&]([A-Za-z0-9_]{2,40})=", html)))[:80]
        auth_clues = sorted(set(re.findall(r"(?i)\b(login|logout|auth|oauth|saml|jwt|token|session|password|signin|signup)\b", html)))[:30]
        security_headers = {
            "content-security-policy": bool(headers.get("content-security-policy")),
            "strict-transport-security": bool(headers.get("strict-transport-security")),
            "x-frame-options": bool(headers.get("x-frame-options")),
            "x-content-type-options": bool(headers.get("x-content-type-options")),
            "referrer-policy": bool(headers.get("referrer-policy")),
            "permissions-policy": bool(headers.get("permissions-policy")),
        }
        cookie_headers = [value for key, value in headers.items() if key.lower() == "set-cookie"]
        cookies = []
        for header in cookie_headers:
            jar = SimpleCookie()
            try:
                jar.load(header)
                for name, morsel in jar.items():
                    cookies.append({"name": name, "secure": bool(morsel["secure"]), "httponly": bool(morsel["httponly"]), "samesite": morsel["samesite"] or ""})
            except Exception:
                continue
        return {
            "security_headers": security_headers,
            "cookies": cookies,
            "csp": headers.get("content-security-policy", "")[:500],
            "comments": [comment.strip()[:200] for comment in comments if comment.strip()],
            "js_endpoints": js_endpoints,
            "interesting_parameters": parameters,
            "authentication_clues": auth_clues,
        }

    @staticmethod
    def _safe_server_technology(value: str) -> str:
        if not value or not SAFE_HEADER_VALUE_RE.match(value):
            return ""
        lowered = value.lower()
        for token, label in SAFE_SERVER_NAMES.items():
            if token in lowered:
                return label
        return ""

    @staticmethod
    def _safe_powered_by(value: str) -> str:
        if not value or not SAFE_HEADER_VALUE_RE.match(value):
            return ""
        lowered = value.lower()
        for token, label in SAFE_POWERED_BY.items():
            if token in lowered:
                return label
        return ""

    def report(self, target: TargetContext, raw: dict[str, Any], findings: list[Finding], errors: list[str] | None = None):
        return self._result(target, raw, findings, errors)
