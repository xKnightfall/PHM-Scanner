"""GitHub source adapter."""

from __future__ import annotations

import base64
import json
import math
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any

from phm.sources.base import SourceAdapter

GITHUB_API_BASE = "https://api.github.com"
USER_AGENT = "PHM-Scanner/0.1.4"


class GitHubAPIError(RuntimeError):
    """Raised for GitHub API failures."""

    def __init__(self, message: str, status: int | None = None, rate: dict[str, str] | None = None) -> None:
        super().__init__(message)
        self.status = status
        self.rate = rate or {}


@dataclass(slots=True)
class GitHubResponse:
    data: Any
    rate: dict[str, str]
    status: int


def github_headers() -> dict[str, str]:
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": USER_AGENT,
    }
    token = os.getenv("GITHUB_TOKEN") or os.getenv("GH_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def _rate_from_headers(headers) -> dict[str, str]:
    return {
        "limit": headers.get("X-RateLimit-Limit", ""),
        "remaining": headers.get("X-RateLimit-Remaining", ""),
        "reset": headers.get("X-RateLimit-Reset", ""),
        "resource": headers.get("X-RateLimit-Resource", ""),
    }


def github_get(path: str, params: dict[str, Any] | None = None, timeout: float = 10.0) -> GitHubResponse:
    """GET a GitHub API path and return JSON data plus rate-limit metadata."""

    if path.startswith("https://"):
        url = path
    else:
        url = f"{GITHUB_API_BASE}{path}"
    if params:
        url = f"{url}?{urllib.parse.urlencode(params, doseq=True)}"
    request = urllib.request.Request(url, headers=github_headers())
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310 - fixed GitHub API/public URLs
            body = response.read().decode("utf-8", errors="replace")
            data = json.loads(body) if body else {}
            return GitHubResponse(data=data, rate=_rate_from_headers(response.headers), status=response.status)
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        message = body
        try:
            parsed = json.loads(body)
            message = parsed.get("message", body)
        except json.JSONDecodeError:
            pass
        raise GitHubAPIError(message, status=exc.code, rate=_rate_from_headers(exc.headers)) from exc
    except urllib.error.URLError as exc:
        raise GitHubAPIError(f"GitHub API unavailable: {exc}") from exc


def parse_repo_slug(value: str) -> tuple[str, str] | None:
    """Parse owner/repo from common GitHub URL or slug forms."""

    value = value.strip().rstrip("/")
    match = re.search(r"github\.com[:/]([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+?)(?:\.git)?(?:/|$)", value)
    if match:
        return match.group(1), match.group(2)
    match = re.fullmatch(r"([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)", value)
    if match:
        return match.group(1), match.group(2)
    return None


def parse_github_user(value: str) -> str | None:
    value = value.strip().rstrip("/")
    match = re.search(r"github\.com/([A-Za-z0-9-]+)(?:/)?$", value)
    if match:
        return match.group(1)
    if re.fullmatch(r"[A-Za-z0-9-]{1,39}", value):
        return value
    return None


SECRET_PATTERNS: dict[str, re.Pattern[str]] = {
    "aws_access_key_id": re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    "aws_secret_assignment": re.compile(r"(?i)\baws(.{0,20})?(?:secret|access).{0,20}?\b[:=]\s*['\"]?([A-Za-z0-9/+=]{32,})"),
    "github_token": re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{36,255}\b"),
    "gitlab_token": re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}\b"),
    "slack_token": re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
    "stripe_key": re.compile(r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{20,}\b"),
    "sendgrid_key": re.compile(r"\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\b"),
    "google_api_key": re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
    "twilio_sid": re.compile(r"\bAC[a-fA-F0-9]{32}\b"),
    "jwt": re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
    "private_key_header": re.compile(r"-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP )?PRIVATE KEY-----"),
    "generic_secret_assignment": re.compile(r"(?i)\b(?:api[_-]?key|secret|token|password|passwd|client[_-]?secret|auth[_-]?token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_./+=-]{20,})"),
}


def redact_secret(value: str) -> str:
    if len(value) <= 8:
        return "<redacted>"
    return f"{value[:4]}...{value[-4:]}"


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    frequencies = {ch: value.count(ch) for ch in set(value)}
    return -sum((count / len(value)) * math.log2(count / len(value)) for count in frequencies.values())


def scan_text_for_secrets(text: str, file_path: str, max_findings: int = 20) -> list[dict[str, Any]]:
    """Return redacted potential secret findings from text."""

    findings: list[dict[str, Any]] = []
    lines = text.splitlines()
    for line_number, line in enumerate(lines, start=1):
        for secret_type, pattern in SECRET_PATTERNS.items():
            for match in pattern.finditer(line):
                secret_value = next((group for group in reversed(match.groups()) if group), match.group(0)) if match.groups() else match.group(0)
                entropy = shannon_entropy(secret_value)
                if secret_type == "generic_secret_assignment" and entropy < 3.2:
                    continue
                findings.append(
                    {
                        "type": secret_type,
                        "file": file_path,
                        "line": line_number,
                        "redacted_value": redact_secret(secret_value),
                        "entropy": round(entropy, 3),
                    }
                )
                if len(findings) >= max_findings:
                    return findings
    return findings


def decode_blob_content(blob: dict[str, Any]) -> str:
    if blob.get("encoding") != "base64" or not blob.get("content"):
        return ""
    return base64.b64decode(blob["content"]).decode("utf-8", errors="replace")


class GitHubAdapter(SourceAdapter):
    """GitHub REST API adapter.

    The adapter centralizes authentication, rate metadata, caching, parsing, and
    provider-specific errors. Plugins consume normalized dictionaries rather than
    building URLs directly.
    """

    source_name = "github"

    def get(self, path: str, params: dict[str, Any] | None = None) -> GitHubResponse:
        # Low-level method intentionally does not cache because callers may need
        # response metadata. Higher-level methods below cache normalized output.
        return github_get(path, params=params, timeout=self.timeout)

    def user(self, username: str) -> dict[str, Any]:
        cache_key = f"user:{username}"
        cached = self.cache_get(cache_key)
        if cached is not None:
            return cached
        try:
            profile_response = self.get(f"/users/{username}")
        except GitHubAPIError as exc:
            if exc.status == 404:
                result = {"username": username, "exists": False, "message": "GitHub user was not found", "rate": {"profile": exc.rate}, "metadata": {"source": self.source_name, "cached": False}}
                self.cache_set(cache_key, result)
                return result
            raise
        repos_response = self.get(f"/users/{username}/repos", {"per_page": 20, "sort": "updated", "type": "owner"})
        repos = repos_response.data if isinstance(repos_response.data, list) else []
        result = {
            "username": username,
            "exists": True,
            "profile": profile_response.data,
            "recent_repositories": [self._repo_summary(repo) for repo in repos],
            "rate": {"profile": profile_response.rate, "repos": repos_response.rate},
            "metadata": {"source": self.source_name, "cached": False},
        }
        self.cache_set(cache_key, result)
        return result

    def organization(self, org: str) -> dict[str, Any]:
        cache_key = f"org:{org}"
        cached = self.cache_get(cache_key)
        if cached is not None:
            return cached
        try:
            org_response = self.get(f"/orgs/{org}")
        except GitHubAPIError as exc:
            if exc.status == 404:
                result = {"org": org, "exists": False, "message": "GitHub organization was not found", "rate": {"org": exc.rate}, "metadata": {"source": self.source_name, "cached": False}}
                self.cache_set(cache_key, result)
                return result
            raise
        repos_response = self.get(f"/orgs/{org}/repos", {"per_page": 30, "sort": "updated", "type": "public"})
        repos = repos_response.data if isinstance(repos_response.data, list) else []
        members: list[dict[str, Any]] = []
        try:
            members_response = self.get(f"/orgs/{org}/public_members", {"per_page": 20})
            if isinstance(members_response.data, list):
                members = [{"login": item.get("login"), "html_url": item.get("html_url")} for item in members_response.data]
        except Exception:
            members = []
        result = {
            "org": org,
            "exists": True,
            "profile": org_response.data,
            "repositories": [self._repo_summary(repo, include_topics=True) for repo in repos],
            "public_members_sample": members,
            "rate": {"org": org_response.rate, "repos": repos_response.rate},
            "metadata": {"source": self.source_name, "cached": False},
        }
        self.cache_set(cache_key, result)
        return result

    def search(self, query: str, per_page: int = 10, include_code: bool = True) -> dict[str, Any]:
        cache_key = f"search:{query}:{per_page}:{include_code}:{bool(os.getenv('GITHUB_TOKEN') or os.getenv('GH_TOKEN'))}"
        cached = self.cache_get(cache_key)
        if cached is not None:
            return cached
        repository_query = f'"{query}" in:name,description,readme'
        user_query = f'"{query}" in:login,fullname,email'
        repository_response = self.get("/search/repositories", {"q": repository_query, "per_page": per_page, "sort": "updated"})
        user_response = self.get("/search/users", {"q": user_query, "per_page": min(per_page, 10)})

        code_items: list[dict[str, Any]] = []
        code_error = ""
        if include_code and (os.getenv("GITHUB_TOKEN") or os.getenv("GH_TOKEN")):
            try:
                code_response = self.get("/search/code", {"q": f'"{query}"', "per_page": min(per_page, 10)})
                raw_code_items = code_response.data.get("items", []) if isinstance(code_response.data, dict) else []
                code_items = [
                    {
                        "name": item.get("name"),
                        "path": item.get("path"),
                        "html_url": item.get("html_url"),
                        "repository": (item.get("repository") or {}).get("full_name"),
                    }
                    for item in raw_code_items
                ]
            except GitHubAPIError as exc:
                code_error = f"code search failed: {exc}"
        elif include_code:
            code_error = "code search skipped: set GITHUB_TOKEN or GH_TOKEN to enable authenticated GitHub code search"

        result = {
            "query": query,
            "repository_search": repository_response.data,
            "user_search": user_response.data,
            "code_items": code_items,
            "code_error": code_error,
            "rate": {"repositories": repository_response.rate, "users": user_response.rate},
            "metadata": {"source": self.source_name, "cached": False},
        }
        self.cache_set(cache_key, result)
        return result

    def repository(self, owner: str, repo: str, max_secret_files: int = 25, max_blob_size: int = 180_000) -> dict[str, Any]:
        from pathlib import PurePosixPath

        cache_key = f"repo:{owner}/{repo}:{max_secret_files}:{max_blob_size}"
        cached = self.cache_get(cache_key)
        if cached is not None:
            return cached
        try:
            repo_response = self.get(f"/repos/{owner}/{repo}")
        except GitHubAPIError as exc:
            if exc.status == 404:
                result = {"owner": owner, "repo": repo, "exists": False, "message": "GitHub repository was not found", "rate": {"repo": exc.rate}, "metadata": {"source": self.source_name, "cached": False}}
                self.cache_set(cache_key, result)
                return result
            raise
        languages_response = self.get(f"/repos/{owner}/{repo}/languages")
        commits_response = self.get(f"/repos/{owner}/{repo}/commits", {"per_page": 10})
        contributors_data: list[dict[str, Any]] = []
        contributors_rate: dict[str, str] = {}
        try:
            contributors_response = self.get(f"/repos/{owner}/{repo}/contributors", {"per_page": 20, "anon": "true"})
            contributors_data = contributors_response.data if isinstance(contributors_response.data, list) else []
            contributors_rate = contributors_response.rate
        except Exception:
            contributors_data = []
        topics: list[str] = []
        try:
            topics_response = self.get(f"/repos/{owner}/{repo}/topics")
            topics = topics_response.data.get("names", []) if isinstance(topics_response.data, dict) else []
        except Exception:
            topics = []
        releases: list[dict[str, Any]] = []
        try:
            releases_response = self.get(f"/repos/{owner}/{repo}/releases", {"per_page": 5})
            raw_releases = releases_response.data if isinstance(releases_response.data, list) else []
            releases = [{"name": item.get("name") or item.get("tag_name"), "tag_name": item.get("tag_name"), "published_at": item.get("published_at"), "prerelease": item.get("prerelease")} for item in raw_releases]
        except Exception:
            releases = []

        repo_data = repo_response.data
        default_branch = repo_data.get("default_branch", "main")
        tree_items: list[dict[str, Any]] = []
        secret_findings: list[dict[str, Any]] = []
        tree_error = ""
        try:
            tree_response = self.get(f"/repos/{owner}/{repo}/git/trees/{default_branch}", {"recursive": "1"})
            tree_items = tree_response.data.get("tree", []) if isinstance(tree_response.data, dict) else []
            scanned = 0
            for item in tree_items:
                if scanned >= max_secret_files:
                    break
                if item.get("type") != "blob":
                    continue
                path = item.get("path", "")
                size = int(item.get("size") or 0)
                suffix = PurePosixPath(path).suffix
                name = PurePosixPath(path).name
                if size > max_blob_size:
                    continue
                if suffix not in _TEXT_EXTENSIONS and name not in {"Dockerfile", ".env", ".npmrc", ".pypirc"}:
                    continue
                blob_response = self.get(item.get("url", ""))
                text = decode_blob_content(blob_response.data if isinstance(blob_response.data, dict) else {})
                if not text:
                    continue
                scanned += 1
                secret_findings.extend(scan_text_for_secrets(text, path, max_findings=20 - len(secret_findings)))
                if len(secret_findings) >= 20:
                    break
        except Exception as exc:  # noqa: BLE001
            tree_error = f"{type(exc).__name__}: {exc}"

        dependency_files = interesting_project_files(tree_items)
        activity_summary = {
            "pushed_at": repo_data.get("pushed_at"),
            "updated_at": repo_data.get("updated_at"),
            "recent_commit_count_sampled": len(commits_response.data) if isinstance(commits_response.data, list) else 0,
            "contributors_sampled": len(contributors_data),
            "open_issues_count": repo_data.get("open_issues_count"),
        }
        health = {
            "archived": repo_data.get("archived"),
            "disabled": repo_data.get("disabled"),
            "has_issues": repo_data.get("has_issues"),
            "has_wiki": repo_data.get("has_wiki"),
            "fork": repo_data.get("fork"),
        }
        result = {
            "owner": owner,
            "repo": repo,
            "exists": True,
            "repository": repo_data,
            "languages": languages_response.data,
            "topics": topics,
            "releases": releases,
            "activity_summary": activity_summary,
            "repository_health": health,
            "dependency_files": dependency_files,
            "recent_commits": commits_response.data if isinstance(commits_response.data, list) else [],
            "contributors_sample": [
                {"login": item.get("login") or item.get("name"), "html_url": item.get("html_url"), "contributions": item.get("contributions"), "type": item.get("type")}
                for item in contributors_data[:20]
            ],
            "tree_sample_count": len(tree_items),
            "technology_hints": technology_hints(tree_items),
            "potential_secret_findings": secret_findings,
            "secret_scan_note": "Potential secrets are redacted and unverified. Validate authorization and rotate exposed credentials if confirmed.",
            "tree_error": tree_error,
            "rate": {"repo": repo_response.rate, "languages": languages_response.rate, "commits": commits_response.rate, "contributors": contributors_rate},
            "metadata": {"source": self.source_name, "cached": False},
        }
        self.cache_set(cache_key, result)
        return result

    @staticmethod
    def _repo_summary(repo: dict[str, Any], include_topics: bool = False) -> dict[str, Any]:
        summary = {
            "full_name": repo.get("full_name"),
            "html_url": repo.get("html_url"),
            "description": repo.get("description"),
            "language": repo.get("language"),
            "stargazers_count": repo.get("stargazers_count"),
            "forks_count": repo.get("forks_count"),
            "fork": repo.get("fork"),
            "archived": repo.get("archived"),
            "pushed_at": repo.get("pushed_at"),
            "updated_at": repo.get("updated_at"),
        }
        if include_topics:
            summary["topics"] = repo.get("topics", [])
        return summary


_TEXT_EXTENSIONS = {
    ".py",
    ".js",
    ".ts",
    ".jsx",
    ".tsx",
    ".java",
    ".go",
    ".rb",
    ".php",
    ".cs",
    ".c",
    ".cpp",
    ".h",
    ".rs",
    ".swift",
    ".kt",
    ".sh",
    ".ps1",
    ".yml",
    ".yaml",
    ".json",
    ".xml",
    ".toml",
    ".ini",
    ".cfg",
    ".env",
    ".md",
    ".txt",
    ".conf",
}

TECH_FILE_HINTS = {
    "package.json": "Node.js / JavaScript",
    "requirements.txt": "Python",
    "pyproject.toml": "Python",
    "poetry.lock": "Python / Poetry",
    "Pipfile": "Python / Pipenv",
    "go.mod": "Go",
    "Cargo.toml": "Rust",
    "pom.xml": "Java / Maven",
    "build.gradle": "Java/Kotlin / Gradle",
    "Gemfile": "Ruby",
    "composer.json": "PHP / Composer",
    "Dockerfile": "Docker",
    "docker-compose.yml": "Docker Compose",
    "docker-compose.yaml": "Docker Compose",
    "terraform.tf": "Terraform",
    "main.tf": "Terraform",
    "variables.tf": "Terraform",
    "ansible.cfg": "Ansible",
    "playbook.yml": "Ansible",
    "playbook.yaml": "Ansible",
    "Chart.yaml": "Helm / Kubernetes",
    "kustomization.yaml": "Kustomize / Kubernetes",
    "serverless.yml": "Serverless Framework",
    "template.yaml": "AWS SAM / CloudFormation",
    "cloudbuild.yaml": "Google Cloud Build",
    "azure-pipelines.yml": "Azure Pipelines",
}


def interesting_project_files(tree_items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    names = {
        "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
        "requirements.txt", "pyproject.toml", "poetry.lock", "Pipfile", "Pipfile.lock",
        "go.mod", "go.sum", "Cargo.toml", "Cargo.lock", "pom.xml", "build.gradle",
        "Gemfile", "composer.json", "Dockerfile", "docker-compose.yml", "docker-compose.yaml",
        "terraform.tf", "main.tf", "variables.tf", "Chart.yaml", "kustomization.yaml",
        ".github/workflows", ".gitlab-ci.yml", "Jenkinsfile",
    }
    output: list[dict[str, Any]] = []
    for item in tree_items:
        path = item.get("path", "")
        base = path.rsplit("/", 1)[-1]
        if base in names or any(marker in path for marker in [".github/workflows", "k8s", "kubernetes", "helm", "terraform"]):
            output.append({"path": path, "size": item.get("size"), "type": item.get("type")})
        if len(output) >= 80:
            break
    return output


def technology_hints(tree_items: list[dict[str, Any]]) -> list[str]:
    from pathlib import PurePosixPath

    hints: set[str] = set()
    for item in tree_items:
        path = PurePosixPath(item.get("path", ""))
        name = path.name
        if name in TECH_FILE_HINTS:
            hints.add(TECH_FILE_HINTS[name])
        path_text = str(path)
        if path.suffix == ".tf":
            hints.add("Terraform")
        if path.suffix in {".tfvars"}:
            hints.add("Terraform")
        if ".github/workflows" in path_text:
            hints.add("GitHub Actions")
        if "k8s" in path.parts or "kubernetes" in path.parts or path_text.endswith(("deployment.yaml", "service.yaml", "ingress.yaml")):
            hints.add("Kubernetes")
        if "ansible" in path.parts or path_text.endswith(("playbook.yml", "playbook.yaml")):
            hints.add("Ansible")
        if "cloudformation" in path.parts or path_text.endswith(("cloudformation.yml", "cloudformation.yaml")):
            hints.add("AWS CloudFormation")
        if ".gitlab-ci.yml" == name:
            hints.add("GitLab CI")
    return sorted(hints)
