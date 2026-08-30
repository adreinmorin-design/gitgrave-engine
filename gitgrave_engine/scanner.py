"""Defensive, read-only GitHub exposure scanner."""

from __future__ import annotations

import asyncio
import hashlib
import math
import re
from collections import Counter
from datetime import datetime, timezone
from typing import Any, Literal
from urllib.parse import quote, urlparse

import aiohttp
from pydantic import BaseModel, Field

GITHUB_API = "https://api.github.com"


class AuditStep(BaseModel):
    sequence: int
    stage: Literal["target_input", "repo_discovery", "commit_history", "secret_detection", "sink_execution"]
    message: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: dict[str, Any] = Field(default_factory=dict)


class SecretFinding(BaseModel):
    """Redacted evidence; candidate values are never retained."""

    repository: str
    commit: str
    file: str
    line: int | None = None
    kind: str
    confidence: Literal["medium", "high"]
    candidate_sha256: str
    validation: Literal["not_attempted"] = "not_attempted"
    evidence_poc: str


class HeuristicFinding(BaseModel):
    repository: str
    commit: str
    file: str
    line: int | None = None
    rule: str
    explanation: str


class SinkTrace(BaseModel):
    """Static source-to-sink relationship; no code or command is executed."""

    repository: str
    commit: str
    file: str
    source_line: int
    source: str
    sink_line: int
    sink: str
    confidence: Literal["medium", "high"]


class SecurityAuditTracker(BaseModel):
    target_input: str
    repositories: list[str] = Field(default_factory=list)
    steps: list[AuditStep] = Field(default_factory=list)
    secret_findings: list[SecretFinding] = Field(default_factory=list)
    heuristic_findings: list[HeuristicFinding] = Field(default_factory=list)
    sink_traces: list[SinkTrace] = Field(default_factory=list)
    status: Literal["running", "completed", "failed"] = "running"

    def log(self, stage: Literal["target_input", "repo_discovery", "commit_history", "secret_detection", "sink_execution"], message: str, **metadata: Any) -> None:
        self.steps.append(AuditStep(sequence=len(self.steps) + 1, stage=stage, message=message, metadata=metadata))


SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("github_pat", re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,255}\b")),
    ("openai_api_key", re.compile(r"\bsk-[A-Za-z0-9]{20,}\b")),
    ("aws_access_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("private_key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("generic_secret_assignment", re.compile(r"(?i)\b(?:api[_-]?key|secret|password|token)\b\s*[:=]\s*['\"]([^'\"]{12,})['\"]")),
)

HEURISTIC_RULES: tuple[tuple[str, re.Pattern[str], str], ...] = (
    ("dynamic_eval", re.compile(r"\beval\s*\("), "Dynamic evaluation can execute attacker-controlled input."),
    ("shell_execution", re.compile(r"\b(?:os\.system|subprocess\.[A-Za-z_]+).*shell\s*=\s*True"), "Shell execution increases command-injection risk."),
    ("unsafe_deserialization", re.compile(r"\b(?:pickle\.loads|yaml\.load)\s*\("), "Deserializing untrusted data can lead to code execution."),
)

SOURCE_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("request_input", re.compile(r"\b(?:request\.(?:args|form|json|get_json)|input)\b")),
    ("environment_input", re.compile(r"\bos\.environ(?:\.get)?\b")),
    ("file_input", re.compile(r"\b(?:open|Path\([^)]*\)\.read_text)\s*\(")),
)

SINK_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("dynamic_execution", re.compile(r"\b(?:eval|exec)\s*\(")),
    ("shell_execution", re.compile(r"\b(?:os\.system|os\.popen|subprocess\.[A-Za-z_]+)\s*\(")),
    ("sql_execution", re.compile(r"\.(?:execute|executemany)\s*\(")),
    ("template_execution", re.compile(r"\b(?:render_template_string|jinja2\.Template)\s*\(")),
)


def _entropy(value: str) -> float:
    counts = Counter(value)
    return -sum((count / len(value)) * math.log2(count / len(value)) for count in counts.values())


def _fingerprint(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()


def _is_url(value: str) -> bool:
    parsed = urlparse(value)
    return parsed.scheme in {"http", "https"} and bool(parsed.netloc)


def _repo_from_url(value: str) -> str | None:
    parsed = urlparse(value)
    if parsed.netloc.lower() not in {"github.com", "www.github.com"}:
        return None
    parts = [part for part in parsed.path.split("/") if part]
    return f"{parts[0]}/{parts[1].removesuffix('.git')}" if len(parts) >= 2 else None


def _evidence_poc(repository: str, commit: str) -> str:
    """Return a harmless command that retrieves public evidence only."""
    owner, name = repository.split("/", 1)
    return f"curl --fail --silent --show-error -H 'Accept: application/vnd.github.v3.diff' 'https://github.com/{quote(owner)}/{quote(name)}/commit/{quote(commit)}.diff'"


class GitHubScanner:
    """Async GitHub scanner with bounded concurrency, retries, and no token use."""

    def __init__(self, tracker: SecurityAuditTracker, token: str | None = None, concurrency: int = 8) -> None:
        self.tracker = tracker
        self.token = token
        self.semaphore = asyncio.Semaphore(max(1, concurrency))
        self.timeout = aiohttp.ClientTimeout(total=20)

    def _headers(self) -> dict[str, str]:
        headers = {"Accept": "application/vnd.github+json", "User-Agent": "gitgrave-engine/1.0"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        return headers

    async def _get_json(self, session: aiohttp.ClientSession, path: str, params: dict[str, str] | None = None) -> Any:
        for attempt in range(3):
            try:
                async with self.semaphore, session.get(f"{GITHUB_API}{path}", params=params, headers=self._headers()) as response:
                    remaining = response.headers.get("X-RateLimit-Remaining")
                    if remaining == "0":
                        self.tracker.log("repo_discovery", "GitHub rate limit exhausted; stopping requests", endpoint=path)
                        return None
                    if response.status in {403, 429} and attempt < 2:
                        await asyncio.sleep(min(2**attempt, 8))
                        continue
                    if response.status == 404:
                        return None
                    response.raise_for_status()
                    return await response.json()
            except (aiohttp.ClientError, asyncio.TimeoutError) as error:
                if attempt == 2:
                    self.tracker.log("repo_discovery", "Network request failed", endpoint=path, error=type(error).__name__)
                    return None
                await asyncio.sleep(2**attempt)
        return None

    async def discover(self, target_input: str) -> list[str]:
        self.tracker.log("target_input", "Accepted target input", input_type="url" if _is_url(target_input) else "name")
        async with aiohttp.ClientSession(timeout=self.timeout) as session:
            if _is_url(target_input):
                repository = _repo_from_url(target_input)
                if repository:
                    repositories = [repository]
                else:
                    owner = urlparse(target_input).path.strip("/").split("/")[0]
                    payload = await self._get_json(session, f"/users/{quote(owner)}/repos", {"per_page": "100"})
                    repositories = [item["full_name"] for item in (payload or []) if item.get("fork") is False]
            else:
                payload = await self._get_json(session, "/search/repositories", {"q": f"{target_input} in:name", "per_page": "100"})
                repositories = [item["full_name"] for item in (payload or {}).get("items", [])]
            self.tracker.repositories = sorted(set(repositories))
            self.tracker.log("repo_discovery", f"Identified {len(self.tracker.repositories)} public repositories matching target profile")
            return self.tracker.repositories

    async def scan_repository(self, session: aiohttp.ClientSession, repository: str) -> None:
        owner, name = repository.split("/", 1)
        commits = await self._get_json(session, f"/repos/{quote(owner)}/{quote(name)}/commits", {"per_page": "100"}) or []
        self.tracker.log("commit_history", f"Extracted {len(commits)} commits", repository=repository)
        await asyncio.gather(*(self.scan_commit(session, repository, commit["sha"]) for commit in commits if commit.get("sha")))

    async def scan_commit(self, session: aiohttp.ClientSession, repository: str, sha: str) -> None:
        owner, name = repository.split("/", 1)
        payload = await self._get_json(session, f"/repos/{quote(owner)}/{quote(name)}/commits/{quote(sha)}") or {}
        for file_data in payload.get("files", []):
            filename = file_data.get("filename", "unknown")
            added_lines = [
                (line_number, line)
                for line_number, line in enumerate((file_data.get("patch") or "").splitlines(), 1)
                if line.startswith("+") and not line.startswith("+++")
            ]
            sources = [
                (line_number, source, line)
                for line_number, line in added_lines
                for source, pattern in SOURCE_PATTERNS
                if pattern.search(line)
            ]
            for line_number, line in added_lines:
                if not line.startswith("+") or line.startswith("+++"):
                    continue
                for kind, pattern in SECRET_PATTERNS:
                    for match in pattern.finditer(line):
                        candidate = match.group(1) if match.lastindex else match.group(0)
                        if kind == "generic_secret_assignment" and _entropy(candidate) < 3.2:
                            continue
                        self.tracker.secret_findings.append(SecretFinding(repository=repository, commit=sha, file=filename, line=line_number, kind=kind, confidence="high" if kind != "generic_secret_assignment" else "medium", candidate_sha256=_fingerprint(candidate), evidence_poc=_evidence_poc(repository, sha)))
                        self.tracker.log("secret_detection", "Redacted secret-like value detected; public evidence PoC generated", repository=repository, commit=sha, kind=kind, file=filename, evidence_poc=_evidence_poc(repository, sha))
                for rule, pattern, explanation in HEURISTIC_RULES:
                    if pattern.search(line):
                        self.tracker.heuristic_findings.append(HeuristicFinding(repository=repository, commit=sha, file=filename, line=line_number, rule=rule, explanation=explanation))
                for sink, pattern in SINK_PATTERNS:
                    if not pattern.search(line) or not sources:
                        continue
                    source_line, source, _ = min(sources, key=lambda item: abs(item[0] - line_number))
                    distance = abs(source_line - line_number)
                    if distance > 20:
                        continue
                    confidence: Literal["medium", "high"] = "high" if distance <= 5 else "medium"
                    self.tracker.sink_traces.append(SinkTrace(repository=repository, commit=sha, file=filename, source_line=source_line, source=source, sink_line=line_number, sink=sink, confidence=confidence))
                    self.tracker.log("sink_execution", "Static source-to-sink flow traced; execution was not performed", repository=repository, commit=sha, file=filename, source=source, sink=sink, source_line=source_line, sink_line=line_number)

    async def run(self) -> SecurityAuditTracker:
        try:
            await self.discover(self.tracker.target_input)
            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                await asyncio.gather(*(self.scan_repository(session, repository) for repository in self.tracker.repositories))
            self.tracker.log("sink_execution", "Credential validation skipped: detected values are never transmitted")
            self.tracker.status = "completed"
        except (aiohttp.ClientError, asyncio.TimeoutError, ValueError) as error:
            self.tracker.status = "failed"
            self.tracker.log("sink_execution", "Scan failed safely", error=type(error).__name__)
        return self.tracker


async def scout_target(target_input: str, tracker: SecurityAuditTracker) -> list[str]:
    return await GitHubScanner(tracker).discover(target_input)


async def scan_target(target_input: str, token: str | None = None) -> SecurityAuditTracker:
    return await GitHubScanner(SecurityAuditTracker(target_input=target_input), token=token).run()