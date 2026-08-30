"""Defensive, read-only GitHub exposure scanner."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import math
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
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
    confidence: Literal["low", "medium", "high"] = "medium"


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


def _looks_like_placeholder_secret(value: str) -> bool:
    lower = value.lower()
    placeholder_tokens = (
        "example",
        "demo",
        "sample",
        "placeholder",
        "changeme",
        "password123",
        "testuser",
        "your_",
        "your-",
        "replace_me",
        "replace-me",
        "fill_me_in",
        "kitten",
        "pooch",
        "lorem",
        "ipsum",
        "not_a_real",
    )
    if any(token in lower for token in placeholder_tokens):
        return True
    if re.search(r"(?:example|demo|sample|placeholder|changeme|testuser)[-_a-z0-9]*\d{2,}", lower):
        return True
    if re.fullmatch(r"(?:[a-z]+|[0-9]+|[A-Z]+)", lower) and len(lower) < 8:
        return True
    return False


def _should_skip_secret_candidate(kind: str, filename: str, candidate: str) -> bool:
    lower_file = filename.lower()
    lower_value = candidate.lower()
    if any(marker in lower_file for marker in ("test", "tests", "fixtures", "sample", "demo", "mock", "example")):
        if _looks_like_placeholder_secret(lower_value):
            return True
    if kind == "generic_secret_assignment":
        if _looks_like_placeholder_secret(lower_value):
            return True
        if any(token in lower_file for token in ("test", "fixtures", "sample", "demo", "example")):
            return True
        if len(candidate) < 12:
            return True
        if not re.search(r"(?:[A-Za-z0-9_\-]{12,})", candidate):
            return True
    return False


def _should_skip_heuristic_candidate(rule: str, filename: str, line: str) -> bool:
    lower_file = filename.lower()
    lower_line = line.lower()
    if any(marker in lower_file for marker in ("test", "tests", "fixture", "fixtures", "mock", "sample", "demo")):
        if any(marker in lower_line for marker in ("example", "demo", "sample", "placeholder", "kitten", "testuser")):
            return True
    return False


def _path_risk_weight(filename: str) -> int:
    lower_file = filename.lower()
    if any(marker in lower_file for marker in ("routes/", "api/", "controllers/", "server/", "app/", "src/")):
        return 2
    if any(marker in lower_file for marker in ("test", "tests", "fixture", "fixtures", "mock", "sample", "demo", "docs", "vendor", "dist", "build")):
        return -2
    return 0


def _heuristic_confidence(rule: str, filename: str, line: str) -> Literal["low", "medium", "high"]:
    lower_file = filename.lower()
    lower_line = line.lower()
    if any(marker in lower_file for marker in ("test", "tests", "fixture", "fixtures", "mock", "sample", "demo")):
        return "low"
    path_weight = _path_risk_weight(filename)
    if rule == "dynamic_eval":
        if "eval(" not in lower_line:
            return "low"
        strong_tokens = ("req.body", "request", "username", "code", "payload", "query", "data")
        weak_tokens = ("userinput", "searchparams", "input")
        high_signal = any(token in lower_line for token in strong_tokens)
        medium_signal = any(token in lower_line for token in weak_tokens)
        if high_signal and any(token in lower_line for token in ("=", "let ", "const ", "return ")):
            return "high" if path_weight >= 0 else "medium"
        if path_weight > 0 and high_signal:
            return "high"
        if medium_signal:
            return "medium"
        return "medium" if path_weight >= 0 else "low"
    if rule == "shell_execution":
        if "shell=true" in lower_line or "shell = true" in lower_line:
            return "high" if any(token in lower_line for token in ("subprocess", "os.system", "os.popen", "bash", "sh")) and path_weight >= 0 else "medium"
        return "medium"
    if rule == "unsafe_deserialization":
        if any(token in lower_line for token in ("yaml.load", "pickle.loads", "marshal.loads", "ast.literal_eval")):
            return "high" if any(token in lower_line for token in ("request", "body", "input", "payload", "data", "json")) and path_weight >= 0 else "medium"
        return "medium"
    return "medium"


def _extract_variable_assignments(line: str, tracked_sources: dict[str, str]) -> dict[str, str]:
    assignments: dict[str, str] = {}
    for match in re.finditer(r"\b(?:const|let|var)\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*([^;]+)", line):
        variable_name = match.group(1)
        value = match.group(2).strip()
        source: str | None = None

        if re.search(r"(?:req\.|request\.|input\b|query\b|body\b|form\b|json\b|params\b)", value):
            source = "request_input"
        else:
            for tracked_name, tracked_source in tracked_sources.items():
                if re.search(rf"\b{re.escape(tracked_name)}\b", value):
                    source = tracked_source
                    break

        if source is not None:
            assignments[variable_name] = source
    return assignments


def _extract_sink_variable(line: str) -> str | None:
    match = re.search(r"\b(?:eval|exec|os\.system|os\.popen|subprocess\.[A-Za-z_]+)\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)", line)
    if match:
        return match.group(1)
    return None


def _skip_file_path(filename: str, *, deep_review: bool = False) -> bool:
    lower = filename.lower()
    parts = [part for part in lower.replace('\\', '/').split('/') if part]
    if any(part in {".git", "node_modules", "vendor", "dist", "build", "coverage", "__pycache__", "target"} for part in parts):
        return True
    if not deep_review and any(marker in lower for marker in ("/docs/", "/examples/", "/fixtures/", "/samples/", "/mock/")):
        return True
    return False


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


def _heuristic_poc(repository: str, commit: str, file: str, line: int | None = None) -> str:
    owner, name = repository.split("/", 1)
    diff_url = f"https://github.com/{quote(owner)}/{quote(name)}/commit/{quote(commit)}.diff"
    if line is not None:
        return (
            f"curl --fail --silent --show-error -H 'Accept: application/vnd.github.v3.diff' '{diff_url}' "
            f"| nl -ba | sed -n '{max(1, line - 2)},{line + 2}p'"
        )
    return f"curl --fail --silent --show-error -H 'Accept: application/vnd.github.v3.diff' '{diff_url}'"


def write_report_package(
    tracker: SecurityAuditTracker,
    output_path: str | Path | None = None,
    *,
    report_title: str = "GitGrave Security Report",
) -> dict[str, Any]:
    """Package a report with concise PoCs and redacted findings."""
    findings: list[dict[str, Any]] = []

    for finding in tracker.secret_findings:
        findings.append(
            {
                "type": "secret",
                "repository": finding.repository,
                "commit": finding.commit,
                "file": finding.file,
                "line": finding.line,
                "kind": finding.kind,
                "confidence": finding.confidence,
                "candidate_sha256": finding.candidate_sha256,
                "validation": finding.validation,
                "evidence_poc": finding.evidence_poc,
                "poc": finding.evidence_poc,
            }
        )

    for finding in tracker.heuristic_findings:
        findings.append(
            {
                "type": "heuristic",
                "repository": finding.repository,
                "commit": finding.commit,
                "file": finding.file,
                "line": finding.line,
                "rule": finding.rule,
                "explanation": finding.explanation,
                "confidence": finding.confidence,
                "evidence_poc": _heuristic_poc(finding.repository, finding.commit, finding.file, finding.line),
                "poc": _heuristic_poc(finding.repository, finding.commit, finding.file, finding.line),
            }
        )

    for trace in tracker.sink_traces:
        findings.append(
            {
                "type": "sink_trace",
                "repository": trace.repository,
                "commit": trace.commit,
                "file": trace.file,
                "source_line": trace.source_line,
                "source": trace.source,
                "sink_line": trace.sink_line,
                "sink": trace.sink,
                "confidence": trace.confidence,
                "evidence_poc": _heuristic_poc(trace.repository, trace.commit, trace.file, trace.sink_line),
                "poc": _heuristic_poc(trace.repository, trace.commit, trace.file, trace.sink_line),
            }
        )

    payload: dict[str, Any] = {
        "report_title": report_title,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "target_input": tracker.target_input,
        "status": tracker.status,
        "repositories": tracker.repositories,
        "summary": {
            "repositories": len(tracker.repositories),
            "secret_findings": len(tracker.secret_findings),
            "heuristic_findings": len(tracker.heuristic_findings),
            "sink_traces": len(tracker.sink_traces),
            "total_findings": len(findings),
        },
        "finding_count": len(findings),
        "findings": findings,
    }

    if output_path is not None:
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    return payload


class GitHubScanner:
    """Async GitHub scanner with bounded concurrency, retries, and no token use."""

    def __init__(self, tracker: SecurityAuditTracker, token: str | None = None, concurrency: int = 8, *, deep_review: bool = True) -> None:
        self.tracker = tracker
        self.token = token
        self.semaphore = asyncio.Semaphore(max(1, concurrency))
        self.timeout = aiohttp.ClientTimeout(total=20)
        self.deep_review = deep_review
        self.max_sink_distance = 80 if deep_review else 20

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

    def _scan_file_text(self, repository: str, sha: str, filename: str, text: str) -> None:
        if _skip_file_path(filename, deep_review=self.deep_review):
            return
        lines = text.splitlines()
        tracked_sources: dict[str, str] = {}
        source_locations: dict[str, int] = {}
        for line_number, line in enumerate(lines, 1):
            if not line:
                continue

            for assigned_name, source in _extract_variable_assignments(line, tracked_sources).items():
                tracked_sources[assigned_name] = source
                source_locations[assigned_name] = line_number

            for kind, pattern in SECRET_PATTERNS:
                for match in pattern.finditer(line):
                    candidate = match.group(1) if match.lastindex else match.group(0)
                    if kind == "generic_secret_assignment" and _entropy(candidate) < 3.2:
                        continue
                    if _should_skip_secret_candidate(kind, filename, candidate):
                        continue
                    self.tracker.secret_findings.append(SecretFinding(repository=repository, commit=sha, file=filename, line=line_number, kind=kind, confidence="high" if kind != "generic_secret_assignment" else "medium", candidate_sha256=_fingerprint(candidate), evidence_poc=_evidence_poc(repository, sha)))
                    self.tracker.log("secret_detection", "Redacted secret-like value detected; public evidence PoC generated", repository=repository, commit=sha, kind=kind, file=filename, evidence_poc=_evidence_poc(repository, sha))
            for rule, pattern, explanation in HEURISTIC_RULES:
                if pattern.search(line):
                    if _should_skip_heuristic_candidate(rule, filename, line):
                        continue
                    heuristic_confidence = _heuristic_confidence(rule, filename, line)
                    if any(existing.repository == repository and existing.commit == sha and existing.file == filename and existing.line == line_number and existing.rule == rule for existing in self.tracker.heuristic_findings):
                        continue
                    self.tracker.heuristic_findings.append(HeuristicFinding(repository=repository, commit=sha, file=filename, line=line_number, rule=rule, explanation=explanation, confidence=heuristic_confidence))

            sink_var = _extract_sink_variable(line)
            if not sink_var or sink_var not in tracked_sources:
                continue
            source_line = source_locations.get(sink_var)
            if source_line is None:
                continue
            distance = abs(source_line - line_number)
            if distance > self.max_sink_distance:
                continue
            sink_name = next((sink for sink, pattern in SINK_PATTERNS if pattern.search(line)), "dynamic_execution")
            sink_key = (repository, sha, filename, source_line, line_number, sink_name)
            if sink_key in {(trace.repository, trace.commit, trace.file, trace.source_line, trace.sink_line, trace.sink) for trace in self.tracker.sink_traces}:
                continue
            sink_confidence: Literal["medium", "high"] = "high" if distance <= 5 else "medium"
            self.tracker.sink_traces.append(
                SinkTrace(
                    repository=repository,
                    commit=sha,
                    file=filename,
                    source_line=source_line,
                    source=tracked_sources[sink_var],
                    sink_line=line_number,
                    sink=sink_name,
                    confidence=sink_confidence,
                )
            )
            self.tracker.log("sink_execution", "Static source-to-sink flow traced; execution was not performed", repository=repository, commit=sha, file=filename, source=tracked_sources[sink_var], sink=sink_name, source_line=source_line, sink_line=line_number)

    async def scan_repository(self, session: aiohttp.ClientSession, repository: str) -> None:
        owner, name = repository.split("/", 1)
        commits = await self._get_json(session, f"/repos/{quote(owner)}/{quote(name)}/commits", {"per_page": "100"}) or []
        self.tracker.log("commit_history", f"Extracted {len(commits)} commits", repository=repository)
        await asyncio.gather(*(self.scan_commit(session, repository, commit["sha"]) for commit in commits if commit.get("sha")))

        repo_info = await self._get_json(session, f"/repos/{quote(owner)}/{quote(name)}") or {}
        default_branch = repo_info.get("default_branch") or "main"
        branch_info = await self._get_json(session, f"/repos/{quote(owner)}/{quote(name)}/branches/{quote(default_branch)}") or {}
        tree_sha = (branch_info.get("commit") or {}).get("sha") or default_branch
        tree = await self._get_json(session, f"/repos/{quote(owner)}/{quote(name)}/git/trees/{quote(tree_sha)}", {"recursive": "1"}) or {}
        for item in tree.get("tree", []):
            if item.get("type") != "blob" or not item.get("path"):
                continue
            file_path = item["path"]
            if _skip_file_path(file_path, deep_review=self.deep_review):
                continue
            file_payload = await self._get_json(session, f"/repos/{quote(owner)}/{quote(name)}/contents/{quote(file_path)}", {"ref": default_branch}) or {}
            if not isinstance(file_payload, dict) or file_payload.get("type") != "file":
                continue
            content = file_payload.get("content") or ""
            if file_payload.get("encoding") == "base64":
                try:
                    content = base64.b64decode(content).decode("utf-8", errors="replace")
                except Exception:
                    content = content
            self._scan_file_text(repository, default_branch, file_path, content)

    async def scan_commit(self, session: aiohttp.ClientSession, repository: str, sha: str) -> None:
        owner, name = repository.split("/", 1)
        payload = await self._get_json(session, f"/repos/{quote(owner)}/{quote(name)}/commits/{quote(sha)}") or {}
        for file_data in payload.get("files", []):
            filename = file_data.get("filename", "unknown")
            if _skip_file_path(filename, deep_review=self.deep_review):
                continue
            added_lines = [
                (line_number, line[1:] if line.startswith("+") and not line.startswith("+++") else "")
                for line_number, line in enumerate((file_data.get("patch") or "").splitlines(), 1)
                if line.startswith("+") and not line.startswith("+++")
            ]
            tracked_sources: dict[str, str] = {}
            source_locations: dict[str, int] = {}
            for line_number, line in added_lines:
                if not line:
                    continue
                for assigned_name, source in _extract_variable_assignments(line, tracked_sources).items():
                    tracked_sources[assigned_name] = source
                    source_locations[assigned_name] = line_number

                for kind, pattern in SECRET_PATTERNS:
                    for match in pattern.finditer(line):
                        candidate = match.group(1) if match.lastindex else match.group(0)
                        if kind == "generic_secret_assignment" and _entropy(candidate) < 3.2:
                            continue
                        if _should_skip_secret_candidate(kind, filename, candidate):
                            continue
                        self.tracker.secret_findings.append(SecretFinding(repository=repository, commit=sha, file=filename, line=line_number, kind=kind, confidence="high" if kind != "generic_secret_assignment" else "medium", candidate_sha256=_fingerprint(candidate), evidence_poc=_evidence_poc(repository, sha)))
                        self.tracker.log("secret_detection", "Redacted secret-like value detected; public evidence PoC generated", repository=repository, commit=sha, kind=kind, file=filename, evidence_poc=_evidence_poc(repository, sha))
                for rule, pattern, explanation in HEURISTIC_RULES:
                    if pattern.search(line):
                        if _should_skip_heuristic_candidate(rule, filename, line):
                            continue
                        confidence = _heuristic_confidence(rule, filename, line)
                        self.tracker.heuristic_findings.append(HeuristicFinding(repository=repository, commit=sha, file=filename, line=line_number, rule=rule, explanation=explanation, confidence=confidence))

                sink_var = _extract_sink_variable(line)
                if not sink_var or sink_var not in tracked_sources:
                    continue
                source_line = source_locations.get(sink_var)
                if source_line is None:
                    continue
                sink_name = next((sink for sink, pattern in SINK_PATTERNS if pattern.search(line)), "dynamic_execution")
                sink_key = (repository, sha, filename, source_line, line_number, sink_name)
                if sink_key in {(trace.repository, trace.commit, trace.file, trace.source_line, trace.sink_line, trace.sink) for trace in self.tracker.sink_traces}:
                    continue
                self.tracker.sink_traces.append(SinkTrace(repository=repository, commit=sha, file=filename, source_line=source_line, source=tracked_sources[sink_var], sink_line=line_number, sink=sink_name, confidence="high"))
                self.tracker.log("sink_execution", "Static source-to-sink flow traced; execution was not performed", repository=repository, commit=sha, file=filename, source=tracked_sources[sink_var], sink=sink_name, source_line=source_line, sink_line=line_number)

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
    """Run a read-only GitHub exposure scan for a target input."""
    tracker = SecurityAuditTracker(target_input=target_input)
    scanner = GitHubScanner(tracker, token=token)
    await scanner.run()
    return tracker
