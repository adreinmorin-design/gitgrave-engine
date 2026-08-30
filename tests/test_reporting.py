import asyncio
import base64
import json
from pathlib import Path

from gitgrave_engine.scanner import (
    HeuristicFinding,
    SecretFinding,
    SecurityAuditTracker,
    _heuristic_confidence,
    _should_skip_heuristic_candidate,
    _should_skip_secret_candidate,
    write_report_package,
)


def test_should_skip_demo_secret_candidates_in_test_files() -> None:
    assert _should_skip_secret_candidate(
        "generic_secret_assignment",
        "test/api/erasure-request.test.ts",
        "kitten lesser pooch karate buffoon indoors",
    )
    assert _should_skip_secret_candidate(
        "generic_secret_assignment",
        "fixtures/demo.env",
        "super-secret-example-password",
    )
    assert _should_skip_heuristic_candidate("dynamic_eval", "test/demo.js", "eval(example)")
    assert not _should_skip_heuristic_candidate("dynamic_eval", "routes/userProfile.ts", "username = eval(code) // eslint-disable-line no-eval")
    assert _heuristic_confidence("dynamic_eval", "routes/userProfile.ts", "username = eval(code)") == "high"
    assert _heuristic_confidence("dynamic_eval", "src/legacy.js", "const value = eval(data)") == "high"
    assert _heuristic_confidence("dynamic_eval", "src/legacy.js", "eval(userinput)") == "medium"
    assert _heuristic_confidence("dynamic_eval", "test/demo.js", "eval(example)") == "low"


def test_write_report_package_includes_poc_and_summary(tmp_path: Path) -> None:
    tracker = SecurityAuditTracker(target_input="https://github.com/example/repo")
    tracker.secret_findings.append(
        SecretFinding(
            repository="example/repo",
            commit="abc123",
            file="config/app.env",
            line=17,
            kind="github_pat",
            confidence="high",
            candidate_sha256="deadbeef",
            evidence_poc="curl --fail -L https://example.invalid/commit/abc123.diff",
        )
    )
    tracker.heuristic_findings.append(
        HeuristicFinding(
            repository="example/repo",
            commit="abc123",
            file="app.py",
            line=42,
            rule="dynamic_eval",
            explanation="Dynamic evaluation can execute attacker-controlled input.",
            confidence="high",
        )
    )

    out_path = tmp_path / "microsoft-report.json"
    package = write_report_package(tracker, out_path, report_title="Microsoft Security Report")

    assert out_path.exists()
    assert package["report_title"] == "Microsoft Security Report"
    assert package["finding_count"] == 2
    assert package["findings"][0]["evidence_poc"] == "curl --fail -L https://example.invalid/commit/abc123.diff"
    assert any(item.get("rule") == "dynamic_eval" for item in package["findings"])
    assert isinstance(json.loads(out_path.read_text()), dict)


def test_scan_file_text_detects_live_eval_pattern() -> None:
    tracker = SecurityAuditTracker(target_input="https://github.com/example/repo")
    scanner = __import__("gitgrave_engine.scanner", fromlist=["GitHubScanner"]).GitHubScanner(tracker)

    html = """const code = username?.substring(2, username.length - 1)\nusername = eval(code) // eslint-disable-line no-eval\n"""
    scanner._scan_file_text(repository="example/repo", sha="abc123", filename="routes/userProfile.ts", text=html)

    assert len(tracker.heuristic_findings) == 1
    assert tracker.heuristic_findings[0].rule == "dynamic_eval"
    assert tracker.heuristic_findings[0].confidence == "high"


def test_scan_file_text_ignores_placeholder_generic_secret_values() -> None:
    tracker = SecurityAuditTracker(target_input="https://github.com/example/repo")
    scanner = __import__("gitgrave_engine.scanner", fromlist=["GitHubScanner"]).GitHubScanner(tracker)

    code = """const password = \"example-password-value-123456\";\nconst safe = \"hello\";\n"""
    scanner._scan_file_text(repository="example/repo", sha="abc123", filename="routes/userProfile.ts", text=code)

    assert not any(item.kind == "generic_secret_assignment" for item in tracker.secret_findings)


def test_scan_file_text_rejects_unrelated_sink_source_pairs() -> None:
    tracker = SecurityAuditTracker(target_input="https://github.com/example/repo")
    scanner = __import__("gitgrave_engine.scanner", fromlist=["GitHubScanner"]).GitHubScanner(tracker)

    code = """const userInput = request.form;\nconst unrelated = \"static\";\neval(unrelated);\n"""
    scanner._scan_file_text(repository="example/repo", sha="abc123", filename="routes/userProfile.ts", text=code)

    assert len(tracker.sink_traces) == 0


def test_scan_file_text_allows_deeper_sink_distance_in_deep_review() -> None:
    tracker = SecurityAuditTracker(target_input="https://github.com/example/repo")
    scanner = __import__("gitgrave_engine.scanner", fromlist=["GitHubScanner"]).GitHubScanner(tracker, deep_review=True)

    code = "\n".join([
        "const userInput = request.form;",
        *["const value = userInput;" for _ in range(45)],
        "eval(value);",
    ])
    scanner._scan_file_text(repository="example/repo", sha="abc123", filename="src/app.js", text=code)

    assert len(tracker.sink_traces) == 1
    assert tracker.sink_traces[0].sink == "dynamic_execution"


def test_scan_file_text_tracks_source_variables_to_sink() -> None:
    tracker = SecurityAuditTracker(target_input="https://github.com/example/repo")
    scanner = __import__("gitgrave_engine.scanner", fromlist=["GitHubScanner"]).GitHubScanner(tracker)

    code = """const userInput = req.body.message;\nconst safe = 'hello';\neval(safe);\n"""
    scanner._scan_file_text(repository="example/repo", sha="abc123", filename="routes/lookup.ts", text=code)
    assert len(tracker.sink_traces) == 0

    code2 = """const userInput = req.body.message;\nconst payload = userInput;\neval(payload);\n"""
    tracker.sink_traces.clear()
    scanner._scan_file_text(repository="example/repo", sha="abc123", filename="routes/lookup.ts", text=code2)

    assert len(tracker.sink_traces) == 1
    assert tracker.sink_traces[0].sink == "dynamic_execution"


def test_scan_file_text_scores_router_paths_and_deduplicates() -> None:
    tracker = SecurityAuditTracker(target_input="https://github.com/example/repo")
    scanner = __import__("gitgrave_engine.scanner", fromlist=["GitHubScanner"]).GitHubScanner(tracker)

    code = """const userInput = req.body.message;\nconst payload = userInput;\neval(payload);\n"""
    scanner._scan_file_text(repository="example/repo", sha="abc123", filename="routes/userProfile.ts", text=code)
    scanner._scan_file_text(repository="example/repo", sha="abc123", filename="routes/userProfile.ts", text=code)

    assert len(tracker.heuristic_findings) == 1
    assert tracker.heuristic_findings[0].confidence == "high"
    assert len(tracker.sink_traces) == 1


def test_scan_repository_scans_full_recursive_tree() -> None:
    tracker = SecurityAuditTracker(target_input="https://github.com/example/repo")
    scanner = __import__("gitgrave_engine.scanner", fromlist=["GitHubScanner"]).GitHubScanner(tracker)
    requested_files: list[str] = []
    scanned_files: list[str] = []

    async def fake_get_json(session, path, params=None):
        if path.endswith("/commits"):
            return [{"sha": "abc123"}]
        if path.endswith("/repos/example/repo"):
            return {"default_branch": "main"}
        if path.endswith("/branches/main"):
            return {"commit": {"sha": "tree-sha"}}
        if "/git/trees/" in path:
            return {"tree": [{"type": "blob", "path": f"file_{i}.ts"} for i in range(250)]}
        if path.startswith("/repos/example/repo/contents/"):
            requested_files.append(path.split("/contents/")[-1])
            return {"type": "file", "encoding": "base64", "content": base64.b64encode(b"const value = eval(userInput);\n").decode("ascii")}
        return {}

    scanner._get_json = fake_get_json
    scanner._scan_file_text = lambda repository, sha, filename, text: scanned_files.append(filename)

    asyncio.run(scanner.scan_repository(session=None, repository="example/repo"))

    assert len(requested_files) == 250
    assert len(scanned_files) == 250
    assert scanned_files[0].startswith("file_")


def test_write_report_package_handles_empty_results(tmp_path: Path) -> None:
    tracker = SecurityAuditTracker(target_input="https://github.com/example/repo")
    out_path = tmp_path / "empty-report.json"

    package = write_report_package(tracker, out_path)

    assert package["finding_count"] == 0
    assert package["summary"]["secret_findings"] == 0
    assert package["summary"]["heuristic_findings"] == 0
