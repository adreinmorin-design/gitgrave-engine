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


def test_scanner_uses_token_for_github_requests() -> None:
    tracker = SecurityAuditTracker(target_input="https://github.com/example/repo")
    scanner = __import__("gitgrave_engine.scanner", fromlist=["GitHubScanner"]).GitHubScanner(tracker, token="ghp_secret_token")

    headers = scanner._headers()

    assert headers["Authorization"] == "Bearer ghp_secret_token"
    assert headers["User-Agent"] == "gitgrave-engine/1.0"


def test_log_redacts_sensitive_fields() -> None:
    tracker = SecurityAuditTracker(target_input="https://github.com/example/repo")

    tracker.log("target_input", "starting scan", token="ghp_very_secret_token", authorization="Bearer ghp_very_secret_token")

    metadata = tracker.steps[-1].metadata
    assert metadata["token"] == "[REDACTED]"
    assert metadata["authorization"] == "[REDACTED]"
    assert "ghp_very_secret_token" not in json.dumps(metadata)


def test_resolve_token_uses_keyring_when_available(monkeypatch) -> None:
    import gitgrave_engine.secrets as secrets

    class DummyKeyring:
        def get_password(self, service, username):
            return "ghp_stored_token" if service == "gitgrave-engine" and username == "github-token" else None

    monkeypatch.setattr(secrets, "keyring", DummyKeyring(), raising=False)
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    monkeypatch.delenv("GH_TOKEN", raising=False)

    assert secrets.resolve_github_token() == "ghp_stored_token"


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


def test_scan_file_text_allows_longer_deep_review_chains() -> None:
    tracker = SecurityAuditTracker(target_input="https://github.com/example/repo")
    scanner = __import__("gitgrave_engine.scanner", fromlist=["GitHubScanner"]).GitHubScanner(tracker, deep_review=True)

    steps = ["const userInput = request.form;"]
    previous = "userInput"
    for index in range(90):
        steps.append(f"const value{index} = {previous};")
        previous = f"value{index}"
    steps.extend([
        f"const payload = {previous};",
        "eval(payload);",
    ])

    scanner._scan_file_text(repository="example/repo", sha="abc123", filename="src/app.js", text="\n".join(steps))

    assert len(tracker.sink_traces) == 1
    assert tracker.sink_traces[0].sink == "dynamic_execution"


def test_scan_commit_respects_sink_distance_limit() -> None:
    tracker = SecurityAuditTracker(target_input="https://github.com/example/repo")
    scanner = __import__("gitgrave_engine.scanner", fromlist=["GitHubScanner"]).GitHubScanner(tracker, deep_review=False)

    async def fake_get_json(session, path, params=None):
        if path.endswith("/commits/abc123"):
            return {
                "files": [{
                    "filename": "app.py",
                    "patch": "\n".join([
                        "+user = request.get_json()",
                        *[f"+payload{i} = payload{i - 1} if i > 0 else user" for i in range(25)],
                        "+eval(payload24)",
                    ]),
                }]
            }
        return {}

    scanner._get_json = fake_get_json
    asyncio.run(scanner.scan_commit(session=None, repository="example/repo", sha="abc123"))

    assert len(tracker.sink_traces) == 0


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


def test_scan_file_text_tracks_python_source_variables_to_sink() -> None:
    tracker = SecurityAuditTracker(target_input="https://github.com/example/repo")
    scanner = __import__("gitgrave_engine.scanner", fromlist=["GitHubScanner"]).GitHubScanner(tracker)

    code = """payload = request.get_json()\nresult = payload\neval(result)\n"""
    scanner._scan_file_text(repository="example/repo", sha="abc123", filename="app.py", text=code)

    assert len(tracker.sink_traces) == 1
    assert tracker.sink_traces[0].sink == "dynamic_execution"
    assert tracker.sink_traces[0].source == "request_input"


def test_scan_file_text_tracks_php_source_variables_to_sink() -> None:
    tracker = SecurityAuditTracker(target_input="https://github.com/example/repo")
    scanner = __import__("gitgrave_engine.scanner", fromlist=["GitHubScanner"]).GitHubScanner(tracker)

    code = """$user = $_GET['q'];\n$payload = $user;\neval($payload);\n"""
    scanner._scan_file_text(repository="example/repo", sha="abc123", filename="index.php", text=code)

    assert len(tracker.sink_traces) == 1
    assert tracker.sink_traces[0].sink == "dynamic_execution"
    assert tracker.sink_traces[0].source == "request_input"


def test_scan_file_text_tracks_ruby_java_and_go_source_variables_to_sink() -> None:
    tracker = SecurityAuditTracker(target_input="https://github.com/example/repo")
    scanner = __import__("gitgrave_engine.scanner", fromlist=["GitHubScanner"]).GitHubScanner(tracker)

    ruby_code = """user = params[:q]\npayload = user\nKernel.eval(payload)\n"""
    scanner._scan_file_text(repository="example/repo", sha="abc123", filename="app.rb", text=ruby_code)
    assert len(tracker.sink_traces) == 1
    assert tracker.sink_traces[0].sink == "dynamic_execution"

    java_code = """String user = request.getParameter("q");\nString payload = user;\nScriptEngine engine = new ScriptEngineManager().getEngineByName("js");\nengine.eval(payload);\n"""
    tracker.sink_traces.clear()
    scanner._scan_file_text(repository="example/repo", sha="abc123", filename="App.java", text=java_code)
    assert len(tracker.sink_traces) == 1
    assert tracker.sink_traces[0].sink == "dynamic_execution"

    go_code = """user := r.FormValue("q")\npayload := user\nexec.Command("bash", "-c", payload)\n"""
    tracker.sink_traces.clear()
    scanner._scan_file_text(repository="example/repo", sha="abc123", filename="main.go", text=go_code)
    assert len(tracker.sink_traces) == 1
    assert tracker.sink_traces[0].sink == "shell_execution"


def test_scan_file_text_tracks_csharp_source_variables_to_sink() -> None:
    tracker = SecurityAuditTracker(target_input="https://github.com/example/repo")
    scanner = __import__("gitgrave_engine.scanner", fromlist=["GitHubScanner"]).GitHubScanner(tracker)

    code = """var user = Request.Query["q"].ToString();\nvar payload = user;\nSystem.Web.UI.Page page = null;\npage.Server.Execute(payload);\n"""
    scanner._scan_file_text(repository="example/repo", sha="abc123", filename="HomeController.cs", text=code)

    assert len(tracker.sink_traces) == 1
    assert tracker.sink_traces[0].sink == "dynamic_execution"
    assert tracker.sink_traces[0].source == "request_input"


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
