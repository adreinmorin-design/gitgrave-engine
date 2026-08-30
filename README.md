# GitGrave Engine

GitGrave is a read-only blue-team scanner for public GitHub exposure. It accepts
a repository, organization/user URL, or target name; discovers public
repositories; reviews recent commit patches for credential-like material; and
reports redacted evidence plus conservative code-risk heuristics.

It does **not** validate, replay, or transmit discovered credentials and does
not generate exploit proof-of-concepts. Unknown vulnerabilities cannot be
reliably detected by a repository search tool; the heuristic findings are leads
for authorized defenders to investigate with code review and dedicated SAST/DAST
tools.

## Setup

```bash
python -m pip install -e .
```

An optional `--token` raises GitHub API limits. Use only a token you are
authorized to use.

## Run

```bash
python -m gitgrave_engine AcmeCorp --token "$GITHUB_TOKEN"
python -m gitgrave_engine https://github.com/example/example-repo
python -m gitgrave_engine https://github.com/example
```

Output is JSON containing the target, repository list, ordered audit steps,
redacted secret findings, sink traces, and heuristic findings. Each secret
finding includes an `evidence_poc` `curl` command that retrieves the public
commit diff for independent reproduction. It never authenticates or transmits
the detected value. Secret evidence contains a SHA-256 fingerprint and location,
never the candidate value. GitHub API requests
are asynchronous, bounded by a semaphore, timeout-limited, and stop safely when
the `X-RateLimit-Remaining` header reaches zero.

## Library use

```python
import asyncio
from gitgrave_engine import SecurityAuditTracker, scout_target

async def discover() -> list[str]:
	tracker = SecurityAuditTracker(target_input="https://github.com/example")
	return await scout_target(tracker.target_input, tracker)

asyncio.run(discover())
```

Only scan assets you own or have explicit permission to assess. Rotate any
credential exposed in a finding and remove it from repository history using
your organization's approved process.
