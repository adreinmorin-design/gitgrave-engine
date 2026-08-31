from __future__ import annotations

import argparse
import asyncio
import json

from .scanner import scan_target
from .secrets import resolve_github_token


def main() -> None:
    parser = argparse.ArgumentParser(description="Read-only public GitHub exposure scanner")
    parser.add_argument("target", help="GitHub repository, organization/user URL, or target name")
    parser.add_argument("--token", help="Optional GitHub token for higher API limits; if omitted, the system keyring or GITHUB_TOKEN is used")
    parser.add_argument("--state-file", help="Optional file used to persist progress and resume a previously interrupted scan")
    parser.add_argument("--report-file", help="Optional path for a JSON report package with PoCs and summary")
    parser.add_argument("--report-title", default="GitGrave Security Report", help="Title to use in the exported report package")
    args = parser.parse_args()
    token = args.token or resolve_github_token()
    result = asyncio.run(scan_target(args.target, token=token, state_path=args.state_file))
    if args.report_file:
        from .scanner import write_report_package

        write_report_package(result, args.report_file, report_title=args.report_title)
    print(json.dumps(result.model_dump(mode="json"), indent=2))


if __name__ == "__main__":
    main()