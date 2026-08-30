from __future__ import annotations

import argparse
import asyncio
import json

from .scanner import scan_target


def main() -> None:
    parser = argparse.ArgumentParser(description="Read-only public GitHub exposure scanner")
    parser.add_argument("target", help="GitHub repository, organization/user URL, or target name")
    parser.add_argument("--token", help="Optional GitHub token for higher API limits; never sent to findings")
    args = parser.parse_args()
    result = asyncio.run(scan_target(args.target, token=args.token))
    print(json.dumps(result.model_dump(mode="json"), indent=2))


if __name__ == "__main__":
    main()