"""Secure GitHub token resolution utilities."""

from __future__ import annotations

import os
from typing import Mapping

try:
    import keyring
except Exception:  # pragma: no cover - optional dependency
    keyring = None


def _canonical_token(value: str | None) -> str | None:
    if value is None:
        return None
    token = value.strip()
    return token or None


def resolve_github_token(*, env: Mapping[str, str] | None = None) -> str | None:
    """Return a GitHub token from env vars or the OS keyring.

    The token is never written to disk in the repository and the caller should
    prefer to retrieve it through the system secret store rather than commit it
    into source or environment files.
    """
    env_map = os.environ if env is None else env
    for name in ("GITHUB_TOKEN", "GH_TOKEN"):
        token = _canonical_token(env_map.get(name))
        if token:
            return token

    if keyring is not None:
        try:
            token = _canonical_token(keyring.get_password("gitgrave-engine", "github-token"))
        except Exception:
            token = None
        if token:
            return token

    return None
