"""
SWA AI — minimal .env loader (no external dependencies).

Loads KEY=VALUE pairs from the repository-root `.env` file into
`os.environ` without overriding variables that are already set in the
process environment. Supports comments (#), blank lines, optional
`export ` prefixes and single/double-quoted values.
"""

from __future__ import annotations

import os


def load_env_file(path: str | None = None, override: bool = False) -> dict:
    """Load variables from a .env file. Returns the dict that was applied."""
    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    env_path = path or os.path.join(repo_root, ".env")
    applied: dict[str, str] = {}
    if not os.path.isfile(env_path):
        return applied
    try:
        with open(env_path, "r", encoding="utf-8", errors="ignore") as fh:
            for raw in fh:
                line = raw.rstrip("\n").rstrip("\r").strip()
                if not line or line.startswith("#"):
                    continue
                if line.startswith("export "):
                    line = line[len("export "):].lstrip()
                if "=" not in line:
                    continue
                key, value = line.split("=", 1)
                key = key.strip()
                value = value.strip()
                if not key:
                    continue
                if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
                    value = value[1:-1]
                if not override and key in os.environ:
                    continue
                os.environ[key] = value
                applied[key] = value
    except OSError:
        return applied
    return applied
