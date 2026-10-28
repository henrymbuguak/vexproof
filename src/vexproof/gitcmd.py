"""Run git with protections suited to untrusted repositories.

Protections: hooks disabled, the local-file transport refused, no interactive prompts,
argument lists only (never a shell), and a timeout. The caller's environment is inherited so
proxy and certificate settings (HTTPS_PROXY, GIT_SSL_CAINFO, system git config) keep working.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

from vexproof.errors import VexproofError

DEFAULT_TIMEOUT_S = 300


class GitError(VexproofError):
    """A git command failed, timed out, or git is not installed."""


def run_git(
    args: list[str],
    cwd: Path | None = None,
    *,
    timeout_s: float = DEFAULT_TIMEOUT_S,
    allow_file_protocol: bool = False,
) -> str:
    """Run `git <args>` and return stdout without the trailing newline.

    `allow_file_protocol` exists only so tests can fetch from a local repository.
    """
    env = {**os.environ, "GIT_TERMINAL_PROMPT": "0", "GIT_OPTIONAL_LOCKS": "0"}
    protocol = "always" if allow_file_protocol else "never"
    cmd = [
        "git",
        "-c", f"protocol.file.allow={protocol}",
        "-c", "core.hooksPath=/dev/null",
        "-c", "credential.helper=",
        *args,
    ]  # fmt: skip
    try:
        result = subprocess.run(  # noqa: S603 - fixed executable, validated arguments
            cmd,
            cwd=cwd,
            env=env,
            capture_output=True,
            text=True,
            timeout=timeout_s,
            check=True,
        )
    except FileNotFoundError as exc:
        raise GitError("git is not installed or not on PATH") from exc
    except subprocess.TimeoutExpired as exc:
        raise GitError(f"git {args[0]} timed out after {timeout_s:.0f}s") from exc
    except subprocess.CalledProcessError as exc:
        raise GitError(f"git {args[0]} failed: {exc.stderr.strip()}") from exc
    return result.stdout.rstrip("\n")
