"""
command_runner.py - Safe subprocess wrapper for the Recon Framework.

All external tool calls go through `run_command()`.  It handles:
  - Timeout enforcement
  - stdout / stderr capture
  - Return-code checking
  - Structured logging of every invocation
"""

import shlex
import subprocess
import threading
import time
from dataclasses import dataclass, field
from typing import List, Optional

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from logger import get_logger

log = get_logger("utils.command_runner")


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------

@dataclass
class CommandResult:
    """Holds everything returned by a single subprocess run."""

    command:     List[str]
    returncode:  int
    stdout:      str
    stderr:      str
    elapsed:     float          # seconds
    timed_out:   bool = False
    error:       Optional[str] = None

    @property
    def success(self) -> bool:
        return self.returncode == 0 and not self.timed_out and self.error is None

    def __str__(self) -> str:
        cmd_str = " ".join(self.command)
        status  = "OK" if self.success else "FAILED"
        return f"[{status}] '{cmd_str}' (rc={self.returncode}, {self.elapsed:.1f}s)"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def run_command(
    command: List[str],
    timeout: int = 120,
    cwd: Optional[str] = None,
    env: Optional[dict] = None,
) -> CommandResult:
    """
    Execute *command* as a subprocess and return a :class:`CommandResult`.

    Parameters
    ----------
    command : list[str]
        Tokenised command, e.g. ``["nmap", "-sV", "192.168.1.1"]``.
    timeout : int
        Maximum wall-clock seconds to wait.  The process is killed on breach.
    cwd : str | None
        Working directory for the child process.
    env : dict | None
        Custom environment; inherits the parent environment if *None*.

    Returns
    -------
    CommandResult
        Always returns a result object — never raises on non-zero exit code.
    """
    cmd_str     = " ".join(shlex.quote(str(t)) for t in command)
    thread_name = threading.current_thread().name
    log.debug("[%s] Running: %s (timeout=%ds)", thread_name, cmd_str, timeout)

    start = time.monotonic()
    timed_out = False
    error_msg: Optional[str] = None

    try:
        proc = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            cwd=cwd,
            env=env,
            text=True,
        )
        stdout   = proc.stdout or ""
        stderr   = proc.stderr or ""
        returncode = proc.returncode

    except subprocess.TimeoutExpired as exc:
        timed_out  = True
        returncode = -1
        stdout     = (exc.stdout or b"").decode("utf-8", errors="replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        stderr     = (exc.stderr or b"").decode("utf-8", errors="replace") if isinstance(exc.stderr, bytes) else (exc.stderr or "")
        error_msg  = f"Timed out after {timeout}s"
        log.warning("Command timed out after %ds: %s", timeout, cmd_str)

    except FileNotFoundError:
        returncode = -1
        stdout     = ""
        stderr     = ""
        error_msg  = f"Executable not found: '{command[0]}'"
        log.error("Tool not found — is '%s' installed and on PATH?", command[0])

    except Exception as exc:                   # noqa: BLE001
        returncode = -1
        stdout     = ""
        stderr     = ""
        error_msg  = str(exc)
        log.exception("Unexpected error running '%s': %s", cmd_str, exc)

    elapsed = time.monotonic() - start
    result  = CommandResult(
        command=command,
        returncode=returncode,
        stdout=stdout,
        stderr=stderr,
        elapsed=elapsed,
        timed_out=timed_out,
        error=error_msg,
    )

    if result.success:
        log.debug("[%s] Finished in %.1fs: %s", thread_name, elapsed, cmd_str)
    else:
        log.warning(str(result))
        if stderr.strip():
            log.debug("stderr: %s", stderr.strip()[:500])

    return result


def tool_available(name: str) -> bool:
    """Return True if *name* resolves to an executable.

    Handles both bare names (searched on PATH via shutil.which) and absolute
    or relative paths (checked directly with os.path.isfile + os.access so
    that binaries in ~/go/bin/ are found even when that directory is not on
    the system PATH).
    """
    import shutil
    if os.sep in name:
        found = os.path.isfile(name) and os.access(name, os.X_OK)
    else:
        found = shutil.which(name) is not None
    if not found:
        log.warning("Tool '%s' was not found on PATH.", name)
    return found
