"""
file_utils.py - File I/O helpers for the Recon Framework.

All modules write their results through these helpers to guarantee
consistent formatting, deduplication, and directory creation.
"""

import os
from typing import Iterable, List

import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from logger import get_logger

log = get_logger("utils.file_utils")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def ensure_dir(path: str) -> None:
    """Create *path* (and parents) if it does not already exist."""
    os.makedirs(path, exist_ok=True)


def write_lines(filepath: str, lines: Iterable[str], deduplicate: bool = True) -> int:
    """
    Write *lines* to *filepath*, one entry per line.

    Parameters
    ----------
    filepath    : absolute path to the target file
    lines       : iterable of strings
    deduplicate : if True, strip blank lines and remove duplicates while
                  preserving insertion order

    Returns
    -------
    int : number of lines written
    """
    ensure_dir(os.path.dirname(filepath))

    items: List[str] = []
    if deduplicate:
        seen = set()
        for line in lines:
            clean = line.strip()
            if clean and clean not in seen:
                seen.add(clean)
                items.append(clean)
    else:
        items = [line.rstrip("\n") for line in lines if line.strip()]

    with open(filepath, "w", encoding="utf-8") as fh:
        fh.write("\n".join(items) + ("\n" if items else ""))

    log.debug("Wrote %d lines to %s", len(items), filepath)
    return len(items)


def append_lines(filepath: str, lines: Iterable[str]) -> int:
    """Append *lines* to an existing file (creates it if absent)."""
    ensure_dir(os.path.dirname(filepath))

    items = [line.strip() for line in lines if line.strip()]
    if not items:
        return 0

    with open(filepath, "a", encoding="utf-8") as fh:
        fh.write("\n".join(items) + "\n")

    log.debug("Appended %d lines to %s", len(items), filepath)
    return len(items)


def read_lines(filepath: str) -> List[str]:
    """
    Return a deduplicated list of non-blank lines from *filepath*.

    Returns an empty list (not an exception) if the file does not exist.
    """
    if not os.path.isfile(filepath):
        log.warning("File not found (returning empty): %s", filepath)
        return []

    with open(filepath, "r", encoding="utf-8") as fh:
        raw = fh.readlines()

    seen: set = set()
    result: List[str] = []
    for line in raw:
        clean = line.strip()
        if clean and clean not in seen:
            seen.add(clean)
            result.append(clean)

    log.debug("Read %d unique lines from %s", len(result), filepath)
    return result


def write_report_section(filepath: str, header: str, content: str) -> None:
    """
    Append a titled section to a report file.

    Example output
    --------------
    =============================================
    PORT SCAN RESULTS
    =============================================
    <content>
    """
    ensure_dir(os.path.dirname(filepath))
    separator = "=" * 60
    section = f"\n{separator}\n{header.upper()}\n{separator}\n{content}\n"

    with open(filepath, "a", encoding="utf-8") as fh:
        fh.write(section)

    log.debug("Appended section '%s' to %s", header, filepath)


def count_lines(filepath: str) -> int:
    """Return the number of non-blank lines in *filepath*."""
    return len(read_lines(filepath))
