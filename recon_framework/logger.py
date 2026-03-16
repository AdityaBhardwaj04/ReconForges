"""
logger.py - Centralized logging for the Automated Reconnaissance Framework.

Every module imports `get_logger(__name__)` to receive a pre-configured logger.
Log output goes to both the console (colored) and a rotating file.
"""

import logging
import os
from logging.handlers import RotatingFileHandler

from config import LOG_DIR

# ---------------------------------------------------------------------------
# ANSI colour codes for console output
# ---------------------------------------------------------------------------

class _ColourFormatter(logging.Formatter):
    """Apply ANSI colour to log level names for terminal readability."""

    GREY    = "\x1b[38;5;245m"
    CYAN    = "\x1b[36m"
    YELLOW  = "\x1b[33m"
    RED     = "\x1b[31m"
    BOLD_RED = "\x1b[1;31m"
    RESET   = "\x1b[0m"

    LEVEL_COLOURS = {
        logging.DEBUG:    GREY,
        logging.INFO:     CYAN,
        logging.WARNING:  YELLOW,
        logging.ERROR:    RED,
        logging.CRITICAL: BOLD_RED,
    }

    _FMT = "[%(asctime)s] [%(levelname)-8s] [%(name)s] %(message)s"
    _DATE = "%H:%M:%S"

    def format(self, record: logging.LogRecord) -> str:
        colour = self.LEVEL_COLOURS.get(record.levelno, self.RESET)
        formatter = logging.Formatter(
            f"{colour}{self._FMT}{self.RESET}",
            datefmt=self._DATE,
        )
        return formatter.format(record)


# ---------------------------------------------------------------------------
# Public factory
# ---------------------------------------------------------------------------

_root_configured = False


def get_logger(name: str, level: int = logging.DEBUG) -> logging.Logger:
    """
    Return a logger identified by *name*.

    The root 'recon' logger is configured once on first call; subsequent calls
    just return child loggers attached to the same handlers.
    """
    global _root_configured

    root = logging.getLogger("recon")

    if not _root_configured:
        root.setLevel(logging.DEBUG)

        # -- Console handler (INFO and above, coloured) ---------------------
        ch = logging.StreamHandler()
        ch.setLevel(logging.INFO)
        ch.setFormatter(_ColourFormatter())
        root.addHandler(ch)

        # -- Rotating file handler (DEBUG and above, plain text) ------------
        os.makedirs(LOG_DIR, exist_ok=True)
        log_file = os.path.join(LOG_DIR, "recon.log")
        fh = RotatingFileHandler(
            log_file,
            maxBytes=5 * 1024 * 1024,   # 5 MB per file
            backupCount=3,
            encoding="utf-8",
        )
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(
            logging.Formatter(
                "[%(asctime)s] [%(levelname)-8s] [%(name)s] %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S",
            )
        )
        root.addHandler(fh)

        _root_configured = True

    child = root.getChild(name) if name != "recon" else root
    child.setLevel(level)
    return child
