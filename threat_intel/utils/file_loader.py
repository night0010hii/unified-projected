# =============================================================================
# utils/file_loader.py — Reads local feed files and returns their content
#                          together with format metadata.
# =============================================================================

import logging
import os
from typing import List, Optional

logger = logging.getLogger(__name__)

# Map file extension → format string expected by the parser
_EXT_FORMAT_MAP = {
    ".txt":  "txt",
    ".csv":  "csv",
    ".json": "json",
}


def _detect_format(filepath: str) -> str:
    """Infer feed format from file extension (default: txt)."""
    _, ext = os.path.splitext(filepath)
    return _EXT_FORMAT_MAP.get(ext.lower(), "txt")


def load_file(filepath: str) -> Optional[dict]:
    """
    Read a single local file and return a feed dict.

    Returns:
        {source, format, raw_text}  or  None on error.
    """
    if not os.path.isfile(filepath):
        logger.warning(f"[file_loader] File not found: {filepath}")
        return None
    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as fh:
            raw_text = fh.read()
        source = os.path.basename(filepath)
        fmt    = _detect_format(filepath)
        logger.info(
            f"[file_loader] Loaded '{source}' "
            f"({len(raw_text)} chars, format={fmt})"
        )
        return {"source": source, "format": fmt, "raw_text": raw_text}
    except OSError as exc:
        logger.error(f"[file_loader] Cannot read '{filepath}': {exc}")
        return None


def load_all_local_feeds(filepaths: List[str]) -> List[dict]:
    """
    Load every file in *filepaths*; skip files that cannot be read.

    Returns:
        List of feed dicts {source, format, raw_text}.
    """
    feeds = []
    for fp in filepaths:
        feed = load_file(fp)
        if feed:
            feeds.append(feed)
    logger.info(f"[file_loader] {len(feeds)}/{len(filepaths)} local feeds loaded")
    return feeds
