"""Shared check for directory entries that must not be followed while walking."""

from __future__ import annotations

import os
import stat
from pathlib import Path


def is_reparse_point(entry: os.DirEntry[str] | Path) -> bool:
    """Symlink or junction (or any other reparse point) at ``entry`` itself."""
    if entry.is_symlink():
        return True
    attributes: object = getattr(entry.stat(follow_symlinks=False), "st_file_attributes", None)
    if isinstance(attributes, int):
        return bool(attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT)
    isjunction: object = getattr(os.path, "isjunction", None)  # Python 3.12+
    path = str(entry) if isinstance(entry, Path) else entry.path
    return bool(isjunction(path)) if callable(isjunction) else False
