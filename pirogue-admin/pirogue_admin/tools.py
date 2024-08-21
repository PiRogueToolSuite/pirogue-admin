"""
Functions that can be useful in any modules.
"""

import hashlib
from pathlib import Path


def get_size_and_digest(path: Path):
    """
    Helper function to compare file before/after, using size and one digest algorithm.
    """
    if not path.exists():
        return -1, None
    return path.stat().st_size, hashlib.file_digest(path.open('rb'), 'sha256').hexdigest()
