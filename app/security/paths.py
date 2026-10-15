"""Path canonicalization, directory traversal, and symlink defenses.

Prevents:
- Directory traversal attacks (../, ..\\, URL-encoded %2e%2e, Unicode dot lookalikes)
- Null byte injection (\x00, %00)
- Absolute path escaping
- Symlink dereferencing outside allowed root directory
- Access to sensitive files (*.env, *.pem, id_rsa*, *secret*, etc.)
"""

from __future__ import annotations

import fnmatch
import os
import pathlib
import urllib.parse
from typing import List, Optional, Tuple

DEFAULT_DENIED_PATTERNS = [
    "*.env*",
    "*.pem",
    "*.key",
    "*.crt",
    "id_rsa*",
    "id_ed25519*",
    "*secret*",
    "*credential*",
    "*password*",
    "*.sqlite*",
    "*.db",
    "/etc/*",
    "/proc/*",
    "/sys/*",
    "C:\\Windows\\*",
]


def sanitize_raw_path(raw_path: str, max_depth: int = 5) -> str:
    """Pre-cleans raw path string by unquoting iteratively and stripping null bytes."""
    current = raw_path
    for _ in range(max_depth):
        if "\x00" in current or "%00" in current.lower():
            raise ValueError("NULL_BYTE_IN_PATH")
        unquoted = urllib.parse.unquote(current)
        if unquoted == current:
            break
        current = unquoted

    if "\x00" in current or "%00" in current.lower():
        raise ValueError("NULL_BYTE_IN_PATH")

    return current.strip()


def validate_file_path(
    path_str: str,
    allowed_base_dirs: List[str],
    denied_patterns: Optional[List[str]] = None,
    allow_symlinks: bool = False,
    max_size_kb: Optional[int] = None,
) -> Tuple[bool, Optional[str], str]:
    """Canonicalizes and validates a requested file path against security policies.

    Returns:
        (is_safe: bool, canonical_path_str: Optional[str], reason_code: str)
    """
    if not path_str or not isinstance(path_str, str):
        return False, None, "EMPTY_PATH"

    try:
        cleaned_path = sanitize_raw_path(path_str)
    except ValueError as e:
        return False, None, str(e)

    # Convert to Path object
    target_path = pathlib.Path(cleaned_path)

    # 1. Resolve canonical base directories
    canonical_allowed_bases: List[pathlib.Path] = []
    for base in allowed_base_dirs:
        try:
            base_p = pathlib.Path(base).resolve()
            canonical_allowed_bases.append(base_p)
        except (OSError, ValueError):
            pass

    if not canonical_allowed_bases:
        return False, None, "NO_VALID_ALLOWED_BASE_DIRECTORIES"

    # 2. Determine candidate path
    if not target_path.is_absolute():
        candidate_path = canonical_allowed_bases[0] / target_path
    else:
        candidate_path = target_path

    # 3. Check for symlink dereference outside allowed boundary
    if not allow_symlinks and (candidate_path.is_symlink() or os.path.islink(cleaned_path)):
        return False, None, "SYMLINK_ACCESS_DENIED"

    # Resolve target candidate
    resolved_candidate = candidate_path.resolve()

    # 4. Containment Check: Verify resolved path is strictly inside at least one allowed base dir
    is_contained = False
    for base_p in canonical_allowed_bases:
        try:
            resolved_candidate.relative_to(base_p)
            is_contained = True
            break
        except ValueError:
            continue

    if not is_contained:
        return False, None, "PATH_TRAVERSAL_OUTSIDE_ALLOWED_ROOT"

    # 5. Check against denied glob patterns
    patterns_to_check = (denied_patterns or []) + DEFAULT_DENIED_PATTERNS
    file_name = resolved_candidate.name.lower()
    full_path_str = str(resolved_candidate).lower()

    for pattern in patterns_to_check:
        pat = pattern.lower()
        if fnmatch.fnmatch(file_name, pat) or fnmatch.fnmatch(full_path_str, pat):
            return False, None, f"DENIED_PATTERN_MATCH_{pattern}"

    # 6. File size check if file exists
    if max_size_kb is not None and resolved_candidate.exists() and resolved_candidate.is_file():
        size_bytes = resolved_candidate.stat().st_size
        if size_bytes > (max_size_kb * 1024):
            return False, None, f"FILE_SIZE_EXCEEDS_LIMIT_{size_bytes}_BYTES"

    return True, str(resolved_candidate), "PATH_VALIDATED_SAFE"


def is_safe_path(
    path_str: str,
    allowed_dirs: Optional[List[str]] = None,
    denied_patterns: Optional[List[str]] = None,
) -> Tuple[bool, str]:
    """Convenience validator returning (is_safe, reason)."""
    base_dirs = allowed_dirs or ["/workspace", "."]
    is_valid, _, reason = validate_file_path(
        path_str=path_str,
        allowed_base_dirs=base_dirs,
        denied_patterns=denied_patterns,
    )
    return is_valid, reason
