"""Content hashing utilities for scan result caching.

Provides SHA-256 based hashing for file content and cache key computation.
"""

import hashlib


def compute_content_hash(content: str) -> str:
    """Compute SHA-256 hex digest of content.

    Args:
        content: The file content to hash.

    Returns:
        Hex string of the SHA-256 digest.
    """
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def compute_cache_key(content: str, scanner_names: list[str], version: str) -> str:
    """Compute a cache key from content, scanner names, and version.

    The key is a SHA-256 digest of the content concatenated with sorted
    scanner names and the validator version. This ensures cache invalidation
    when content changes, scanners change, or the validator is upgraded.

    Args:
        content: The file content to include in the key.
        scanner_names: List of scanner module names applied to this content.
        version: The validator version string.

    Returns:
        Hex string of the SHA-256 cache key.
    """
    sorted_scanners = sorted(scanner_names)
    key_material = content + "\x00" + "\x00".join(sorted_scanners) + "\x00" + version
    return hashlib.sha256(key_material.encode("utf-8")).hexdigest()
