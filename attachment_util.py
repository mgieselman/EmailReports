"""Shared utilities for extracting files from compressed email attachments."""

from __future__ import annotations

import gzip
import io
import logging
import zipfile

logger = logging.getLogger(__name__)

MAX_DECOMPRESSED_SIZE = 50 * 1024 * 1024  # 50 MB
_CHUNK_SIZE = 65536


def _safe_gzip_decompress(raw: bytes, filename: str) -> bytes | None:
    """Decompress gzip data in chunks, aborting if size limit is exceeded."""
    try:
        chunks: list[bytes] = []
        total = 0
        with gzip.GzipFile(fileobj=io.BytesIO(raw)) as gz:
            while chunk := gz.read(_CHUNK_SIZE):
                total += len(chunk)
                if total > MAX_DECOMPRESSED_SIZE:
                    logger.warning("Decompressed size exceeds limit for %s", filename)
                    return None
                chunks.append(chunk)
        return b"".join(chunks)
    except Exception:
        logger.warning("Failed to gunzip %s", filename)
        return None


def _safe_zip_read(zf: zipfile.ZipFile, entry_name: str, filename: str) -> bytes | None:
    """Read a zip entry in chunks, aborting if size limit is exceeded."""
    chunks: list[bytes] = []
    total = 0
    with zf.open(entry_name) as f:
        while chunk := f.read(_CHUNK_SIZE):
            total += len(chunk)
            if total > MAX_DECOMPRESSED_SIZE:
                logger.warning("Decompressed size exceeds limit for %s in %s", entry_name, filename)
                return None
            chunks.append(chunk)
    return b"".join(chunks)


def extract_from_attachment(
    filename: str,
    raw: bytes,
    target_extension: str,
    label: str,
) -> bytes | None:
    """Extract file content from a raw attachment.

    Handles plain files, .gz, and .zip. Returns None if the attachment
    doesn't match *target_extension* or can't be decompressed.
    """
    lower = filename.lower()
    if lower.endswith(target_extension):
        return raw
    if lower.endswith(".gz"):
        return _safe_gzip_decompress(raw, filename)
    if lower.endswith(".zip"):
        try:
            with zipfile.ZipFile(io.BytesIO(raw)) as zf:
                matches = [n for n in zf.namelist() if n.lower().endswith(target_extension)]
                if not matches:
                    logger.warning("No %s found inside zip %s", target_extension, filename)
                    return None
                return _safe_zip_read(zf, matches[0], filename)
        except Exception:
            logger.warning("Failed to unzip %s (%s)", filename, label)
            return None
    logger.debug("Skipping non-%s attachment %s", label, filename)
    return None
