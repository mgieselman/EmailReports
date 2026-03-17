"""Shared utilities for extracting files from compressed email attachments."""

from __future__ import annotations

import gzip
import io
import logging
import zipfile

logger = logging.getLogger(__name__)

MAX_DECOMPRESSED_SIZE = 50 * 1024 * 1024  # 50 MB


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
        try:
            data = gzip.decompress(raw)
            if len(data) > MAX_DECOMPRESSED_SIZE:
                logger.warning("Decompressed size exceeds limit for %s", filename)
                return None
            return data
        except Exception:
            logger.warning("Failed to gunzip %s (%s)", filename, label)
            return None
    if lower.endswith(".zip"):
        try:
            with zipfile.ZipFile(io.BytesIO(raw)) as zf:
                matches = [n for n in zf.namelist() if n.lower().endswith(target_extension)]
                if not matches:
                    logger.warning("No %s found inside zip %s", target_extension, filename)
                    return None
                info = zf.getinfo(matches[0])
                if info.file_size > MAX_DECOMPRESSED_SIZE:
                    logger.warning("Decompressed size exceeds limit for %s in %s", matches[0], filename)
                    return None
                return zf.read(matches[0])
        except Exception:
            logger.warning("Failed to unzip %s (%s)", filename, label)
            return None
    logger.debug("Skipping non-%s attachment %s", label, filename)
    return None
