"""Tests for attachment_util.py — shared extraction logic."""

from __future__ import annotations

import gzip
import io
import zipfile

import attachment_util


class TestExtractFromAttachment:
    def test_plain_file(self):
        data = b"<xml>content</xml>"
        result = attachment_util.extract_from_attachment("report.xml", data, ".xml", "DMARC")
        assert result == data

    def test_gzipped_file(self):
        data = b"<xml>content</xml>"
        gz = gzip.compress(data)
        result = attachment_util.extract_from_attachment("report.xml.gz", gz, ".xml", "DMARC")
        assert result == data

    def test_zipped_file(self):
        data = b"<xml>content</xml>"
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("inner.xml", data)
        result = attachment_util.extract_from_attachment("report.zip", buf.getvalue(), ".xml", "DMARC")
        assert result == data

    def test_case_insensitive(self):
        data = b"content"
        result = attachment_util.extract_from_attachment("REPORT.XML", data, ".xml", "DMARC")
        assert result == data

    def test_unsupported_extension_returns_none(self):
        result = attachment_util.extract_from_attachment("report.pdf", b"data", ".xml", "DMARC")
        assert result is None

    def test_corrupt_gz_returns_none(self):
        result = attachment_util.extract_from_attachment("report.gz", b"bad", ".xml", "DMARC")
        assert result is None

    def test_corrupt_zip_returns_none(self):
        result = attachment_util.extract_from_attachment("report.zip", b"bad", ".xml", "DMARC")
        assert result is None

    def test_zip_no_matching_file_returns_none(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("readme.txt", "no match")
        result = attachment_util.extract_from_attachment("report.zip", buf.getvalue(), ".xml", "DMARC")
        assert result is None

    def test_oversized_gz_rejected(self, monkeypatch):
        monkeypatch.setattr(attachment_util, "MAX_DECOMPRESSED_SIZE", 10)
        data = gzip.compress(b"x" * 100)
        result = attachment_util.extract_from_attachment("report.gz", data, ".xml", "DMARC")
        assert result is None

    def test_oversized_zip_rejected(self, monkeypatch):
        monkeypatch.setattr(attachment_util, "MAX_DECOMPRESSED_SIZE", 10)
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("inner.xml", b"x" * 100)
        result = attachment_util.extract_from_attachment("report.zip", buf.getvalue(), ".xml", "DMARC")
        assert result is None
