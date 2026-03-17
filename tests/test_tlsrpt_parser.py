"""Tests for tlsrpt_parser.py — JSON extraction and parsing."""

from __future__ import annotations

import base64
import io
import json
import zipfile
from datetime import UTC, datetime

import attachment_util
import tlsrpt_parser

# ---------------------------------------------------------------------------
# parse_attachment — format handling
# ---------------------------------------------------------------------------


class TestParseAttachmentFormats:
    def test_plain_json(self, tlsrpt_b64_json):
        report = tlsrpt_parser.parse_attachment("report.json", tlsrpt_b64_json)
        assert report is not None
        assert report.org_name == "google.com"

    def test_gzipped_json(self, tlsrpt_b64_gz):
        report = tlsrpt_parser.parse_attachment("report.json.gz", tlsrpt_b64_gz)
        assert report is not None
        assert report.org_name == "google.com"

    def test_zipped_json(self, tlsrpt_b64_zip):
        report = tlsrpt_parser.parse_attachment("report.zip", tlsrpt_b64_zip)
        assert report is not None
        assert report.org_name == "google.com"

    def test_case_insensitive_extension(self, tlsrpt_b64_json):
        report = tlsrpt_parser.parse_attachment("REPORT.JSON", tlsrpt_b64_json)
        assert report is not None

    def test_case_insensitive_gz(self, tlsrpt_b64_gz):
        report = tlsrpt_parser.parse_attachment("report.JSON.GZ", tlsrpt_b64_gz)
        assert report is not None

    def test_unsupported_extension_returns_none(self, tlsrpt_b64_json):
        result = tlsrpt_parser.parse_attachment("report.xml", tlsrpt_b64_json)
        assert result is None

    def test_corrupt_gz_returns_none(self):
        bad_gz = base64.b64encode(b"not-gzip").decode()
        result = tlsrpt_parser.parse_attachment("report.gz", bad_gz)
        assert result is None

    def test_corrupt_zip_returns_none(self):
        bad_zip = base64.b64encode(b"not-zip").decode()
        result = tlsrpt_parser.parse_attachment("report.zip", bad_zip)
        assert result is None

    def test_zip_no_json_returns_none(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("readme.txt", "no json")
        b64 = base64.b64encode(buf.getvalue()).decode()
        result = tlsrpt_parser.parse_attachment("report.zip", b64)
        assert result is None

    def test_zip_multiple_json_uses_first(self, tlsrpt_json_bytes):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("first.json", tlsrpt_json_bytes)
            zf.writestr("second.json", tlsrpt_json_bytes)
        b64 = base64.b64encode(buf.getvalue()).decode()
        report = tlsrpt_parser.parse_attachment("report.zip", b64)
        assert report is not None


# ---------------------------------------------------------------------------
# parse_attachment — JSON content (hyphenated keys)
# ---------------------------------------------------------------------------


class TestParseJsonHyphenated:
    def test_metadata(self, tlsrpt_b64_json):
        report = tlsrpt_parser.parse_attachment("r.json", tlsrpt_b64_json)
        assert report.org_name == "google.com"
        assert "gieselman.com" in report.report_id

    def test_dates(self, tlsrpt_b64_json):
        report = tlsrpt_parser.parse_attachment("r.json", tlsrpt_b64_json)
        assert report.date_begin == datetime(2024, 3, 15, tzinfo=UTC)
        assert report.date_end == datetime(2024, 3, 16, tzinfo=UTC)

    def test_policy_summary(self, tlsrpt_b64_json):
        report = tlsrpt_parser.parse_attachment("r.json", tlsrpt_b64_json)
        assert len(report.policies) == 1
        pol = report.policies[0]
        assert pol.policy_type == "sts"
        assert pol.policy_domain == "gieselman.com"
        assert pol.successful_session_count == 485
        assert pol.failed_session_count == 2

    def test_failure_details(self, tlsrpt_b64_json):
        report = tlsrpt_parser.parse_attachment("r.json", tlsrpt_b64_json)
        fd = report.policies[0].failure_details[0]
        assert fd.result_type == "certificate-expired"
        assert fd.sending_mta_ip == "209.85.220.41"
        assert fd.receiving_mx_hostname == "mail.gieselman.com"
        assert fd.failed_session_count == 2
        assert fd.failure_reason_code == "Certificate has expired"

    def test_totals(self, tlsrpt_b64_json):
        report = tlsrpt_parser.parse_attachment("r.json", tlsrpt_b64_json)
        assert report.total_successful == 485
        assert report.total_failures == 2


# ---------------------------------------------------------------------------
# parse_attachment — underscore keys (some providers use these)
# ---------------------------------------------------------------------------


class TestParseJsonUnderscore:
    def test_underscore_keys_parsed(self, tlsrpt_underscore_json_bytes):
        b64 = base64.b64encode(tlsrpt_underscore_json_bytes).decode()
        report = tlsrpt_parser.parse_attachment("r.json", b64)
        assert report.org_name == "proofpoint.com"
        assert report.total_successful == 100
        assert report.total_failures == 15

    def test_underscore_failure_details(self, tlsrpt_underscore_json_bytes):
        b64 = base64.b64encode(tlsrpt_underscore_json_bytes).decode()
        report = tlsrpt_parser.parse_attachment("r.json", b64)
        fd = report.policies[0].failure_details[0]
        assert fd.result_type == "starttls-not-supported"
        assert fd.failed_session_count == 15

    def test_underscore_dates(self, tlsrpt_underscore_json_bytes):
        b64 = base64.b64encode(tlsrpt_underscore_json_bytes).decode()
        report = tlsrpt_parser.parse_attachment("r.json", b64)
        assert report.date_begin.year == 2024
        assert report.date_begin.month == 3


# ---------------------------------------------------------------------------
# No failures report
# ---------------------------------------------------------------------------


class TestNoFailures:
    def test_no_failures(self, tlsrpt_no_failures_json_bytes):
        b64 = base64.b64encode(tlsrpt_no_failures_json_bytes).decode()
        report = tlsrpt_parser.parse_attachment("r.json", b64)
        assert report.org_name == "microsoft.com"
        assert report.total_failures == 0
        assert report.total_successful == 200
        assert report.policies[0].failure_details == []


# ---------------------------------------------------------------------------
# Timestamp parsing edge cases
# ---------------------------------------------------------------------------


class TestTimestampParsing:
    def test_empty_string(self):
        result = tlsrpt_parser._parse_ts("")
        assert result == datetime(1970, 1, 1, tzinfo=UTC)

    def test_iso_format_z(self):
        result = tlsrpt_parser._parse_ts("2024-03-15T00:00:00Z")
        assert result.year == 2024
        assert result.month == 3

    def test_date_only(self):
        result = tlsrpt_parser._parse_ts("2024-03-15")
        assert result.year == 2024

    def test_invalid_returns_epoch(self):
        result = tlsrpt_parser._parse_ts("not-a-date")
        assert result == datetime(1970, 1, 1, tzinfo=UTC)


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


class TestEdgeCases:
    def test_empty_policies(self):
        doc = json.dumps({"organization-name": "test", "report-id": "1", "date-range": {}, "policies": []})
        b64 = base64.b64encode(doc.encode()).decode()
        report = tlsrpt_parser.parse_attachment("r.json", b64)
        assert report.policies == []
        assert report.total_failures == 0
        assert report.total_successful == 0

    def test_missing_all_optional_fields(self):
        doc = json.dumps({})
        b64 = base64.b64encode(doc.encode()).decode()
        report = tlsrpt_parser.parse_attachment("r.json", b64)
        assert report.org_name == ""
        assert report.policies == []

    def test_oversized_gz_rejected(self, tlsrpt_json_bytes, monkeypatch):
        import gzip

        monkeypatch.setattr(attachment_util, "MAX_DECOMPRESSED_SIZE", 10)
        gz_data = gzip.compress(tlsrpt_json_bytes)
        b64 = base64.b64encode(gz_data).decode()
        result = tlsrpt_parser.parse_attachment("report.json.gz", b64)
        assert result is None

    def test_oversized_zip_entry_rejected(self, tlsrpt_json_bytes, monkeypatch):
        monkeypatch.setattr(attachment_util, "MAX_DECOMPRESSED_SIZE", 10)
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("report.json", tlsrpt_json_bytes)
        b64 = base64.b64encode(buf.getvalue()).decode()
        result = tlsrpt_parser.parse_attachment("report.zip", b64)
        assert result is None

    def test_tz_aware_timestamp_preserved(self):
        result = tlsrpt_parser._parse_ts("2024-03-15T05:00:00+05:00")
        assert result.hour == 0  # 05:00+05:00 = 00:00 UTC
