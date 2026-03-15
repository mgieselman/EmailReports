"""Tests for dmarc_parser.py — XML extraction and parsing."""

from __future__ import annotations

import base64
import io
import zipfile

import dmarc_parser
from models import DmarcDisposition, DmarcResult

# ---------------------------------------------------------------------------
# parse_attachment — format handling
# ---------------------------------------------------------------------------


class TestParseAttachmentFormats:
    def test_plain_xml(self, dmarc_b64_xml):
        report = dmarc_parser.parse_attachment("report.xml", dmarc_b64_xml)
        assert report is not None
        assert report.org_name == "google.com"

    def test_gzipped_xml(self, dmarc_b64_gz):
        report = dmarc_parser.parse_attachment("report.xml.gz", dmarc_b64_gz)
        assert report is not None
        assert report.org_name == "google.com"

    def test_zipped_xml(self, dmarc_b64_zip):
        report = dmarc_parser.parse_attachment("report.zip", dmarc_b64_zip)
        assert report is not None
        assert report.org_name == "google.com"

    def test_case_insensitive_extension(self, dmarc_b64_xml):
        report = dmarc_parser.parse_attachment("REPORT.XML", dmarc_b64_xml)
        assert report is not None

    def test_case_insensitive_gz(self, dmarc_b64_gz):
        report = dmarc_parser.parse_attachment("report.XML.GZ", dmarc_b64_gz)
        assert report is not None

    def test_case_insensitive_zip(self, dmarc_b64_zip):
        report = dmarc_parser.parse_attachment("report.ZIP", dmarc_b64_zip)
        assert report is not None

    def test_unsupported_extension_returns_none(self, dmarc_b64_xml):
        result = dmarc_parser.parse_attachment("report.pdf", dmarc_b64_xml)
        assert result is None

    def test_corrupt_gz_returns_none(self):
        bad_gz = base64.b64encode(b"not-gzip-data").decode()
        result = dmarc_parser.parse_attachment("report.gz", bad_gz)
        assert result is None

    def test_corrupt_zip_returns_none(self):
        bad_zip = base64.b64encode(b"not-zip-data").decode()
        result = dmarc_parser.parse_attachment("report.zip", bad_zip)
        assert result is None

    def test_zip_with_no_xml_returns_none(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("readme.txt", "no xml here")
        b64 = base64.b64encode(buf.getvalue()).decode()
        result = dmarc_parser.parse_attachment("report.zip", b64)
        assert result is None

    def test_zip_multiple_xml_uses_first(self, dmarc_xml_bytes):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("first.xml", dmarc_xml_bytes)
            zf.writestr("second.xml", dmarc_xml_bytes)
        b64 = base64.b64encode(buf.getvalue()).decode()
        report = dmarc_parser.parse_attachment("report.zip", b64)
        assert report is not None


# ---------------------------------------------------------------------------
# parse_attachment — XML content parsing
# ---------------------------------------------------------------------------


class TestParseXmlContent:
    def test_full_report_metadata(self, dmarc_b64_xml):
        report = dmarc_parser.parse_attachment("r.xml", dmarc_b64_xml)
        assert report.org_name == "google.com"
        assert report.report_id == "12345678901234567890"
        assert report.domain == "gieselman.com"
        assert report.policy == DmarcDisposition.REJECT

    def test_full_report_dates(self, dmarc_b64_xml):
        report = dmarc_parser.parse_attachment("r.xml", dmarc_b64_xml)
        assert report.date_begin.year == 2024
        assert report.date_begin.month == 3
        assert report.date_begin.day == 15

    def test_full_report_records(self, dmarc_b64_xml):
        report = dmarc_parser.parse_attachment("r.xml", dmarc_b64_xml)
        assert len(report.records) == 2

    def test_passing_record(self, dmarc_b64_xml):
        report = dmarc_parser.parse_attachment("r.xml", dmarc_b64_xml)
        passing = [r for r in report.records if r.source_ip == "209.85.220.41"][0]
        assert passing.count == 150
        assert passing.dkim_result == DmarcResult.PASS
        assert passing.spf_result == DmarcResult.PASS
        assert passing.disposition == DmarcDisposition.NONE
        assert passing.header_from == "gieselman.com"
        assert passing.envelope_from == "gieselman.com"
        assert passing.dkim_domain == "gieselman.com"
        assert passing.spf_domain == "gieselman.com"

    def test_failing_record(self, dmarc_b64_xml):
        report = dmarc_parser.parse_attachment("r.xml", dmarc_b64_xml)
        failing = [r for r in report.records if r.source_ip == "185.99.99.1"][0]
        assert failing.count == 3
        assert failing.dkim_result == DmarcResult.FAIL
        assert failing.spf_result == DmarcResult.FAIL
        assert failing.disposition == DmarcDisposition.REJECT
        assert failing.envelope_from == "spoofed.example.com"

    def test_total_messages(self, dmarc_b64_xml):
        report = dmarc_parser.parse_attachment("r.xml", dmarc_b64_xml)
        assert report.total_messages == 153

    def test_failing_records_property(self, dmarc_b64_xml):
        report = dmarc_parser.parse_attachment("r.xml", dmarc_b64_xml)
        assert len(report.failing_records) == 1
        assert report.failing_records[0].source_ip == "185.99.99.1"


class TestParseMinimalXml:
    def test_no_records(self, dmarc_minimal_xml_bytes):
        b64 = base64.b64encode(dmarc_minimal_xml_bytes).decode()
        report = dmarc_parser.parse_attachment("r.xml", b64)
        assert report is not None
        assert report.org_name == "yahoo.com"
        assert report.records == []
        assert report.total_messages == 0
        assert report.policy == DmarcDisposition.NONE


class TestParseMultiAuthXml:
    def test_multi_auth_results(self, dmarc_multi_auth_xml_bytes):
        b64 = base64.b64encode(dmarc_multi_auth_xml_bytes).decode()
        report = dmarc_parser.parse_attachment("r.xml", b64)
        assert report is not None
        assert len(report.records) == 2
        assert report.policy == DmarcDisposition.QUARANTINE

    def test_record_without_auth_results(self, dmarc_multi_auth_xml_bytes):
        """Second record in multi_auth has no auth_results."""
        b64 = base64.b64encode(dmarc_multi_auth_xml_bytes).decode()
        report = dmarc_parser.parse_attachment("r.xml", b64)
        no_auth = [r for r in report.records if r.source_ip == "10.0.0.1"][0]
        assert no_auth.dkim_domain == ""
        assert no_auth.spf_domain == ""

    def test_mixed_dkim_spf(self, dmarc_multi_auth_xml_bytes):
        b64 = base64.b64encode(dmarc_multi_auth_xml_bytes).decode()
        report = dmarc_parser.parse_attachment("r.xml", b64)
        mixed = [r for r in report.records if r.source_ip == "40.107.22.55"][0]
        assert mixed.dkim_result == DmarcResult.PASS
        assert mixed.spf_result == DmarcResult.FAIL
        # Should not be in failing_records (needs BOTH to fail)
        assert mixed not in report.failing_records


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


class TestEdgeCases:
    def test_missing_row_element_skipped(self):
        """A <record> with no <row> child should be skipped."""
        xml = b"""\
        <feedback>
          <report_metadata>
            <org_name>test</org_name>
            <report_id>1</report_id>
            <date_range><begin>0</begin><end>0</end></date_range>
          </report_metadata>
          <policy_published><domain>test.com</domain><p>none</p></policy_published>
          <record><identifiers><header_from>test.com</header_from></identifiers></record>
        </feedback>"""
        b64 = base64.b64encode(xml).decode()
        report = dmarc_parser.parse_attachment("r.xml", b64)
        assert report.records == []

    def test_whitespace_in_text_stripped(self):
        xml = b"""\
        <feedback>
          <report_metadata>
            <org_name>  google.com  </org_name>
            <report_id>  ws-test  </report_id>
            <date_range><begin>0</begin><end>0</end></date_range>
          </report_metadata>
          <policy_published><domain>  test.com  </domain><p>none</p></policy_published>
        </feedback>"""
        b64 = base64.b64encode(xml).decode()
        report = dmarc_parser.parse_attachment("r.xml", b64)
        assert report.org_name == "google.com"
        assert report.domain == "test.com"
        assert report.report_id == "ws-test"

    def test_text_helper_with_none_parent(self):
        result = dmarc_parser._text(None, "tag", "default")
        assert result == "default"
