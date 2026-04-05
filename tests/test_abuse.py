"""Tests for abuse.py — automated abuse reporting."""

from __future__ import annotations

import base64
from datetime import UTC, datetime
from unittest.mock import MagicMock, patch

import pytest

import abuse
from models import (
    AbuseReportRecord,
    DmarcDisposition,
    DmarcRecord,
    DmarcReport,
    DmarcResult,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _dmarc_record(
    source_ip: str = "74.208.4.196",
    count: int = 1,
    disposition: DmarcDisposition = DmarcDisposition.REJECT,
    dkim: DmarcResult = DmarcResult.FAIL,
    spf: DmarcResult = DmarcResult.FAIL,
    header_from: str = "gieselman.com",
) -> DmarcRecord:
    return DmarcRecord(
        source_ip=source_ip,
        count=count,
        disposition=disposition,
        dkim_result=dkim,
        spf_result=spf,
        header_from=header_from,
    )


def _dmarc_report(
    records: list[DmarcRecord] | None = None,
    domain: str = "gieselman.com",
) -> DmarcReport:
    return DmarcReport(
        org_name="Yahoo",
        report_id="test-123",
        date_begin=datetime(2026, 4, 2, tzinfo=UTC),
        date_end=datetime(2026, 4, 3, tzinfo=UTC),
        domain=domain,
        policy=DmarcDisposition.REJECT,
        records=[_dmarc_record()] if records is None else records,
    )


# ---------------------------------------------------------------------------
# Tests: is_abuse_reporting_enabled
# ---------------------------------------------------------------------------


class TestIsAbuseReportingEnabled:
    def test_default_disabled(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("ABUSE_REPORTING_ENABLED", raising=False)
        assert abuse.is_abuse_reporting_enabled() is False

    def test_false_string(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("ABUSE_REPORTING_ENABLED", "false")
        assert abuse.is_abuse_reporting_enabled() is False

    def test_true_string(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("ABUSE_REPORTING_ENABLED", "true")
        assert abuse.is_abuse_reporting_enabled() is True

    def test_true_uppercase(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("ABUSE_REPORTING_ENABLED", "True")
        assert abuse.is_abuse_reporting_enabled() is True


# ---------------------------------------------------------------------------
# Tests: find_spoofing_records
# ---------------------------------------------------------------------------


class TestFindSpoofingRecords:
    def test_finds_spoofing(self) -> None:
        rec = _dmarc_record()
        report = _dmarc_report(records=[rec])
        assert abuse.find_spoofing_records(report) == [rec]

    def test_excludes_passing_dkim(self) -> None:
        rec = _dmarc_record(dkim=DmarcResult.PASS)
        report = _dmarc_report(records=[rec])
        assert abuse.find_spoofing_records(report) == []

    def test_excludes_passing_spf(self) -> None:
        rec = _dmarc_record(spf=DmarcResult.PASS)
        report = _dmarc_report(records=[rec])
        assert abuse.find_spoofing_records(report) == []

    def test_excludes_non_reject_disposition(self) -> None:
        rec = _dmarc_record(disposition=DmarcDisposition.QUARANTINE)
        report = _dmarc_report(records=[rec])
        assert abuse.find_spoofing_records(report) == []

    def test_excludes_none_disposition(self) -> None:
        rec = _dmarc_record(disposition=DmarcDisposition.NONE)
        report = _dmarc_report(records=[rec])
        assert abuse.find_spoofing_records(report) == []

    def test_mixed_records(self) -> None:
        spoofing = _dmarc_record(source_ip="1.2.3.4")
        passing = _dmarc_record(source_ip="5.6.7.8", dkim=DmarcResult.PASS)
        report = _dmarc_report(records=[spoofing, passing])
        result = abuse.find_spoofing_records(report)
        assert len(result) == 1
        assert result[0].source_ip == "1.2.3.4"

    def test_empty_records(self) -> None:
        report = _dmarc_report(records=[])
        assert abuse.find_spoofing_records(report) == []


# ---------------------------------------------------------------------------
# Tests: send_abuse_reports
# ---------------------------------------------------------------------------


class TestSendAbuseReports:
    @patch("abuse.storage")
    @patch("abuse.rdap")
    def test_sends_two_emails_per_ip(self, mock_rdap: MagicMock, mock_storage: MagicMock) -> None:
        mock_storage.abuse_report_exists.return_value = False
        mock_rdap.lookup_abuse_contact.return_value = "abuse@ionos.com"
        mock_graph = MagicMock()

        report = _dmarc_report()
        result = abuse.send_abuse_reports(report, "report.xml", "dGVzdA==", mock_graph)

        assert result == 1
        assert mock_graph.send_mail.call_count == 2
        # First call: plain-text email
        first_call = mock_graph.send_mail.call_args_list[0]
        assert first_call[0][0] == "postmaster@gieselman.com"
        assert first_call[0][1] == "abuse@ionos.com"
        assert "Abuse Report:" in first_call[0][2]
        # Second call: ARF email
        second_call = mock_graph.send_mail.call_args_list[1]
        assert "[ARF]" in second_call[0][2]

    @patch("abuse.storage")
    @patch("abuse.rdap")
    def test_no_spoofing_records_returns_zero(self, mock_rdap: MagicMock, mock_storage: MagicMock) -> None:
        mock_graph = MagicMock()
        report = _dmarc_report(records=[_dmarc_record(dkim=DmarcResult.PASS)])
        result = abuse.send_abuse_reports(report, "report.xml", "dGVzdA==", mock_graph)
        assert result == 0
        mock_graph.send_mail.assert_not_called()

    @patch("abuse.storage")
    @patch("abuse.rdap")
    def test_skips_already_reported_ip(self, mock_rdap: MagicMock, mock_storage: MagicMock) -> None:
        mock_storage.abuse_report_exists.return_value = True
        mock_graph = MagicMock()

        report = _dmarc_report()
        result = abuse.send_abuse_reports(report, "report.xml", "dGVzdA==", mock_graph)

        assert result == 0
        mock_graph.send_mail.assert_not_called()

    @patch("abuse.storage")
    @patch("abuse.rdap")
    def test_skips_private_ip(self, mock_rdap: MagicMock, mock_storage: MagicMock) -> None:
        mock_storage.abuse_report_exists.return_value = False
        mock_rdap.lookup_abuse_contact.return_value = None
        mock_graph = MagicMock()
        rec = _dmarc_record(source_ip="192.168.1.1")
        report = _dmarc_report(records=[rec])
        result = abuse.send_abuse_reports(report, "report.xml", "dGVzdA==", mock_graph)
        assert result == 0
        mock_graph.send_mail.assert_not_called()

    @patch("abuse.storage")
    @patch("abuse.rdap")
    def test_skips_loopback_ip(self, mock_rdap: MagicMock, mock_storage: MagicMock) -> None:
        mock_storage.abuse_report_exists.return_value = False
        mock_rdap.lookup_abuse_contact.return_value = None
        mock_graph = MagicMock()
        rec = _dmarc_record(source_ip="127.0.0.1")
        report = _dmarc_report(records=[rec])
        result = abuse.send_abuse_reports(report, "report.xml", "dGVzdA==", mock_graph)
        assert result == 0

    @patch("abuse.storage")
    @patch("abuse.rdap")
    def test_skips_when_no_abuse_contact(self, mock_rdap: MagicMock, mock_storage: MagicMock) -> None:
        mock_storage.abuse_report_exists.return_value = False
        mock_rdap.lookup_abuse_contact.return_value = None
        mock_graph = MagicMock()

        report = _dmarc_report()
        result = abuse.send_abuse_reports(report, "report.xml", "dGVzdA==", mock_graph)

        assert result == 0
        mock_graph.send_mail.assert_not_called()

    @patch("abuse.storage")
    @patch("abuse.rdap")
    def test_saves_abuse_report_record(self, mock_rdap: MagicMock, mock_storage: MagicMock) -> None:
        mock_storage.abuse_report_exists.return_value = False
        mock_rdap.lookup_abuse_contact.return_value = "abuse@example.com"
        mock_graph = MagicMock()

        report = _dmarc_report()
        abuse.send_abuse_reports(report, "report.xml", "dGVzdA==", mock_graph)

        mock_storage.save_abuse_report.assert_called_once()
        saved = mock_storage.save_abuse_report.call_args[0][0]
        assert isinstance(saved, AbuseReportRecord)
        assert saved.source_ip == "74.208.4.196"
        assert saved.abuse_email == "abuse@example.com"
        assert saved.domain == "gieselman.com"
        assert saved.report_count == 1

    @patch("abuse.storage")
    @patch("abuse.rdap")
    def test_aggregates_count_for_same_ip(self, mock_rdap: MagicMock, mock_storage: MagicMock) -> None:
        mock_storage.abuse_report_exists.return_value = False
        mock_rdap.lookup_abuse_contact.return_value = "abuse@example.com"
        mock_graph = MagicMock()

        rec1 = _dmarc_record(source_ip="1.2.3.4", count=3)
        rec2 = _dmarc_record(source_ip="1.2.3.4", count=5)
        report = _dmarc_report(records=[rec1, rec2])
        abuse.send_abuse_reports(report, "report.xml", "dGVzdA==", mock_graph)

        saved = mock_storage.save_abuse_report.call_args[0][0]
        assert saved.report_count == 8

    @patch("abuse.storage")
    @patch("abuse.rdap")
    def test_multiple_ips(self, mock_rdap: MagicMock, mock_storage: MagicMock) -> None:
        mock_storage.abuse_report_exists.return_value = False
        mock_rdap.lookup_abuse_contact.return_value = "abuse@example.com"
        mock_graph = MagicMock()

        rec1 = _dmarc_record(source_ip="1.2.3.4")
        rec2 = _dmarc_record(source_ip="5.6.7.8")
        report = _dmarc_report(records=[rec1, rec2])
        result = abuse.send_abuse_reports(report, "report.xml", "dGVzdA==", mock_graph)

        assert result == 2
        assert mock_graph.send_mail.call_count == 4  # 2 emails per IP

    @patch("abuse.storage")
    @patch("abuse.rdap")
    def test_per_ip_error_does_not_stop_others(self, mock_rdap: MagicMock, mock_storage: MagicMock) -> None:
        mock_storage.abuse_report_exists.return_value = False
        # First IP lookup succeeds, second fails
        mock_rdap.lookup_abuse_contact.side_effect = ["abuse@example.com", Exception("boom")]
        mock_graph = MagicMock()

        rec1 = _dmarc_record(source_ip="1.2.3.4")
        rec2 = _dmarc_record(source_ip="5.6.7.8")
        report = _dmarc_report(records=[rec1, rec2])
        result = abuse.send_abuse_reports(report, "report.xml", "dGVzdA==", mock_graph)

        assert result == 1  # First IP succeeded

    @patch("abuse.storage")
    @patch("abuse.rdap")
    def test_invalid_source_ip_skipped(self, mock_rdap: MagicMock, mock_storage: MagicMock) -> None:
        mock_storage.abuse_report_exists.return_value = False
        mock_rdap.lookup_abuse_contact.return_value = None
        mock_graph = MagicMock()
        rec = _dmarc_record(source_ip="not-an-ip")
        report = _dmarc_report(records=[rec])
        result = abuse.send_abuse_reports(report, "report.xml", "dGVzdA==", mock_graph)
        assert result == 0

    @patch("abuse.storage")
    @patch("abuse.rdap")
    def test_plain_email_includes_xml_attachment(self, mock_rdap: MagicMock, mock_storage: MagicMock) -> None:
        mock_storage.abuse_report_exists.return_value = False
        mock_rdap.lookup_abuse_contact.return_value = "abuse@example.com"
        mock_graph = MagicMock()

        report = _dmarc_report()
        abuse.send_abuse_reports(report, "report.xml.gz", "dGVzdA==", mock_graph)

        first_call = mock_graph.send_mail.call_args_list[0]
        attachments = first_call[1].get("attachments") or first_call[0][4] if len(first_call[0]) > 4 else None
        # Check keyword arg
        if attachments is None:
            attachments = first_call.kwargs.get("attachments")
        assert any(a["name"] == "report.xml.gz" for a in attachments)

    @patch("abuse.storage")
    @patch("abuse.rdap")
    def test_arf_email_includes_both_attachments(self, mock_rdap: MagicMock, mock_storage: MagicMock) -> None:
        mock_storage.abuse_report_exists.return_value = False
        mock_rdap.lookup_abuse_contact.return_value = "abuse@example.com"
        mock_graph = MagicMock()

        report = _dmarc_report()
        abuse.send_abuse_reports(report, "report.xml", "dGVzdA==", mock_graph)

        second_call = mock_graph.send_mail.call_args_list[1]
        attachments = second_call.kwargs.get("attachments")
        assert len(attachments) == 2
        names = {a["name"] for a in attachments}
        assert "report.xml" in names
        assert "abuse-report-74.208.4.196.eml" in names


# ---------------------------------------------------------------------------
# Tests: _render_plain_report
# ---------------------------------------------------------------------------


class TestRenderPlainReport:
    def test_renders_template(self) -> None:
        report = _dmarc_report()
        html = abuse._render_plain_report(report, "74.208.4.196", 1, "2026-04-02 to 2026-04-03")
        assert "74.208.4.196" in html
        assert "gieselman.com" in html
        assert "Yahoo" in html
        assert "test-123" in html

    def test_includes_message_count(self) -> None:
        report = _dmarc_report()
        html = abuse._render_plain_report(report, "1.2.3.4", 5, "2026-04-02 to 2026-04-03")
        assert "5" in html


# ---------------------------------------------------------------------------
# Tests: _build_arf_message
# ---------------------------------------------------------------------------


class TestBuildArfMessage:
    def test_returns_valid_base64(self) -> None:
        report = _dmarc_report()
        result = abuse._build_arf_message(
            report,
            "74.208.4.196",
            1,
            "postmaster@gieselman.com",
            "abuse@ionos.com",
            "2026-04-02 to 2026-04-03",
        )
        decoded = base64.b64decode(result)
        assert b"Feedback-Type: auth-failure" in decoded
        assert b"Source-IP: 74.208.4.196" in decoded

    def test_contains_required_arf_fields(self) -> None:
        report = _dmarc_report()
        result = abuse._build_arf_message(
            report,
            "1.2.3.4",
            3,
            "postmaster@example.com",
            "abuse@provider.com",
            "2026-04-02 to 2026-04-03",
        )
        decoded = base64.b64decode(result)
        text = decoded.decode("utf-8", errors="replace")
        assert "Feedback-Type: auth-failure" in text
        assert "User-Agent: EmailReports/1.0" in text
        assert "Version: 1" in text
        assert "Source-IP: 1.2.3.4" in text
        assert "Source-IP-Count: 3" in text
        assert "Reported-Domain: gieselman.com" in text
        assert "dkim=fail" in text
        assert "spf=fail" in text

    def test_contains_human_readable_part(self) -> None:
        report = _dmarc_report()
        result = abuse._build_arf_message(
            report,
            "74.208.4.196",
            1,
            "postmaster@gieselman.com",
            "abuse@ionos.com",
            "2026-04-02 to 2026-04-03",
        )
        decoded = base64.b64decode(result).decode("utf-8", errors="replace")
        assert "Spoofed Domain: gieselman.com" in decoded
        assert "74.208.4.196" in decoded

    def test_includes_auto_submitted_header(self) -> None:
        report = _dmarc_report()
        result = abuse._build_arf_message(
            report,
            "1.2.3.4",
            1,
            "postmaster@example.com",
            "abuse@example.com",
            "2026-04-02 to 2026-04-03",
        )
        decoded = base64.b64decode(result).decode("utf-8", errors="replace")
        assert "Auto-Submitted: auto-generated" in decoded
