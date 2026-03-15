"""Tests for alert.py — severity logic, HTML generation, and delivery."""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import MagicMock, patch

import alert
from models import (
    AlertSeverity,
    AlertSummary,
    DmarcDisposition,
    DmarcRecord,
    DmarcReport,
    DmarcResult,
    TlsFailureDetail,
    TlsPolicy,
    TlsRptReport,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _dmarc_report(records=None, policy=DmarcDisposition.REJECT):
    return DmarcReport(
        org_name="google.com",
        report_id="test-1",
        date_begin=datetime(2024, 3, 15, tzinfo=UTC),
        date_end=datetime(2024, 3, 16, tzinfo=UTC),
        domain="gieselman.com",
        policy=policy,
        records=records or [],
    )


def _dmarc_record(count=1, dkim="pass", spf="pass", source_ip="1.2.3.4"):
    return DmarcRecord(
        source_ip=source_ip,
        count=count,
        disposition=DmarcDisposition.NONE,
        dkim_result=DmarcResult(dkim),
        spf_result=DmarcResult(spf),
        header_from="gieselman.com",
        dkim_domain="gieselman.com",
    )


def _tls_report(policies=None):
    return TlsRptReport(
        org_name="google.com",
        report_id="tls-1",
        date_begin=datetime(2024, 3, 15, tzinfo=UTC),
        date_end=datetime(2024, 3, 16, tzinfo=UTC),
        policies=policies or [],
    )


# ---------------------------------------------------------------------------
# DMARC severity
# ---------------------------------------------------------------------------


class TestDmarcSeverity:
    def test_all_passing_is_info(self):
        records = [_dmarc_record(count=100, dkim="pass", spf="pass")]
        result = alert.build_dmarc_alert(_dmarc_report(records))
        assert result.severity == AlertSeverity.INFO

    def test_minor_failures_is_warning(self):
        records = [
            _dmarc_record(count=100, dkim="pass", spf="pass"),
            _dmarc_record(count=2, dkim="fail", spf="fail"),
        ]
        result = alert.build_dmarc_alert(_dmarc_report(records))
        assert result.severity == AlertSeverity.WARNING

    def test_major_failures_is_critical(self):
        records = [
            _dmarc_record(count=10, dkim="pass", spf="pass"),
            _dmarc_record(count=5, dkim="fail", spf="fail"),
        ]
        # 5/15 = 33% > 10%
        result = alert.build_dmarc_alert(_dmarc_report(records))
        assert result.severity == AlertSeverity.CRITICAL

    def test_empty_records_is_info(self):
        result = alert.build_dmarc_alert(_dmarc_report([]))
        assert result.severity == AlertSeverity.INFO

    def test_boundary_10_percent(self):
        # Exactly 10/100 = 10%, not > 10%
        records = [
            _dmarc_record(count=90, dkim="pass", spf="pass"),
            _dmarc_record(count=10, dkim="fail", spf="fail"),
        ]
        result = alert.build_dmarc_alert(_dmarc_report(records))
        assert result.severity == AlertSeverity.WARNING

    def test_just_over_10_percent_is_critical(self):
        records = [
            _dmarc_record(count=89, dkim="pass", spf="pass"),
            _dmarc_record(count=11, dkim="fail", spf="fail"),
        ]
        result = alert.build_dmarc_alert(_dmarc_report(records))
        assert result.severity == AlertSeverity.CRITICAL


# ---------------------------------------------------------------------------
# TLS-RPT severity
# ---------------------------------------------------------------------------


class TestTlsRptSeverity:
    def test_no_failures_is_info(self):
        policies = [
            TlsPolicy(policy_type="sts", policy_domain="a.com", successful_session_count=100, failed_session_count=0)
        ]
        result = alert.build_tlsrpt_alert(_tls_report(policies))
        assert result.severity == AlertSeverity.INFO

    def test_minor_failures_is_warning(self):
        policies = [
            TlsPolicy(policy_type="sts", policy_domain="a.com", successful_session_count=100, failed_session_count=5)
        ]
        result = alert.build_tlsrpt_alert(_tls_report(policies))
        assert result.severity == AlertSeverity.WARNING

    def test_major_failures_is_critical(self):
        policies = [
            TlsPolicy(policy_type="sts", policy_domain="a.com", successful_session_count=10, failed_session_count=5)
        ]
        result = alert.build_tlsrpt_alert(_tls_report(policies))
        assert result.severity == AlertSeverity.CRITICAL

    def test_empty_policies_is_info(self):
        result = alert.build_tlsrpt_alert(_tls_report([]))
        assert result.severity == AlertSeverity.INFO

    def test_all_failures_is_critical(self):
        policies = [
            TlsPolicy(policy_type="sts", policy_domain="a.com", successful_session_count=0, failed_session_count=100)
        ]
        result = alert.build_tlsrpt_alert(_tls_report(policies))
        assert result.severity == AlertSeverity.CRITICAL


# ---------------------------------------------------------------------------
# DMARC HTML content
# ---------------------------------------------------------------------------


class TestDmarcHtmlContent:
    def test_contains_domain(self):
        records = [_dmarc_record(count=10)]
        result = alert.build_dmarc_alert(_dmarc_report(records))
        assert "gieselman.com" in result.body_html

    def test_contains_org_name(self):
        records = [_dmarc_record(count=10)]
        result = alert.build_dmarc_alert(_dmarc_report(records))
        assert "google.com" in result.body_html

    def test_contains_stat_cards(self):
        records = [_dmarc_record(count=10)]
        result = alert.build_dmarc_alert(_dmarc_report(records))
        assert "Total Messages" in result.body_html
        assert "Passing" in result.body_html
        assert "Pass Rate" in result.body_html

    def test_contains_status_badges(self):
        records = [
            _dmarc_record(count=10, dkim="pass", spf="pass"),
            _dmarc_record(count=2, dkim="fail", spf="fail", source_ip="5.6.7.8"),
        ]
        result = alert.build_dmarc_alert(_dmarc_report(records))
        assert "PASS" in result.body_html
        assert "FAIL" in result.body_html

    def test_contains_severity_badge(self):
        records = [_dmarc_record(count=10)]
        result = alert.build_dmarc_alert(_dmarc_report(records))
        assert "ALL CLEAR" in result.body_html

    def test_contains_footer(self):
        records = [_dmarc_record(count=10)]
        result = alert.build_dmarc_alert(_dmarc_report(records))
        assert "gieselman.com Email Security Monitor" in result.body_html

    def test_title_format(self):
        records = [_dmarc_record(count=10)]
        result = alert.build_dmarc_alert(_dmarc_report(records))
        assert result.title == "DMARC Report: gieselman.com (google.com)"


# ---------------------------------------------------------------------------
# TLS-RPT HTML content
# ---------------------------------------------------------------------------


class TestTlsRptHtmlContent:
    def test_contains_org_name(self):
        policies = [
            TlsPolicy(
                policy_type="sts", policy_domain="gieselman.com", successful_session_count=100, failed_session_count=0
            )
        ]
        result = alert.build_tlsrpt_alert(_tls_report(policies))
        assert "google.com" in result.body_html

    def test_contains_stat_cards(self):
        policies = [
            TlsPolicy(
                policy_type="sts", policy_domain="gieselman.com", successful_session_count=100, failed_session_count=2
            )
        ]
        result = alert.build_tlsrpt_alert(_tls_report(policies))
        assert "Total Sessions" in result.body_html
        assert "Successful" in result.body_html
        assert "Success Rate" in result.body_html

    def test_no_failure_details_shows_successful_badge(self):
        policies = [
            TlsPolicy(
                policy_type="sts", policy_domain="gieselman.com", successful_session_count=100, failed_session_count=0
            )
        ]
        result = alert.build_tlsrpt_alert(_tls_report(policies))
        assert "SUCCESSFUL" in result.body_html

    def test_failure_details_in_table(self):
        fd = TlsFailureDetail(
            result_type="certificate-expired",
            receiving_mx_hostname="mail.gieselman.com",
            failed_session_count=2,
            failure_reason_code="Certificate expired",
        )
        policies = [
            TlsPolicy(
                policy_type="sts",
                policy_domain="gieselman.com",
                successful_session_count=100,
                failed_session_count=2,
                failure_details=[fd],
            )
        ]
        result = alert.build_tlsrpt_alert(_tls_report(policies))
        assert "certificate-expired" in result.body_html.lower()
        assert "mail.gieselman.com" in result.body_html


# ---------------------------------------------------------------------------
# Markdown output (for Teams)
# ---------------------------------------------------------------------------


class TestMarkdownOutput:
    def test_dmarc_markdown_contains_key_fields(self):
        records = [_dmarc_record(count=10, dkim="fail", spf="fail")]
        result = alert.build_dmarc_alert(_dmarc_report(records))
        assert "**Org:**" in result.body_markdown
        assert "**Domain:**" in result.body_markdown
        assert "**Total messages:**" in result.body_markdown
        assert "Source IP" in result.body_markdown

    def test_tlsrpt_markdown_contains_key_fields(self):
        policies = [
            TlsPolicy(
                policy_type="sts",
                policy_domain="gieselman.com",
                successful_session_count=100,
                failed_session_count=5,
                failure_details=[TlsFailureDetail(result_type="test", failed_session_count=5)],
            )
        ]
        result = alert.build_tlsrpt_alert(_tls_report(policies))
        assert "**Org:**" in result.body_markdown
        assert "**Successful sessions:**" in result.body_markdown
        assert "Result" in result.body_markdown


# ---------------------------------------------------------------------------
# send_teams_alert
# ---------------------------------------------------------------------------


class TestSendTeamsAlert:
    def test_skips_when_no_webhook(self, monkeypatch):
        monkeypatch.setenv("TEAMS_WEBHOOK_URL", "")
        a = AlertSummary(title="t", severity=AlertSeverity.INFO, body_markdown="m")
        # Should not raise
        alert.send_teams_alert(a)

    def test_posts_to_webhook(self, monkeypatch):
        monkeypatch.setenv("TEAMS_WEBHOOK_URL", "https://webhook.test/hook")
        a = AlertSummary(title="Test", severity=AlertSeverity.INFO, body_markdown="m")
        with patch("alert.requests.post") as mock_post:
            mock_post.return_value = MagicMock(raise_for_status=MagicMock())
            alert.send_teams_alert(a)
            mock_post.assert_called_once()
            call_url = mock_post.call_args[0][0]
            assert call_url == "https://webhook.test/hook"

    def test_adaptive_card_severity_attention(self, monkeypatch):
        monkeypatch.setenv("TEAMS_WEBHOOK_URL", "https://webhook.test/hook")
        a = AlertSummary(title="Critical", severity=AlertSeverity.CRITICAL, body_markdown="m")
        with patch("alert.requests.post") as mock_post:
            mock_post.return_value = MagicMock(raise_for_status=MagicMock())
            alert.send_teams_alert(a)
            card = mock_post.call_args[1]["json"]
            body = card["attachments"][0]["content"]["body"]
            assert body[0]["color"] == "Attention"

    def test_adaptive_card_severity_good(self, monkeypatch):
        monkeypatch.setenv("TEAMS_WEBHOOK_URL", "https://webhook.test/hook")
        a = AlertSummary(title="OK", severity=AlertSeverity.INFO, body_markdown="m")
        with patch("alert.requests.post") as mock_post:
            mock_post.return_value = MagicMock(raise_for_status=MagicMock())
            alert.send_teams_alert(a)
            card = mock_post.call_args[1]["json"]
            body = card["attachments"][0]["content"]["body"]
            assert body[0]["color"] == "Good"


# ---------------------------------------------------------------------------
# send_email_alert
# ---------------------------------------------------------------------------


class TestSendEmailAlert:
    def test_disabled_by_default(self, mock_graph, monkeypatch):
        monkeypatch.setenv("ALERT_EMAIL_ENABLED", "false")
        a = AlertSummary(title="t", severity=AlertSeverity.INFO, body_markdown="m")
        alert.send_email_alert(a, mock_graph)
        mock_graph.send_mail.assert_not_called()

    def test_enabled_sends_email(self, mock_graph, monkeypatch):
        monkeypatch.setenv("ALERT_EMAIL_ENABLED", "true")
        monkeypatch.setenv("ALERT_EMAIL_FROM", "from@test.com")
        monkeypatch.setenv("ALERT_EMAIL_TO", "to@test.com")
        a = AlertSummary(title="Test", severity=AlertSeverity.INFO, body_markdown="m", body_html="<p>html</p>")
        alert.send_email_alert(a, mock_graph)
        mock_graph.send_mail.assert_called_once_with("from@test.com", "to@test.com", "Test", "<p>html</p>")

    def test_case_insensitive_enabled(self, mock_graph, monkeypatch):
        monkeypatch.setenv("ALERT_EMAIL_ENABLED", "TRUE")
        a = AlertSummary(title="Test", severity=AlertSeverity.INFO, body_markdown="m", body_html="<p>html</p>")
        alert.send_email_alert(a, mock_graph)
        mock_graph.send_mail.assert_called_once()


# ---------------------------------------------------------------------------
# HTML helpers
# ---------------------------------------------------------------------------


class TestHtmlHelpers:
    def test_status_badge_pass(self):
        html = alert._status_badge("pass")
        assert "PASS" in html
        assert "#dcfce7" in html  # green bg

    def test_status_badge_fail(self):
        html = alert._status_badge("fail")
        assert "FAIL" in html
        assert "#fee2e2" in html  # red bg

    def test_status_badge_custom_pass_value(self):
        html = alert._status_badge("successful", pass_value="successful")
        assert "SUCCESSFUL" in html
        assert "#dcfce7" in html

    def test_stat_card_content(self):
        html = alert._stat_card("42", "Total")
        assert "42" in html
        assert "Total" in html

    def test_stat_card_custom_color(self):
        html = alert._stat_card("0", "Failed", color="#991b1b")
        assert "#991b1b" in html

    def test_build_table_empty_rows(self):
        html = alert._build_table(["A", "B"], [])
        assert "<th" in html
        assert "<td" not in html

    def test_build_table_alternating_rows(self):
        html = alert._build_table(["X"], [["row0"], ["row1"], ["row2"]])
        assert "row0" in html
        assert "row1" in html
        assert "row2" in html
        # Even rows white, odd rows light gray
        assert "#f8fafc" in html
