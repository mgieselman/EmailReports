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
    ReportRecord,
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
        assert "Email Security Monitor" in result.body_html

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


class TestSendGenericWebhook:
    def test_skips_when_no_url(self, monkeypatch):
        monkeypatch.setenv("GENERIC_WEBHOOK_URL", "")
        a = AlertSummary(title="t", severity=AlertSeverity.INFO, body_markdown="m")
        alert.send_generic_webhook(a)  # should not raise

    def test_posts_json_payload(self, monkeypatch):
        monkeypatch.setenv("GENERIC_WEBHOOK_URL", "https://hook.test/endpoint")
        a = AlertSummary(title="Test Alert", severity=AlertSeverity.WARNING, body_markdown="body")
        with patch("alert.requests.post") as mock_post:
            mock_post.return_value = MagicMock(raise_for_status=MagicMock())
            alert.send_generic_webhook(a)
            mock_post.assert_called_once()
            call_url = mock_post.call_args[0][0]
            assert call_url == "https://hook.test/endpoint"
            payload = mock_post.call_args[1]["json"]
            assert payload["title"] == "Test Alert"
            assert payload["severity"] == "warning"
            assert payload["body"] == "body"
            assert "timestamp" in payload


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


class TestViewModelHelpers:
    def test_card_returns_dict(self):
        card = alert._card("42", "Total", "#ff0000")
        assert card["value"] == "42"
        assert card["label"] == "Total"
        assert card["color"] == "#ff0000"

    def test_card_default_color(self):
        card = alert._card("0", "Test")
        assert card["color"] == "#1e293b"

    def test_base_context(self):
        ctx = alert._base_context("Title", AlertSeverity.WARNING, [alert._card("1", "X")])
        assert ctx["title"] == "Title"
        assert ctx["sev_label"] == "WARNING"
        assert len(ctx["stat_cards"]) == 1


# ---------------------------------------------------------------------------
# Weekly summary
# ---------------------------------------------------------------------------


def _report_record(
    report_type="dmarc",
    org="google.com",
    total=100,
    pass_c=95,
    fail_c=5,
    size=4000,
    dmarc_failure_details_json="",
    tls_failure_details_json="",
):
    return ReportRecord(
        report_type=report_type,
        report_id=f"test-{org}-{total}",
        org_name=org,
        domain="example.com",
        total_messages=total,
        pass_count=pass_c,
        fail_count=fail_c,
        policy="reject" if report_type == "dmarc" else "",
        attachment_size_bytes=size,
        dmarc_failure_details_json=dmarc_failure_details_json,
        tls_failure_details_json=tls_failure_details_json,
    )


class TestWeeklySummary:
    def test_basic_summary(self):
        records = [
            _report_record("dmarc", "google.com", 100, 95, 5),
            _report_record("dmarc", "microsoft.com", 50, 50, 0),
            _report_record("tlsrpt", "google.com", 200, 198, 2),
        ]
        result = alert.build_weekly_summary(records, days=7)
        assert "3 reports" in result.title
        assert result.severity == AlertSeverity.WARNING

    def test_all_passing_is_info(self):
        records = [_report_record("dmarc", "google.com", 100, 100, 0)]
        result = alert.build_weekly_summary(records)
        assert result.severity == AlertSeverity.INFO

    def test_high_failure_rate_is_critical(self):
        records = [_report_record("dmarc", "google.com", 100, 50, 50)]
        result = alert.build_weekly_summary(records)
        assert result.severity == AlertSeverity.CRITICAL

    def test_html_contains_dashboard(self):
        records = [
            _report_record("dmarc", "google.com", 100, 95, 5),
            _report_record("tlsrpt", "yahoo.com", 50, 48, 2),
        ]
        result = alert.build_weekly_summary(records, days=7)
        assert "Weekly Email Security Summary" in result.body_html
        assert "Reporting Sources" in result.body_html
        assert "google.com" in result.body_html
        assert "yahoo.com" in result.body_html
        assert "DMARC Messages" in result.body_html
        assert "TLS Sessions" in result.body_html

    def test_html_contains_policy_distribution(self):
        records = [_report_record("dmarc", "google.com", 100, 95, 5)]
        result = alert.build_weekly_summary(records)
        assert "DMARC Policy Distribution" in result.body_html
        assert "REJECT" in result.body_html

    def test_html_contains_failure_sources(self):
        records = [_report_record("dmarc", "spoofed.example.com", 10, 0, 10)]
        result = alert.build_weekly_summary(records)
        assert "Top Failure Sources" in result.body_html
        assert "spoofed.example.com" in result.body_html

    def test_no_failures_omits_failure_table(self):
        records = [_report_record("dmarc", "google.com", 100, 100, 0)]
        result = alert.build_weekly_summary(records)
        assert "Top Failure Sources" not in result.body_html

    def test_empty_records(self):
        result = alert.build_weekly_summary([], days=7)
        assert "0 reports" in result.title
        assert result.severity == AlertSeverity.INFO

    def test_markdown_output(self):
        records = [
            _report_record("dmarc", "google.com", 100, 95, 5),
            _report_record("tlsrpt", "google.com", 50, 48, 2),
        ]
        result = alert.build_weekly_summary(records, days=7)
        assert "**Total reports:**" in result.body_markdown
        assert "**DMARC:**" in result.body_markdown
        assert "**TLS-RPT:**" in result.body_markdown
        assert "**Top Senders:**" in result.body_markdown

    def test_dmarc_failure_details_in_html(self):
        import json

        details = json.dumps(
            [
                {
                    "source_ip": "5.6.7.8",
                    "count": 3,
                    "disposition": "none",
                    "dkim_result": "fail",
                    "spf_result": "fail",
                    "header_from": "spoofed.com",
                }
            ]
        )
        records = [_report_record("dmarc", "attacker.com", 10, 7, 3, dmarc_failure_details_json=details)]
        result = alert.build_weekly_summary(records, days=7)
        assert "DMARC Failure Details" in result.body_html
        assert "5.6.7.8" in result.body_html
        assert "spoofed.com" in result.body_html
        assert "DMARC Failure Details" in result.body_markdown

    def test_tls_failure_details_in_html(self):
        import json

        details = json.dumps(
            [
                {
                    "result_type": "sts-policy-fetch-error",
                    "sending_mta_ip": "1.2.3.4",
                    "receiving_mx_hostname": "mail.test.com",
                    "failed_session_count": 1,
                    "failure_reason_code": "",
                }
            ]
        )
        records = [_report_record("tlsrpt", "google.com", 10, 9, 1, tls_failure_details_json=details)]
        result = alert.build_weekly_summary(records, days=7)
        assert "TLS-RPT Failure Details" in result.body_html
        assert "sts-policy-fetch-error" in result.body_html.lower()
        assert "mail.test.com" in result.body_html
        assert "TLS-RPT Failure Details" in result.body_markdown

    def test_no_failure_details_omits_sections(self):
        records = [_report_record("dmarc", "google.com", 100, 100, 0)]
        result = alert.build_weekly_summary(records)
        assert "DMARC Failure Details" not in result.body_html
        assert "TLS-RPT Failure Details" not in result.body_html

    def test_failure_details_aggregated_across_records(self):
        import json

        fd = {
            "source_ip": "1.1.1.1",
            "count": 2,
            "disposition": "none",
            "dkim_result": "fail",
            "spf_result": "fail",
            "header_from": "x.com",
        }
        fd2 = {**fd, "count": 3}
        details1 = json.dumps([fd])
        details2 = json.dumps([fd2])
        records = [
            _report_record("dmarc", "a.com", 10, 8, 2, dmarc_failure_details_json=details1),
            _report_record("dmarc", "b.com", 10, 7, 3, dmarc_failure_details_json=details2),
        ]
        result = alert.build_weekly_summary(records, days=7)
        # Aggregated count should be 5 (2+3)
        assert "DMARC Failure Details" in result.body_html
        assert "1.1.1.1" in result.body_html

    def test_tls_failure_details_aggregated_across_records(self):
        import json

        fd = {
            "result_type": "certificate-expired",
            "sending_mta_ip": "1.2.3.4",
            "receiving_mx_hostname": "mx.test.com",
            "failed_session_count": 2,
            "failure_reason_code": "",
        }
        fd2 = {**fd, "failed_session_count": 3}
        details1 = json.dumps([fd])
        details2 = json.dumps([fd2])
        records = [
            _report_record("tlsrpt", "a.com", 10, 8, 2, tls_failure_details_json=details1),
            _report_record("tlsrpt", "b.com", 10, 7, 3, tls_failure_details_json=details2),
        ]
        result = alert.build_weekly_summary(records, days=7)
        assert "TLS-RPT Failure Details" in result.body_html
        assert "mx.test.com" in result.body_html


class TestFormatBytes:
    def test_bytes(self):
        assert alert._format_bytes(500) == "500 B"

    def test_kilobytes(self):
        assert alert._format_bytes(2048) == "2.0 KB"

    def test_megabytes(self):
        assert alert._format_bytes(5 * 1024 * 1024) == "5.0 MB"

    def test_zero(self):
        assert alert._format_bytes(0) == "0 B"

    def test_terabytes(self):
        assert "TB" in alert._format_bytes(2 * 1024**4)
