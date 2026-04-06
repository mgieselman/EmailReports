"""Tests for alert.py — severity logic, HTML generation, and aggregation helpers."""

from __future__ import annotations

from datetime import UTC, datetime

import alert
from models import (
    AlertSeverity,
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


def _dmarc_report(records=None, policy=DmarcDisposition.REJECT, **kwargs):
    defaults = {
        "org_name": "google.com",
        "report_id": "test-1",
        "date_begin": datetime(2024, 3, 15, tzinfo=UTC),
        "date_end": datetime(2024, 3, 16, tzinfo=UTC),
        "domain": "gieselman.com",
        "policy": policy,
        "records": records or [],
    }
    defaults.update(kwargs)
    return DmarcReport(**defaults)


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
# _classify_severity
# ---------------------------------------------------------------------------


class TestClassifySeverity:
    def test_no_failures_is_info(self):
        assert alert._classify_severity(0, 100, has_failures=False) == AlertSeverity.INFO

    def test_low_rate_is_warning(self):
        assert alert._classify_severity(5, 100, has_failures=True) == AlertSeverity.WARNING

    def test_high_rate_is_critical(self):
        assert alert._classify_severity(20, 100, has_failures=True) == AlertSeverity.CRITICAL

    def test_boundary_10_percent_is_warning(self):
        # Exactly 10% is not > 10%
        assert alert._classify_severity(10, 100, has_failures=True) == AlertSeverity.WARNING

    def test_just_over_10_percent_is_critical(self):
        assert alert._classify_severity(11, 100, has_failures=True) == AlertSeverity.CRITICAL

    def test_zero_total_no_failures_is_info(self):
        assert alert._classify_severity(0, 0, has_failures=False) == AlertSeverity.INFO


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

    def test_contains_alignment_strict(self):
        records = [_dmarc_record(count=10)]
        result = alert.build_dmarc_alert(_dmarc_report(records, adkim="s", aspf="s"))
        assert "Strict" in result.body_html
        assert "DKIM Alignment" in result.body_html
        assert "SPF Alignment" in result.body_html

    def test_contains_alignment_relaxed(self):
        records = [_dmarc_record(count=10)]
        result = alert.build_dmarc_alert(_dmarc_report(records, adkim="r", aspf="r"))
        assert "Relaxed" in result.body_html

    def test_subdomain_policy_shown_when_different(self):
        records = [_dmarc_record(count=10)]
        result = alert.build_dmarc_alert(
            _dmarc_report(records, policy=DmarcDisposition.REJECT, sp=DmarcDisposition.QUARANTINE)
        )
        assert "Subdomain Policy" in result.body_html
        assert "QUARANTINE" in result.body_html

    def test_subdomain_policy_hidden_when_same(self):
        records = [_dmarc_record(count=10)]
        result = alert.build_dmarc_alert(
            _dmarc_report(records, policy=DmarcDisposition.REJECT, sp=DmarcDisposition.REJECT)
        )
        assert "Subdomain Policy" not in result.body_html

    def test_sampling_shown_when_below_100(self):
        records = [_dmarc_record(count=10)]
        result = alert.build_dmarc_alert(_dmarc_report(records, pct=50))
        assert "Sampling" in result.body_html
        assert "50%" in result.body_html

    def test_sampling_hidden_when_100(self):
        records = [_dmarc_record(count=10)]
        result = alert.build_dmarc_alert(_dmarc_report(records, pct=100))
        assert "Sampling" not in result.body_html

    def test_contains_dkim_domain_column(self):
        records = [_dmarc_record(count=10)]
        result = alert.build_dmarc_alert(_dmarc_report(records))
        assert "DKIM Domain" in result.body_html

    def test_partial_failures_shown(self):
        records = [
            _dmarc_record(count=10, dkim="pass", spf="pass"),
            _dmarc_record(count=3, dkim="fail", spf="pass", source_ip="2.3.4.5"),
            _dmarc_record(count=2, dkim="pass", spf="fail", source_ip="3.4.5.6"),
        ]
        result = alert.build_dmarc_alert(_dmarc_report(records))
        assert "Partial auth failures" in result.body_html
        assert "DKIM-only" in result.body_html
        assert "SPF-only" in result.body_html

    def test_partial_failures_hidden_when_none(self):
        records = [_dmarc_record(count=10, dkim="pass", spf="pass")]
        result = alert.build_dmarc_alert(_dmarc_report(records))
        assert "Partial auth failures" not in result.body_html

    def test_partial_failures_in_markdown(self):
        records = [
            _dmarc_record(count=10, dkim="pass", spf="pass"),
            _dmarc_record(count=3, dkim="fail", spf="pass", source_ip="2.3.4.5"),
        ]
        result = alert.build_dmarc_alert(_dmarc_report(records))
        assert "**DKIM-only failures:** 3" in result.body_markdown


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
        result = alert.build_dmarc_alert(_dmarc_report(records, adkim="s", aspf="r"))
        assert "**Org:**" in result.body_markdown
        assert "**Domain:**" in result.body_markdown
        assert "**Total messages:**" in result.body_markdown
        assert "Source IP" in result.body_markdown
        assert "**DKIM Alignment:** strict" in result.body_markdown
        assert "**SPF Alignment:** relaxed" in result.body_markdown
        assert "DKIM Domain" in result.body_markdown
        assert "SPF Domain" in result.body_markdown

    def test_dmarc_markdown_subdomain_policy_when_different(self):
        records = [_dmarc_record(count=10)]
        result = alert.build_dmarc_alert(
            _dmarc_report(records, policy=DmarcDisposition.REJECT, sp=DmarcDisposition.NONE)
        )
        assert "**Subdomain Policy:** none" in result.body_markdown

    def test_dmarc_markdown_sampling_when_below_100(self):
        records = [_dmarc_record(count=10)]
        result = alert.build_dmarc_alert(_dmarc_report(records, pct=25))
        assert "**Sampling:** 25%" in result.body_markdown

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
        assert card["color"] == "#ffffff"

    def test_base_context(self):
        ctx = alert._base_context("Title", AlertSeverity.WARNING, [alert._card("1", "X")])
        assert ctx["title"] == "Title"
        assert ctx["sev_label"] == "WARNING"
        assert len(ctx["stat_cards"]) == 1


# ---------------------------------------------------------------------------
# Aggregation helpers
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


class TestAggregationHelpers:
    def test_aggregate_org_volumes(self):
        records = [
            _report_record("dmarc", "big.com", 500),
            _report_record("dmarc", "small.com", 10),
            _report_record("tlsrpt", "big.com", 200),
        ]
        result = alert._aggregate_org_volumes(records)
        assert result[0] == ("big.com", 700)
        assert result[1] == ("small.com", 10)

    def test_aggregate_org_volumes_top_10(self):
        records = [_report_record("dmarc", f"org{i}.com", 100 - i) for i in range(15)]
        result = alert._aggregate_org_volumes(records)
        assert len(result) == 10

    def test_aggregate_policy_distribution(self):
        r1 = _report_record("dmarc", "a.com", 100)
        r2 = _report_record("dmarc", "b.com", 50)
        r2.policy = "quarantine"
        dmarc = [r1, r2]
        result = alert._aggregate_policy_distribution(dmarc)
        assert result[0] == ("reject", 100)
        assert result[1] == ("quarantine", 50)

    def test_aggregate_failure_orgs(self):
        records = [
            _report_record("dmarc", "good.com", 100, 100, 0),
            _report_record("dmarc", "bad.com", 100, 80, 20),
        ]
        result = alert._aggregate_failure_orgs(records)
        assert "bad.com" in result
        assert "good.com" not in result
        assert result["bad.com"] == 20

    def test_aggregate_dmarc_failures(self):
        import json

        fd = {
            "source_ip": "1.1.1.1",
            "count": 2,
            "disposition": "none",
            "dkim_result": "fail",
            "spf_result": "fail",
            "header_from": "x.com",
        }
        dmarc = [_report_record("dmarc", "a.com", dmarc_failure_details_json=json.dumps([fd]))]
        result, total = alert._aggregate_dmarc_failures(dmarc)
        assert len(result) == 1
        assert total == 1
        assert result[0]["source_ip"] == "1.1.1.1"
        assert result[0]["org_name"] == "a.com"

    def test_aggregate_dmarc_failures_merges_same_key(self):
        import json

        fd1 = {
            "source_ip": "1.1.1.1",
            "count": 2,
            "disposition": "none",
            "dkim_result": "fail",
            "spf_result": "fail",
            "header_from": "x.com",
        }
        fd2 = {**fd1, "count": 3}
        dmarc = [
            _report_record("dmarc", "a.com", dmarc_failure_details_json=json.dumps([fd1])),
            _report_record("dmarc", "b.com", dmarc_failure_details_json=json.dumps([fd2])),
        ]
        result, total = alert._aggregate_dmarc_failures(dmarc)
        assert len(result) == 1
        assert total == 1
        assert result[0]["count"] == 5
        assert "a.com" in result[0]["org_name"]
        assert "b.com" in result[0]["org_name"]

    def test_aggregate_dmarc_failures_with_org_name_in_detail(self):
        import json

        fd = {
            "source_ip": "1.1.1.1",
            "count": 2,
            "disposition": "none",
            "dkim_result": "fail",
            "spf_result": "fail",
            "header_from": "x.com",
            "org_name": "reporter.com",
        }
        dmarc = [_report_record("dmarc", "a.com", dmarc_failure_details_json=json.dumps([fd]))]
        result, _ = alert._aggregate_dmarc_failures(dmarc)
        assert result[0]["org_name"] == "reporter.com"

    def test_aggregate_tls_failures(self):
        import json

        fd = {
            "result_type": "cert-expired",
            "sending_mta_ip": "1.2.3.4",
            "receiving_mx_hostname": "mx.test.com",
            "failed_session_count": 2,
            "failure_reason_code": "",
        }
        tlsrpt = [_report_record("tlsrpt", "a.com", tls_failure_details_json=json.dumps([fd]))]
        result, total = alert._aggregate_tls_failures(tlsrpt)
        assert len(result) == 1
        assert total == 1
        assert result[0]["receiving_mx_hostname"] == "mx.test.com"

    def test_aggregate_tls_failures_merges_same_key(self):
        import json

        fd1 = {
            "result_type": "cert-expired",
            "sending_mta_ip": "1.2.3.4",
            "receiving_mx_hostname": "mx.test.com",
            "failed_session_count": 2,
            "failure_reason_code": "",
        }
        fd2 = {**fd1, "failed_session_count": 3}
        tlsrpt = [
            _report_record("tlsrpt", "a.com", tls_failure_details_json=json.dumps([fd1])),
            _report_record("tlsrpt", "b.com", tls_failure_details_json=json.dumps([fd2])),
        ]
        result, total = alert._aggregate_tls_failures(tlsrpt)
        assert len(result) == 1
        assert total == 1
        assert result[0]["failed_session_count"] == 5

    def test_build_sender_details(self):
        dmarc = [_report_record("dmarc", "google.com", 100, 95, 5)]
        tlsrpt = [_report_record("tlsrpt", "google.com", 50, 48, 2)]
        top_senders = [("google.com", 150)]
        failure_orgs = {"google.com": 7}
        result = alert._build_sender_details(top_senders, dmarc, tlsrpt, failure_orgs)
        assert len(result) == 1
        assert result[0]["org"] == "google.com"
        assert result[0]["volume"] == 150
        assert result[0]["dmarc"] == 100
        assert result[0]["tls"] == 50
        assert result[0]["fails"] == 7


# ---------------------------------------------------------------------------
# Weekly summary
# ---------------------------------------------------------------------------


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
        assert "DMARC Msgs" in result.body_html
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
        assert "attacker.com" in result.body_html  # org column
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


class TestTlsRptReceivingIp:
    def test_receiving_ip_in_html(self):
        fd = TlsFailureDetail(
            result_type="certificate-expired",
            receiving_mx_hostname="mail.example.com",
            receiving_ip="192.0.2.1",
            failed_session_count=2,
        )
        policies = [
            TlsPolicy(
                policy_type="sts",
                policy_domain="example.com",
                successful_session_count=100,
                failed_session_count=2,
                failure_details=[fd],
            )
        ]
        result = alert.build_tlsrpt_alert(_tls_report(policies))
        assert "RX IP" in result.body_html
        assert "192.0.2.1" in result.body_html


class TestDmarcTruncation:
    def test_truncation_note_shown(self):
        records = [_dmarc_record(count=1, source_ip=f"1.2.3.{i}") for i in range(60)]
        result = alert.build_dmarc_alert(_dmarc_report(records))
        assert "Showing 50 of 60 records" in result.body_html

    def test_no_truncation_note(self):
        records = [_dmarc_record(count=1, source_ip=f"1.2.3.{i}") for i in range(10)]
        result = alert.build_dmarc_alert(_dmarc_report(records))
        assert "Showing" not in result.body_html


class TestWeeklySummaryTrends:
    def test_trend_deltas_shown(self):
        records = [_report_record("dmarc", "google.com", 100, 95, 5)]
        prev = [_report_record("dmarc", "google.com", 100, 90, 10)]
        result = alert.build_weekly_summary(records, days=7, prev_records=prev)
        # Current 95%, prev 90% => delta +5.0%
        assert "\u25b2" in result.body_html  # up arrow
        assert "+5.0%" in result.body_html

    def test_trend_negative_delta(self):
        records = [_report_record("dmarc", "google.com", 100, 90, 10)]
        prev = [_report_record("dmarc", "google.com", 100, 95, 5)]
        result = alert.build_weekly_summary(records, days=7, prev_records=prev)
        assert "\u25bc" in result.body_html  # down arrow
        assert "-5.0%" in result.body_html

    def test_no_trend_without_prev_records(self):
        records = [_report_record("dmarc", "google.com", 100, 95, 5)]
        result = alert.build_weekly_summary(records, days=7)
        assert "vs prev period" not in result.body_html

    def test_no_trend_with_empty_prev(self):
        records = [_report_record("dmarc", "google.com", 100, 95, 5)]
        result = alert.build_weekly_summary(records, days=7, prev_records=None)
        assert "vs prev period" not in result.body_html

    def test_tls_trend_delta(self):
        records = [_report_record("tlsrpt", "google.com", 100, 100, 0)]
        prev = [_report_record("tlsrpt", "google.com", 100, 90, 10)]
        result = alert.build_weekly_summary(records, days=7, prev_records=prev)
        assert "TLS Pass Rate vs prev period" in result.body_html
        assert "+10.0%" in result.body_html

    def test_no_delta_when_prev_has_no_matching_type(self):
        records = [_report_record("dmarc", "google.com", 100, 95, 5)]
        prev = [_report_record("tlsrpt", "google.com", 100, 90, 10)]
        result = alert.build_weekly_summary(records, days=7, prev_records=prev)
        # No prev DMARC data => no DMARC delta
        assert "DMARC Pass Rate vs prev period" not in result.body_html


class TestWeeklySummaryAbuseCount:
    def test_abuse_count_in_markdown(self):
        records = [_report_record("dmarc", "google.com", 100, 95, 5)]
        result = alert.build_weekly_summary(records, days=7, abuse_reports_sent=3)
        assert "Abuse reports sent:** 3" in result.body_markdown

    def test_abuse_count_in_html(self):
        records = [_report_record("dmarc", "google.com", 100, 95, 5)]
        result = alert.build_weekly_summary(records, days=7, abuse_reports_sent=5)
        assert "Abuse Reports Sent" in result.body_html
        assert "5" in result.body_html

    def test_abuse_count_zero_not_shown_markdown(self):
        records = [_report_record("dmarc", "google.com", 100, 95, 5)]
        result = alert.build_weekly_summary(records, days=7, abuse_reports_sent=0)
        assert "Abuse reports sent" not in result.body_markdown

    def test_abuse_count_zero_not_shown_html(self):
        records = [_report_record("dmarc", "google.com", 100, 95, 5)]
        result = alert.build_weekly_summary(records, days=7, abuse_reports_sent=0)
        assert "Abuse Reports Sent" not in result.body_html

    def test_abuse_count_default_zero(self):
        records = [_report_record("dmarc", "google.com", 100, 95, 5)]
        result = alert.build_weekly_summary(records, days=7)
        assert "Abuse reports sent" not in result.body_markdown


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
