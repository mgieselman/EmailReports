"""Tests for models.py — dataclass properties and enum values."""

from datetime import UTC, datetime

from models import (
    AlertSeverity,
    AlertSummary,
    DmarcDisposition,
    DmarcRecord,
    DmarcReport,
    DmarcResult,
    TlsPolicy,
    TlsRptReport,
)

# ---------------------------------------------------------------------------
# DmarcReport
# ---------------------------------------------------------------------------


class TestDmarcReport:
    def _make_record(self, count=1, dkim="pass", spf="pass"):
        return DmarcRecord(
            source_ip="1.2.3.4",
            count=count,
            disposition=DmarcDisposition.NONE,
            dkim_result=DmarcResult(dkim),
            spf_result=DmarcResult(spf),
            header_from="example.com",
        )

    def _make_report(self, records=None):
        return DmarcReport(
            org_name="test.com",
            report_id="test-1",
            date_begin=datetime(2024, 1, 1, tzinfo=UTC),
            date_end=datetime(2024, 1, 2, tzinfo=UTC),
            domain="example.com",
            policy=DmarcDisposition.REJECT,
            records=records or [],
        )

    def test_total_messages_empty(self):
        report = self._make_report()
        assert report.total_messages == 0

    def test_total_messages_sums_counts(self):
        records = [self._make_record(count=10), self._make_record(count=5)]
        report = self._make_report(records)
        assert report.total_messages == 15

    def test_failing_records_empty_when_all_pass(self):
        records = [self._make_record(dkim="pass", spf="pass")]
        report = self._make_report(records)
        assert report.failing_records == []

    def test_failing_records_only_dkim_fail_not_included(self):
        records = [self._make_record(dkim="fail", spf="pass")]
        report = self._make_report(records)
        assert report.failing_records == []

    def test_failing_records_only_spf_fail_not_included(self):
        records = [self._make_record(dkim="pass", spf="fail")]
        report = self._make_report(records)
        assert report.failing_records == []

    def test_failing_records_both_fail_included(self):
        records = [self._make_record(dkim="fail", spf="fail")]
        report = self._make_report(records)
        assert len(report.failing_records) == 1

    def test_failing_records_mixed(self):
        records = [
            self._make_record(count=100, dkim="pass", spf="pass"),
            self._make_record(count=3, dkim="fail", spf="fail"),
            self._make_record(count=10, dkim="fail", spf="pass"),
        ]
        report = self._make_report(records)
        assert len(report.failing_records) == 1
        assert report.failing_records[0].count == 3
        assert report.total_messages == 113

    def test_default_adkim_aspf(self):
        report = self._make_report()
        assert report.adkim == "r"
        assert report.aspf == "r"

    def test_default_sp(self):
        report = self._make_report()
        assert report.sp == DmarcDisposition.NONE

    def test_default_pct(self):
        report = self._make_report()
        assert report.pct == 100

    def test_dkim_only_fail_records(self):
        records = [
            self._make_record(count=10, dkim="fail", spf="pass"),
            self._make_record(count=5, dkim="pass", spf="pass"),
            self._make_record(count=3, dkim="fail", spf="fail"),
        ]
        report = self._make_report(records)
        assert len(report.dkim_only_fail_records) == 1
        assert report.dkim_only_fail_records[0].count == 10

    def test_spf_only_fail_records(self):
        records = [
            self._make_record(count=10, dkim="pass", spf="fail"),
            self._make_record(count=5, dkim="pass", spf="pass"),
            self._make_record(count=3, dkim="fail", spf="fail"),
        ]
        report = self._make_report(records)
        assert len(report.spf_only_fail_records) == 1
        assert report.spf_only_fail_records[0].count == 10

    def test_partial_fail_empty_when_all_pass(self):
        records = [self._make_record(count=10, dkim="pass", spf="pass")]
        report = self._make_report(records)
        assert report.dkim_only_fail_records == []
        assert report.spf_only_fail_records == []

    def test_custom_alignment_fields(self):
        report = DmarcReport(
            org_name="test.com",
            report_id="test-1",
            date_begin=datetime(2024, 1, 1, tzinfo=UTC),
            date_end=datetime(2024, 1, 2, tzinfo=UTC),
            domain="example.com",
            policy=DmarcDisposition.REJECT,
            adkim="s",
            aspf="s",
            sp=DmarcDisposition.QUARANTINE,
            pct=50,
        )
        assert report.adkim == "s"
        assert report.aspf == "s"
        assert report.sp == DmarcDisposition.QUARANTINE
        assert report.pct == 50


# ---------------------------------------------------------------------------
# TlsRptReport
# ---------------------------------------------------------------------------


class TestTlsRptReport:
    def _make_report(self, policies=None):
        return TlsRptReport(
            org_name="test.com",
            report_id="test-1",
            date_begin=datetime(2024, 1, 1, tzinfo=UTC),
            date_end=datetime(2024, 1, 2, tzinfo=UTC),
            policies=policies or [],
        )

    def test_totals_empty_policies(self):
        report = self._make_report()
        assert report.total_failures == 0
        assert report.total_successful == 0

    def test_totals_sum_across_policies(self):
        policies = [
            TlsPolicy(policy_type="sts", policy_domain="a.com", successful_session_count=100, failed_session_count=5),
            TlsPolicy(policy_type="sts", policy_domain="b.com", successful_session_count=200, failed_session_count=10),
        ]
        report = self._make_report(policies)
        assert report.total_successful == 300
        assert report.total_failures == 15

    def test_totals_no_failures(self):
        policies = [
            TlsPolicy(policy_type="sts", policy_domain="a.com", successful_session_count=500, failed_session_count=0),
        ]
        report = self._make_report(policies)
        assert report.total_failures == 0
        assert report.total_successful == 500


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class TestEnums:
    def test_dmarc_disposition_values(self):
        assert DmarcDisposition("none") == DmarcDisposition.NONE
        assert DmarcDisposition("quarantine") == DmarcDisposition.QUARANTINE
        assert DmarcDisposition("reject") == DmarcDisposition.REJECT

    def test_dmarc_result_values(self):
        assert DmarcResult("pass") == DmarcResult.PASS
        assert DmarcResult("fail") == DmarcResult.FAIL

    def test_alert_severity_values(self):
        assert AlertSeverity("info") == AlertSeverity.INFO
        assert AlertSeverity("warning") == AlertSeverity.WARNING
        assert AlertSeverity("critical") == AlertSeverity.CRITICAL


# ---------------------------------------------------------------------------
# AlertSummary defaults
# ---------------------------------------------------------------------------


class TestAlertSummary:
    def test_default_timestamp(self):
        a = AlertSummary(title="t", severity=AlertSeverity.INFO, body_markdown="m")
        assert isinstance(a.timestamp, datetime)

    def test_default_body_html_empty(self):
        a = AlertSummary(title="t", severity=AlertSeverity.INFO, body_markdown="m")
        assert a.body_html == ""
