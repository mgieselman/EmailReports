"""Send sample DMARC, TLS-RPT, and weekly summary emails for visual testing.

Usage:
    python scripts/send_test_emails.py [dmarc|tlsrpt|weekly|all]

Defaults to "all" if no argument given.
"""

from __future__ import annotations

import json
import os
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

# Add project root to path so we can import application modules.
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))

# Load settings from local.settings.json
settings_path = str(_PROJECT_ROOT / "local.settings.json")
with open(settings_path) as f:
    settings = json.load(f)["Values"]
for k, v in settings.items():
    os.environ.setdefault(k, v)

# Force email sending on
os.environ["ALERT_EMAIL_ENABLED"] = "true"

import alert
from graph_client import GraphClient
from models import (
    DmarcDisposition,
    DmarcRecord,
    DmarcReport,
    DmarcResult,
    ReportRecord,
    TlsFailureDetail,
    TlsPolicy,
    TlsRptReport,
)


def _build_sample_dmarc() -> alert.AlertSummary:
    """Build a DMARC alert with a mix of pass/fail records and new fields."""
    records = [
        DmarcRecord(
            source_ip="209.85.220.41",
            count=150,
            disposition=DmarcDisposition.NONE,
            dkim_result=DmarcResult.PASS,
            spf_result=DmarcResult.PASS,
            header_from="example.com",
            envelope_from="example.com",
            dkim_domain="example.com",
            spf_domain="example.com",
        ),
        DmarcRecord(
            source_ip="40.107.22.55",
            count=42,
            disposition=DmarcDisposition.NONE,
            dkim_result=DmarcResult.PASS,
            spf_result=DmarcResult.FAIL,
            header_from="example.com",
            envelope_from="mail.example.com",
            dkim_domain="example.com",
            spf_domain="mail.example.com",
        ),
        DmarcRecord(
            source_ip="185.99.99.1",
            count=3,
            disposition=DmarcDisposition.REJECT,
            dkim_result=DmarcResult.FAIL,
            spf_result=DmarcResult.FAIL,
            header_from="example.com",
            envelope_from="spoofed.example.net",
            dkim_domain="spoofed.example.net",
            spf_domain="spoofed.example.net",
        ),
        DmarcRecord(
            source_ip="198.51.100.25",
            count=8,
            disposition=DmarcDisposition.QUARANTINE,
            dkim_result=DmarcResult.FAIL,
            spf_result=DmarcResult.PASS,
            header_from="example.com",
            envelope_from="bounce.marketing.example.com",
            dkim_domain="",
            spf_domain="marketing.example.com",
        ),
    ]
    report = DmarcReport(
        org_name="google.com",
        report_id="sample-dmarc-test",
        date_begin=datetime(2024, 3, 15, tzinfo=UTC),
        date_end=datetime(2024, 3, 16, tzinfo=UTC),
        domain="example.com",
        policy=DmarcDisposition.REJECT,
        records=records,
        adkim="s",
        aspf="r",
        sp=DmarcDisposition.QUARANTINE,
        pct=100,
    )
    return alert.build_dmarc_alert(report)


def _build_sample_tlsrpt() -> alert.AlertSummary:
    """Build a TLS-RPT alert with failures."""
    policies = [
        TlsPolicy(
            policy_type="sts",
            policy_domain="example.com",
            successful_session_count=485,
            failed_session_count=5,
            failure_details=[
                TlsFailureDetail(
                    result_type="certificate-expired",
                    sending_mta_ip="209.85.220.41",
                    receiving_mx_hostname="mail.example.com",
                    receiving_ip="192.0.2.1",
                    failed_session_count=3,
                    failure_reason_code="Certificate has expired",
                ),
                TlsFailureDetail(
                    result_type="starttls-not-supported",
                    sending_mta_ip="198.51.100.10",
                    receiving_mx_hostname="mail2.example.com",
                    receiving_ip="192.0.2.2",
                    failed_session_count=2,
                    failure_reason_code="",
                ),
            ],
        ),
        TlsPolicy(
            policy_type="sts",
            policy_domain="sub.example.com",
            successful_session_count=120,
            failed_session_count=0,
            failure_details=[],
        ),
    ]
    report = TlsRptReport(
        org_name="google.com",
        report_id="sample-tlsrpt-test",
        date_begin=datetime(2024, 3, 15, tzinfo=UTC),
        date_end=datetime(2024, 3, 16, tzinfo=UTC),
        policies=policies,
    )
    return alert.build_tlsrpt_alert(report)


def _build_sample_weekly() -> alert.AlertSummary:
    """Build a weekly summary with trend data and failure details."""
    now = datetime.now(UTC)
    dmarc_failures = json.dumps(
        [
            {
                "source_ip": "185.99.99.1",
                "count": 12,
                "disposition": "reject",
                "dkim_result": "fail",
                "spf_result": "fail",
                "header_from": "example.com",
                "org_name": "google.com",
            },
            {
                "source_ip": "203.0.113.50",
                "count": 5,
                "disposition": "quarantine",
                "dkim_result": "fail",
                "spf_result": "fail",
                "header_from": "example.com",
                "org_name": "microsoft.com",
            },
        ]
    )
    tls_failures = json.dumps(
        [
            {
                "result_type": "certificate-expired",
                "sending_mta_ip": "209.85.220.41",
                "receiving_mx_hostname": "mail.example.com",
                "receiving_ip": "192.0.2.1",
                "failed_session_count": 3,
                "failure_reason_code": "Certificate has expired",
            }
        ]
    )

    records = [
        ReportRecord(
            report_type="dmarc",
            report_id="weekly-dmarc-1",
            org_name="google.com",
            domain="example.com",
            total_messages=500,
            pass_count=483,
            fail_count=17,
            policy="reject",
            attachment_size_bytes=12000,
            received_at=now - timedelta(days=2),
            dmarc_failure_details_json=dmarc_failures,
        ),
        ReportRecord(
            report_type="dmarc",
            report_id="weekly-dmarc-2",
            org_name="microsoft.com",
            domain="example.com",
            total_messages=200,
            pass_count=195,
            fail_count=5,
            policy="reject",
            attachment_size_bytes=8000,
            received_at=now - timedelta(days=3),
        ),
        ReportRecord(
            report_type="dmarc",
            report_id="weekly-dmarc-3",
            org_name="yahoo.com",
            domain="example.com",
            total_messages=75,
            pass_count=75,
            fail_count=0,
            policy="none",
            attachment_size_bytes=5000,
            received_at=now - timedelta(days=1),
        ),
        ReportRecord(
            report_type="tlsrpt",
            report_id="weekly-tls-1",
            org_name="google.com",
            domain="",
            total_messages=600,
            pass_count=597,
            fail_count=3,
            attachment_size_bytes=3000,
            received_at=now - timedelta(days=2),
            tls_failure_details_json=tls_failures,
        ),
        ReportRecord(
            report_type="tlsrpt",
            report_id="weekly-tls-2",
            org_name="microsoft.com",
            domain="",
            total_messages=150,
            pass_count=150,
            fail_count=0,
            attachment_size_bytes=2000,
            received_at=now - timedelta(days=4),
        ),
    ]

    # Previous period data for trend comparison
    prev_records = [
        ReportRecord(
            report_type="dmarc",
            report_id="prev-dmarc-1",
            org_name="google.com",
            domain="example.com",
            total_messages=480,
            pass_count=450,
            fail_count=30,
            policy="reject",
            received_at=now - timedelta(days=10),
        ),
        ReportRecord(
            report_type="tlsrpt",
            report_id="prev-tls-1",
            org_name="google.com",
            domain="",
            total_messages=550,
            pass_count=540,
            fail_count=10,
            received_at=now - timedelta(days=10),
        ),
    ]

    return alert.build_weekly_summary(records, days=7, prev_records=prev_records)


def send(which: str) -> None:
    from_addr = os.environ["ALERT_EMAIL_FROM"]
    to_addr = os.environ["ALERT_EMAIL_TO"]

    builders = {
        "dmarc": ("DMARC Alert", _build_sample_dmarc),
        "tlsrpt": ("TLS-RPT Alert", _build_sample_tlsrpt),
        "weekly": ("Weekly Summary", _build_sample_weekly),
    }

    if which == "all":
        targets = list(builders.keys())
    elif which in builders:
        targets = [which]
    else:
        print(f"Unknown report type: {which}")
        print(f"Usage: python {sys.argv[0]} [dmarc|tlsrpt|weekly|all]")
        sys.exit(1)

    with GraphClient() as graph:
        for key in targets:
            label, builder = builders[key]
            summary = builder()
            print(f"Sending {label} to {to_addr}...")
            graph.send_mail(from_addr, to_addr, f"[TEST] {summary.title}", summary.body_html)
            print(f"  Sent: {summary.title}")

    print("Done!")


if __name__ == "__main__":
    which = sys.argv[1] if len(sys.argv) > 1 else "all"
    send(which)
