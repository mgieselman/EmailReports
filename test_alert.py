"""Test script: parse sample DMARC + TLS-RPT data and send alert email.

Usage:
    python test_alert.py [--email] [--teams]

Flags:
    --email   Send the alert email via Graph (requires ALERT_EMAIL_FROM/TO set)
    --teams   Post to Teams webhook (requires TEAMS_WEBHOOK_URL set)

With no flags, just prints the parsed output to the console.
"""

from __future__ import annotations

import argparse
import base64
import gzip
import json
import os


# Load env vars from local.settings.json so this works outside func host
def _load_local_settings():
    settings_path = os.path.join(os.path.dirname(__file__), "local.settings.json")
    if os.path.exists(settings_path):
        with open(settings_path) as f:
            data = json.load(f)
        for k, v in data.get("Values", {}).items():
            if k not in os.environ:
                os.environ[k] = v


_load_local_settings()

import alert
import delivery
import dmarc_parser
import tlsrpt_parser
from graph_client import GraphClient

# ---------------------------------------------------------------------------
# Sample DMARC XML
# ---------------------------------------------------------------------------
SAMPLE_DMARC_XML = """\
<?xml version="1.0" encoding="UTF-8"?>
<feedback>
  <report_metadata>
    <org_name>google.com</org_name>
    <report_id>test-12345</report_id>
    <date_range><begin>1710460800</begin><end>1710547200</end></date_range>
  </report_metadata>
  <policy_published>
    <domain>gieselman.com</domain>
    <p>reject</p>
  </policy_published>
  <record>
    <row>
      <source_ip>209.85.220.41</source_ip>
      <count>150</count>
      <policy_evaluated>
        <disposition>none</disposition>
        <dkim>pass</dkim>
        <spf>pass</spf>
      </policy_evaluated>
    </row>
    <identifiers>
      <header_from>gieselman.com</header_from>
      <envelope_from>gieselman.com</envelope_from>
    </identifiers>
    <auth_results>
      <dkim><domain>gieselman.com</domain></dkim>
      <spf><domain>gieselman.com</domain></spf>
    </auth_results>
  </record>
  <record>
    <row>
      <source_ip>185.99.99.1</source_ip>
      <count>3</count>
      <policy_evaluated>
        <disposition>reject</disposition>
        <dkim>fail</dkim>
        <spf>fail</spf>
      </policy_evaluated>
    </row>
    <identifiers>
      <header_from>gieselman.com</header_from>
      <envelope_from>spoofed.example.com</envelope_from>
    </identifiers>
    <auth_results>
      <dkim><domain>spoofed.example.com</domain></dkim>
      <spf><domain>spoofed.example.com</domain></spf>
    </auth_results>
  </record>
</feedback>
"""

# ---------------------------------------------------------------------------
# Sample TLS-RPT JSON
# ---------------------------------------------------------------------------
SAMPLE_TLSRPT_JSON = json.dumps(
    {
        "organization-name": "google.com",
        "report-id": "tlsrpt-test-67890",
        "date-range": {
            "start-datetime": "2025-03-15T00:00:00Z",
            "end-datetime": "2025-03-16T00:00:00Z",
        },
        "policies": [
            {
                "policy": {
                    "policy-type": "sts",
                    "policy-domain": "gieselman.com",
                },
                "summary": {
                    "total-successful-session-count": 485,
                    "total-failure-session-count": 2,
                },
                "failure-details": [
                    {
                        "result-type": "certificate-expired",
                        "sending-mta-ip": "209.85.220.41",
                        "receiving-mx-hostname": "mail.gieselman.com",
                        "failed-session-count": 2,
                        "failure-reason-code": "Certificate has expired",
                    }
                ],
            }
        ],
    }
)


def main():
    parser = argparse.ArgumentParser(description="Test DMARC/TLS-RPT alert pipeline")
    parser.add_argument("--email", action="store_true", help="Send alert email via Graph")
    parser.add_argument("--teams", action="store_true", help="Post to Teams webhook")
    args = parser.parse_args()

    # -- Parse sample DMARC (gzipped, like a real attachment) ----------------
    dmarc_gz = gzip.compress(SAMPLE_DMARC_XML.encode())
    dmarc_b64 = base64.b64encode(dmarc_gz).decode()
    dmarc_report = dmarc_parser.parse_attachment("google.com!gieselman.com!1710460800!1710547200.xml.gz", dmarc_b64)

    print("=== DMARC Report ===")
    print(f"  Org:      {dmarc_report.org_name}")
    print(f"  Domain:   {dmarc_report.domain}")
    print(f"  Period:   {dmarc_report.date_begin} – {dmarc_report.date_end}")
    print(f"  Records:  {len(dmarc_report.records)}")
    print(f"  Total:    {dmarc_report.total_messages} messages")
    fail_msgs = sum(r.count for r in dmarc_report.failing_records)
    print(f"  Failing:  {len(dmarc_report.failing_records)} records ({fail_msgs} messages)")

    dmarc_alert = alert.build_dmarc_alert(dmarc_report)
    print(f"  Severity: {dmarc_alert.severity.value}")
    print(f"  Title:    {dmarc_alert.title}")
    print()

    # -- Parse sample TLS-RPT -----------------------------------------------
    tlsrpt_gz = gzip.compress(SAMPLE_TLSRPT_JSON.encode())
    tlsrpt_b64 = base64.b64encode(tlsrpt_gz).decode()
    tlsrpt_report = tlsrpt_parser.parse_attachment("google.com!gieselman.com.json.gz", tlsrpt_b64)

    print("=== TLS-RPT Report ===")
    print(f"  Org:        {tlsrpt_report.org_name}")
    print(f"  Period:     {tlsrpt_report.date_begin} – {tlsrpt_report.date_end}")
    print(f"  Policies:   {len(tlsrpt_report.policies)}")
    print(f"  Successful: {tlsrpt_report.total_successful}")
    print(f"  Failed:     {tlsrpt_report.total_failures}")

    tlsrpt_alert = alert.build_tlsrpt_alert(tlsrpt_report)
    print(f"  Severity:   {tlsrpt_alert.severity.value}")
    print(f"  Title:      {tlsrpt_alert.title}")
    print()

    # -- Send alerts ---------------------------------------------------------
    all_alerts = [dmarc_alert, tlsrpt_alert]

    if args.teams:
        for a in all_alerts:
            print(f"Sending Teams alert: {a.title}")
            delivery.send_teams_alert(a)
        print("Teams alerts sent.")

    if args.email:
        graph = GraphClient()
        for a in all_alerts:
            print(f"Sending email alert: {a.title}")
            from_addr = os.environ["ALERT_EMAIL_FROM"]
            to_addr = os.environ["ALERT_EMAIL_TO"]
            graph.send_mail(from_addr, to_addr, a.title, a.body_html)
        print("Email alerts sent.")

    if not args.teams and not args.email:
        print("Dry run complete. Use --email and/or --teams to send alerts.")


if __name__ == "__main__":
    main()
