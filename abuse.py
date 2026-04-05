"""Automated abuse reporting for detected domain spoofing.

When DMARC reports reveal confirmed spoofing (SPF=fail, DKIM=fail,
disposition=reject), this module sends abuse reports to the hosting
provider responsible for the offending source IP.  Two emails are sent
per incident: a plain-text report and an ARF (RFC 5965) formatted
report, since the receiver's preference is unknown.
"""

from __future__ import annotations

import base64
import logging
import os
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

import rdap
import storage
from alert import _env
from graph_client import GraphClient
from models import (
    AbuseReportRecord,
    DmarcDisposition,
    DmarcRecord,
    DmarcReport,
    DmarcResult,
)

logger = logging.getLogger(__name__)

_USER_AGENT = "EmailReports/1.0"


def is_abuse_reporting_enabled() -> bool:
    """Return ``True`` when the operator has opted in to abuse reporting."""
    return os.environ.get("ABUSE_REPORTING_ENABLED", "false").lower() == "true"


def find_spoofing_records(report: DmarcReport) -> list[DmarcRecord]:
    """Return records that represent confirmed spoofing.

    A record qualifies when SPF and DKIM both fail and the receiving
    server rejected the message (disposition=reject).
    """
    return [
        r
        for r in report.records
        if r.dkim_result == DmarcResult.FAIL
        and r.spf_result == DmarcResult.FAIL
        and r.disposition == DmarcDisposition.REJECT
    ]


def send_abuse_reports(
    report: DmarcReport,
    xml_attachment_name: str,
    xml_attachment_b64: str,
    graph: GraphClient,
) -> int:
    """Send abuse reports for every unique spoofing source IP in *report*.

    Returns the number of abuse reports successfully sent (each IP counts
    as one report even though two emails are dispatched per IP).
    """
    spoofing = find_spoofing_records(report)
    if not spoofing:
        return 0

    ip_counts: dict[str, int] = {}
    for rec in spoofing:
        ip_counts[rec.source_ip] = ip_counts.get(rec.source_ip, 0) + rec.count

    from_addr = f"postmaster@{report.domain}"
    sent = 0

    for source_ip, count in ip_counts.items():
        try:
            sent += _report_single_ip(
                report,
                source_ip,
                count,
                from_addr,
                xml_attachment_name,
                xml_attachment_b64,
                graph,
            )
        except Exception:
            logger.exception("Abuse report failed for IP %s", source_ip)

    return sent


def _abuse_subject(source_ip: str, domain: str) -> str:
    return f"Abuse Report: Spoofed emails from {source_ip} impersonating {domain}"


def _report_single_ip(
    report: DmarcReport,
    source_ip: str,
    count: int,
    from_addr: str,
    xml_attachment_name: str,
    xml_attachment_b64: str,
    graph: GraphClient,
) -> int:
    """Process a single source IP: dedup, lookup, send, save.  Returns 1 on success, 0 otherwise."""
    if storage.abuse_report_exists(source_ip):
        logger.debug("Abuse report already sent for %s this week; skipping", source_ip)
        return 0

    abuse_email = rdap.lookup_abuse_contact(source_ip)
    if not abuse_email:
        logger.warning("No abuse contact found for %s; skipping", source_ip)
        return 0

    date_range = f"{report.date_begin:%Y-%m-%d} to {report.date_end:%Y-%m-%d}"
    subject = _abuse_subject(source_ip, report.domain)
    xml_att = {"name": xml_attachment_name, "content_b64": xml_attachment_b64}

    html_body = _render_plain_report(report, source_ip, count, date_range)
    graph.send_mail(from_addr, abuse_email, subject, html_body, attachments=[xml_att])

    arf_b64 = _build_arf_message(report, source_ip, count, from_addr, abuse_email, date_range)
    arf_att = {"name": f"abuse-report-{source_ip}.eml", "content_b64": arf_b64}
    arf_body = _env.get_template("abuse_arf_carrier.html").render()
    graph.send_mail(from_addr, abuse_email, f"[ARF] {subject}", arf_body, attachments=[xml_att, arf_att])

    storage.save_abuse_report(
        AbuseReportRecord(
            source_ip=source_ip,
            abuse_email=abuse_email,
            domain=report.domain,
            report_count=count,
        )
    )
    logger.info("Abuse reports sent for %s → %s (%d message(s))", source_ip, abuse_email, count)
    return 1


def _render_plain_report(report: DmarcReport, source_ip: str, count: int, date_range: str) -> str:
    """Render the human-readable abuse report HTML."""
    template = _env.get_template("abuse_report.html")
    return template.render(
        domain=report.domain,
        source_ip=source_ip,
        message_count=count,
        date_range=date_range,
        org_name=report.org_name,
        report_id=report.report_id,
    )


def _build_arf_message(
    report: DmarcReport,
    source_ip: str,
    count: int,
    from_addr: str,
    to_addr: str,
    date_range: str,
) -> str:
    """Build an ARF (RFC 5965) MIME message and return it base64-encoded."""
    msg = MIMEMultipart("mixed")
    msg["From"] = from_addr
    msg["To"] = to_addr
    msg["Subject"] = _abuse_subject(source_ip, report.domain)
    msg["Auto-Submitted"] = "auto-generated"
    msg["X-Mailer"] = _USER_AGENT

    # Part 1: human-readable summary.
    human_text = (
        f"This is an abuse report for spoofed emails.\n\n"
        f"Source IP: {source_ip}\n"
        f"Spoofed Domain: {report.domain}\n"
        f"Message Count: {count}\n"
        f"Period: {date_range}\n"
        f"Reporting Organization: {report.org_name}\n"
        f"DMARC Report ID: {report.report_id}\n"
        f"SPF: fail | DKIM: fail | Disposition: reject\n"
    )
    msg.attach(MIMEText(human_text, "plain"))

    # Part 2: machine-readable feedback report (RFC 5965).
    arrival = report.date_end.strftime("%a, %d %b %Y %H:%M:%S +0000")
    feedback_fields = (
        f"Feedback-Type: auth-failure\r\n"
        f"User-Agent: {_USER_AGENT}\r\n"
        f"Version: 1\r\n"
        f"Original-Mail-From: <>\r\n"
        f"Arrival-Date: {arrival}\r\n"
        f"Source-IP: {source_ip}\r\n"
        f"Source-IP-Count: {count}\r\n"
        f"Reported-Domain: {report.domain}\r\n"
        f"Authentication-Results: dmarc=fail (p=reject); dkim=fail; spf=fail\r\n"
    )
    feedback_part = MIMEBase("message", "feedback-report")
    feedback_part.set_payload(feedback_fields)
    msg.attach(feedback_part)

    return base64.b64encode(msg.as_bytes()).decode()
