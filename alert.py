"""Alert formatting and delivery via Teams webhook and Graph email.

This module is the ViewModel layer — it prepares data contexts and passes
them to Jinja2 templates for HTML rendering. No HTML is constructed here.
"""

from __future__ import annotations

import json
import logging
import os
from datetime import UTC, datetime
from pathlib import Path

import requests
from jinja2 import Environment, FileSystemLoader

from graph_client import GraphClient
from models import (
    AlertSeverity,
    AlertSummary,
    DmarcReport,
    ReportRecord,
    TlsRptReport,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Template engine
# ---------------------------------------------------------------------------

_TEMPLATE_DIR = Path(__file__).resolve().parent / "templates"
_env = Environment(loader=FileSystemLoader(_TEMPLATE_DIR), autoescape=True)

SEVERITY_COLOR = {
    AlertSeverity.INFO: "#10b981",
    AlertSeverity.WARNING: "#f59e0b",
    AlertSeverity.CRITICAL: "#ef4444",
}

SEVERITY_LABEL = {
    AlertSeverity.INFO: "ALL CLEAR",
    AlertSeverity.WARNING: "WARNING",
    AlertSeverity.CRITICAL: "CRITICAL",
}

SEVERITY_BG = {
    AlertSeverity.INFO: "#ecfdf5",
    AlertSeverity.WARNING: "#fffbeb",
    AlertSeverity.CRITICAL: "#fef2f2",
}


def _base_context(title: str, severity: AlertSeverity, stat_cards: list[dict]) -> dict:
    """Build the shared template context for the base layout."""
    return {
        "title": title,
        "sev_color": SEVERITY_COLOR[severity],
        "sev_label": SEVERITY_LABEL[severity],
        "sev_bg": SEVERITY_BG[severity],
        "stat_cards": stat_cards,
        "timestamp": f"{datetime.now(UTC):%Y-%m-%d %H:%M} UTC",
    }


def _card(value: str, label: str, color: str = "#1e293b") -> dict:
    return {"value": value, "label": label, "color": color}


# ---------------------------------------------------------------------------
# DMARC alert
# ---------------------------------------------------------------------------


def build_dmarc_alert(report: DmarcReport) -> AlertSummary:
    failing = report.failing_records
    total = report.total_messages
    fail_count = sum(r.count for r in failing)
    pass_count = total - fail_count

    if not failing:
        severity = AlertSeverity.INFO
    elif fail_count / max(total, 1) > 0.1:
        severity = AlertSeverity.CRITICAL
    else:
        severity = AlertSeverity.WARNING

    pass_rate = f"{pass_count / max(total, 1) * 100:.0f}%"

    # Markdown (Teams)
    lines = [
        f"**Org:** {report.org_name}",
        f"**Domain:** {report.domain}",
        f"**Period:** {report.date_begin:%Y-%m-%d} \u2013 {report.date_end:%Y-%m-%d}",
        f"**Policy:** {report.policy.value}",
        f"**Total messages:** {total}",
        f"**Fully failing (DKIM+SPF):** {fail_count}",
    ]
    if failing:
        lines.append("")
        lines.append("| Source IP | Count | DKIM | SPF | Header From |")
        lines.append("|-----------|------:|------|-----|-------------|")
        for r in failing[:20]:
            lines.append(
                f"| {r.source_ip} | {r.count} | {r.dkim_result.value} | {r.spf_result.value} | {r.header_from} |"
            )

    ctx = _base_context(
        "DMARC Aggregate Report",
        severity,
        [
            _card(str(total), "Total Messages"),
            _card(str(pass_count), "Passing", "#166534"),
            _card(str(fail_count), "Failing", "#991b1b" if fail_count > 0 else "#166534"),
            _card(pass_rate, "Pass Rate", "#166534" if pass_count == total else "#b45309"),
            _card(report.policy.value.upper(), "Policy"),
        ],
    )
    ctx["report"] = report
    ctx["records"] = report.records[:50]

    body_html = _env.get_template("dmarc_alert.html").render(ctx)

    return AlertSummary(
        title=f"DMARC Report: {report.domain} ({report.org_name})",
        severity=severity,
        body_markdown="\n".join(lines),
        body_html=body_html,
    )


# ---------------------------------------------------------------------------
# TLS-RPT alert
# ---------------------------------------------------------------------------


def build_tlsrpt_alert(report: TlsRptReport) -> AlertSummary:
    total_fail = report.total_failures
    total_ok = report.total_successful
    total_all = total_ok + total_fail

    if total_fail == 0:
        severity = AlertSeverity.INFO
    elif total_fail / max(total_all, 1) > 0.1:
        severity = AlertSeverity.CRITICAL
    else:
        severity = AlertSeverity.WARNING

    success_rate = f"{total_ok / max(total_all, 1) * 100:.0f}%"

    # Markdown (Teams)
    lines = [
        f"**Org:** {report.org_name}",
        f"**Period:** {report.date_begin:%Y-%m-%d} \u2013 {report.date_end:%Y-%m-%d}",
        f"**Successful sessions:** {total_ok}",
        f"**Failed sessions:** {total_fail}",
    ]
    for pol in report.policies:
        lines.append(f"\n**Policy:** {pol.policy_type} \u2014 {pol.policy_domain}")
        if pol.failure_details:
            lines.append("| Result | MX Host | Failed | Reason |")
            lines.append("|--------|---------|-------:|--------|")
            for fd in pol.failure_details[:20]:
                lines.append(
                    f"| {fd.result_type} | {fd.receiving_mx_hostname} | {fd.failed_session_count} | {fd.failure_reason_code} |"
                )

    # Flatten policies into row dicts for template
    policies_rows = []
    for pol in report.policies:
        if pol.failure_details:
            for fd in pol.failure_details[:20]:
                policies_rows.append(
                    {
                        "domain": str(pol.policy_domain),
                        "policy_type": pol.policy_type.upper(),
                        "result": fd.result_type,
                        "mx_host": fd.receiving_mx_hostname,
                        "failed": fd.failed_session_count,
                        "reason": fd.failure_reason_code,
                    }
                )
        else:
            policies_rows.append(
                {
                    "domain": str(pol.policy_domain),
                    "policy_type": pol.policy_type.upper(),
                    "result": "successful",
                    "mx_host": "\u2014",
                    "failed": 0,
                    "reason": "\u2014",
                }
            )

    ctx = _base_context(
        "TLS-RPT Report",
        severity,
        [
            _card(str(total_all), "Total Sessions"),
            _card(str(total_ok), "Successful", "#166534"),
            _card(str(total_fail), "Failed", "#991b1b" if total_fail > 0 else "#166534"),
            _card(success_rate, "Success Rate", "#166534" if total_fail == 0 else "#b45309"),
        ],
    )
    ctx["report"] = report
    ctx["policies"] = policies_rows

    body_html = _env.get_template("tlsrpt_alert.html").render(ctx)

    return AlertSummary(
        title=f"TLS-RPT: {report.org_name}",
        severity=severity,
        body_markdown="\n".join(lines),
        body_html=body_html,
    )


# ---------------------------------------------------------------------------
# Weekly summary
# ---------------------------------------------------------------------------


def build_weekly_summary(records: list[ReportRecord], days: int = 7) -> AlertSummary:
    """Build a summary alert from accumulated report records."""
    dmarc = [r for r in records if r.report_type == "dmarc"]
    tlsrpt = [r for r in records if r.report_type == "tlsrpt"]

    dmarc_reports = len(dmarc)
    tlsrpt_reports = len(tlsrpt)
    total_reports = dmarc_reports + tlsrpt_reports

    dmarc_messages = sum(r.total_messages for r in dmarc)
    dmarc_pass = sum(r.pass_count for r in dmarc)
    dmarc_fail = sum(r.fail_count for r in dmarc)
    dmarc_pass_rate = f"{dmarc_pass / max(dmarc_messages, 1) * 100:.1f}%"

    tls_total = sum(r.pass_count + r.fail_count for r in tlsrpt)
    tls_pass = sum(r.pass_count for r in tlsrpt)
    tls_fail = sum(r.fail_count for r in tlsrpt)
    tls_pass_rate = f"{tls_pass / max(tls_total, 1) * 100:.1f}%"

    total_bytes = sum(r.attachment_size_bytes for r in records)
    total_size = _format_bytes(total_bytes)

    # Aggregations
    org_volumes: dict[str, int] = {}
    for r in records:
        org_volumes[r.org_name] = org_volumes.get(r.org_name, 0) + r.total_messages
    top_senders = sorted(org_volumes.items(), key=lambda x: x[1], reverse=True)[:10]

    policy_counts: dict[str, int] = {}
    for r in dmarc:
        policy_counts[r.policy] = policy_counts.get(r.policy, 0) + r.total_messages
    policy_dist = sorted(policy_counts.items(), key=lambda x: x[1], reverse=True)

    failure_orgs: dict[str, int] = {}
    for r in records:
        if r.fail_count > 0:
            failure_orgs[r.org_name] = failure_orgs.get(r.org_name, 0) + r.fail_count
    top_failures = sorted(failure_orgs.items(), key=lambda x: x[1], reverse=True)[:10]

    # Severity
    total_fail = dmarc_fail + tls_fail
    total_all = dmarc_messages + tls_total
    if total_fail == 0:
        severity = AlertSeverity.INFO
    elif total_fail / max(total_all, 1) > 0.1:
        severity = AlertSeverity.CRITICAL
    else:
        severity = AlertSeverity.WARNING

    # Markdown (Teams)
    md_lines = [
        f"**Period:** Last {days} days",
        f"**Total reports:** {total_reports} ({dmarc_reports} DMARC, {tlsrpt_reports} TLS-RPT)",
        f"**Attachment volume:** {total_size}",
        "",
        f"**DMARC:** {dmarc_messages} messages \u2014 {dmarc_pass} pass, {dmarc_fail} fail ({dmarc_pass_rate})",
        f"**TLS-RPT:** {tls_total} sessions \u2014 {tls_pass} pass, {tls_fail} fail ({tls_pass_rate})",
    ]
    if top_senders:
        md_lines.extend(["", "**Top Senders:**"])
        for org, vol in top_senders[:5]:
            md_lines.append(f"- {org}: {vol:,} messages")

    # Structured data for template
    senders = []
    for org, vol in top_senders:
        org_dmarc = sum(r.total_messages for r in dmarc if r.org_name == org)
        org_tls = sum(r.pass_count + r.fail_count for r in tlsrpt if r.org_name == org)
        org_fails = failure_orgs.get(org, 0)
        senders.append({"org": org, "volume": vol, "dmarc": org_dmarc, "tls": org_tls, "fails": org_fails})

    policy_dist_data = []
    for pol, count in policy_dist:
        pct = f"{count / max(dmarc_messages, 1) * 100:.0f}%"
        color = "#166534" if pol == "reject" else "#b45309" if pol == "quarantine" else "#991b1b"
        policy_dist_data.append({"policy": pol, "count": count, "pct": pct, "color": color})

    failures_data = [{"org": org, "count": count} for org, count in top_failures]

    # Aggregate DMARC failure details across all records
    dmarc_failure_agg: dict[tuple[str, str], dict] = {}
    for r in dmarc:
        if r.dmarc_failure_details_json:
            for fd in json.loads(r.dmarc_failure_details_json):
                key = (fd["source_ip"], fd["header_from"])
                if key in dmarc_failure_agg:
                    dmarc_failure_agg[key]["count"] += fd["count"]
                else:
                    dmarc_failure_agg[key] = {**fd}
    dmarc_failures_data = sorted(dmarc_failure_agg.values(), key=lambda x: x["count"], reverse=True)[:20]

    # Aggregate TLS failure details across all records
    tls_failure_agg: dict[tuple[str, str, str], dict] = {}
    for r in tlsrpt:
        if r.tls_failure_details_json:
            for fd in json.loads(r.tls_failure_details_json):
                tls_key = (fd["result_type"], fd["receiving_mx_hostname"], fd["failure_reason_code"])
                if tls_key in tls_failure_agg:
                    tls_failure_agg[tls_key]["failed_session_count"] += fd["failed_session_count"]
                else:
                    tls_failure_agg[tls_key] = {**fd}
    tls_failures_data = sorted(tls_failure_agg.values(), key=lambda x: x["failed_session_count"], reverse=True)[:20]

    if dmarc_failures_data:
        md_lines.extend(["", "**DMARC Failure Details:**"])
        md_lines.append("| Source IP | Count | DKIM | SPF | Header From |")
        md_lines.append("|-----------|------:|------|-----|-------------|")
        for fd in dmarc_failures_data[:10]:
            md_lines.append(
                f"| {fd['source_ip']} | {fd['count']} | {fd['dkim_result']} | {fd['spf_result']} | {fd['header_from']} |"
            )

    if tls_failures_data:
        md_lines.extend(["", "**TLS-RPT Failure Details:**"])
        md_lines.append("| Result Type | MX Host | Failed | Reason |")
        md_lines.append("|-------------|---------|-------:|--------|")
        for fd in tls_failures_data[:10]:
            md_lines.append(
                f"| {fd['result_type']} | {fd['receiving_mx_hostname']} | {fd['failed_session_count']} | {fd['failure_reason_code'] or '—'} |"
            )

    ctx = _base_context(
        "Weekly Email Security Summary",
        severity,
        [
            _card(str(total_reports), "Reports"),
            _card(str(dmarc_messages), "DMARC Messages"),
            _card(dmarc_pass_rate, "DMARC Pass Rate", "#166534" if dmarc_fail == 0 else "#b45309"),
            _card(str(tls_total), "TLS Sessions"),
            _card(tls_pass_rate, "TLS Pass Rate", "#166534" if tls_fail == 0 else "#b45309"),
        ],
    )
    ctx.update(
        {
            "days": days,
            "total_reports": total_reports,
            "total_size": total_size,
            "senders": senders,
            "policy_dist": policy_dist_data,
            "top_failures": failures_data,
            "dmarc_failures": dmarc_failures_data,
            "tls_failures": tls_failures_data,
        }
    )

    body_html = _env.get_template("weekly_summary.html").render(ctx)

    return AlertSummary(
        title=f"Weekly Email Security Summary \u2014 {total_reports} reports",
        severity=severity,
        body_markdown="\n".join(md_lines),
        body_html=body_html,
    )


def _format_bytes(size: int) -> str:
    n = float(size)
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.1f} {unit}" if unit != "B" else f"{int(n)} B"
        n /= 1024
    return f"{n:.1f} TB"


# ---------------------------------------------------------------------------
# Delivery
# ---------------------------------------------------------------------------


def send_teams_alert(alert_summary: AlertSummary) -> None:
    webhook_url = os.environ.get("TEAMS_WEBHOOK_URL", "")
    if not webhook_url:
        logger.debug("TEAMS_WEBHOOK_URL not set; skipping Teams notification")
        return

    card = {
        "type": "message",
        "attachments": [
            {
                "contentType": "application/vnd.microsoft.card.adaptive",
                "contentUrl": None,
                "content": {
                    "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                    "type": "AdaptiveCard",
                    "version": "1.4",
                    "body": [
                        {
                            "type": "TextBlock",
                            "size": "Large",
                            "weight": "Bolder",
                            "text": alert_summary.title,
                            "color": "Attention" if alert_summary.severity != AlertSeverity.INFO else "Good",
                        },
                        {"type": "TextBlock", "text": alert_summary.body_markdown, "wrap": True},
                        {
                            "type": "TextBlock",
                            "text": f"_{alert_summary.timestamp:%Y-%m-%d %H:%M UTC}_",
                            "isSubtle": True,
                            "size": "Small",
                        },
                    ],
                },
            }
        ],
    }

    resp = requests.post(webhook_url, json=card, timeout=30)
    resp.raise_for_status()
    logger.info("Teams alert sent: %s", alert_summary.title)


def send_generic_webhook(alert_summary: AlertSummary) -> None:
    """POST alert as JSON to a generic webhook URL (Slack, Discord, n8n, etc.)."""
    webhook_url = os.environ.get("GENERIC_WEBHOOK_URL", "")
    if not webhook_url:
        return

    payload = {
        "title": alert_summary.title,
        "severity": alert_summary.severity.value,
        "body": alert_summary.body_markdown,
        "timestamp": alert_summary.timestamp.isoformat(),
    }

    resp = requests.post(webhook_url, json=payload, timeout=30)
    resp.raise_for_status()
    logger.info("Generic webhook sent: %s", alert_summary.title)


def send_email_alert(alert_summary: AlertSummary, graph: GraphClient) -> None:
    enabled = os.environ.get("ALERT_EMAIL_ENABLED", "false").lower() == "true"
    if not enabled:
        return

    from_addr = os.environ["ALERT_EMAIL_FROM"]
    to_addr = os.environ["ALERT_EMAIL_TO"]
    graph.send_mail(from_addr, to_addr, alert_summary.title, alert_summary.body_html)
