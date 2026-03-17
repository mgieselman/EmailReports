"""Alert formatting and delivery via Teams webhook and Graph email."""

from __future__ import annotations

import html
import logging
import os
from datetime import UTC, datetime

import requests

from graph_client import GraphClient
from models import (
    AlertSeverity,
    AlertSummary,
    DmarcReport,
    TlsRptReport,
)

logger = logging.getLogger(__name__)

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


# ---------------------------------------------------------------------------
# Shared HTML helpers
# ---------------------------------------------------------------------------


def _status_badge(result: str, pass_value: str = "pass") -> str:
    """Render a pass/fail pill badge."""
    is_pass = result.lower() == pass_value.lower()
    bg = "#dcfce7" if is_pass else "#fee2e2"
    fg = "#166534" if is_pass else "#991b1b"
    label = result.upper()
    return (
        f'<span style="display:inline-block;padding:2px 10px;border-radius:12px;'
        f"font-size:11px;font-weight:600;letter-spacing:0.5px;"
        f'background:{bg};color:{fg}">{label}</span>'
    )


def _stat_card(value: str, label: str, color: str = "#1e293b") -> str:
    """Render a KPI stat card for the dashboard row."""
    return (
        f'<td style="padding:0 8px"><div style="background:#ffffff;border:1px solid #e2e8f0;'
        f'border-radius:8px;padding:16px 20px;text-align:center;min-width:100px">'
        f'<div style="font-size:28px;font-weight:700;color:{color};line-height:1.1">{value}</div>'
        f'<div style="font-size:11px;color:#64748b;text-transform:uppercase;letter-spacing:0.5px;'
        f'margin-top:4px">{label}</div></div></td>'
    )


def _wrap_dashboard(
    title: str, severity: AlertSeverity, subtitle: str, stat_cards_html: str, table_html: str, timestamp: str
) -> str:
    """Wrap content in the full dashboard email layout."""
    sev_color = SEVERITY_COLOR[severity]
    sev_label = SEVERITY_LABEL[severity]
    sev_bg = SEVERITY_BG[severity]

    return f"""\
<!DOCTYPE html>
<html><head><meta charset="utf-8"></head>
<body style="margin:0;padding:0;background:#f1f5f9;font-family:'Segoe UI',Roboto,Helvetica,Arial,sans-serif">
<table width="100%" cellpadding="0" cellspacing="0" style="background:#f1f5f9;padding:24px 0">
<tr><td align="center">
<table width="640" cellpadding="0" cellspacing="0" style="background:#ffffff;border-radius:12px;overflow:hidden;box-shadow:0 1px 3px rgba(0,0,0,0.1)">

  <!-- Header bar -->
  <tr><td style="background:#0f172a;padding:20px 28px">
    <table width="100%" cellpadding="0" cellspacing="0"><tr>
      <td style="color:#ffffff;font-size:18px;font-weight:600">{title}</td>
      <td align="right">
        <span style="display:inline-block;padding:4px 14px;border-radius:20px;font-size:11px;
              font-weight:700;letter-spacing:1px;background:{sev_color};color:#ffffff">{sev_label}</span>
      </td>
    </tr></table>
  </td></tr>

  <!-- Subtitle / meta -->
  <tr><td style="background:#1e293b;padding:10px 28px;color:#94a3b8;font-size:12px">
    {subtitle}
  </td></tr>

  <!-- Stat cards -->
  <tr><td style="padding:20px 20px 12px;background:{sev_bg}">
    <table cellpadding="0" cellspacing="0" style="width:100%"><tr>
      {stat_cards_html}
    </tr></table>
  </td></tr>

  <!-- Data table -->
  <tr><td style="padding:12px 20px 24px">
    {table_html}
  </td></tr>

  <!-- Footer -->
  <tr><td style="background:#f8fafc;padding:14px 28px;border-top:1px solid #e2e8f0">
    <table width="100%" cellpadding="0" cellspacing="0"><tr>
      <td style="color:#94a3b8;font-size:11px">gieselman.com Email Security Monitor</td>
      <td align="right" style="color:#94a3b8;font-size:11px">{timestamp}</td>
    </tr></table>
  </td></tr>

</table>
</td></tr></table>
</body></html>"""


def _build_table(headers: list[str], rows: list[list[str]]) -> str:
    """Build a styled HTML table."""
    th_style = (
        "padding:10px 12px;text-align:left;font-size:11px;font-weight:600;"
        "text-transform:uppercase;letter-spacing:0.5px;color:#64748b;"
        "background:#f8fafc;border-bottom:2px solid #e2e8f0"
    )
    td_style = "padding:9px 12px;font-size:13px;color:#334155;border-bottom:1px solid #f1f5f9"

    parts = ['<table width="100%" cellpadding="0" cellspacing="0" style="border-collapse:collapse">']
    parts.append("<tr>")
    for h in headers:
        parts.append(f'<th style="{th_style}">{h}</th>')
    parts.append("</tr>")

    for i, row in enumerate(rows):
        bg = "#ffffff" if i % 2 == 0 else "#f8fafc"
        parts.append(f'<tr style="background:{bg}">')
        for cell in row:
            parts.append(f'<td style="{td_style}">{cell}</td>')
        parts.append("</tr>")

    parts.append("</table>")
    return "".join(parts)


# ---------------------------------------------------------------------------
# Build alert summaries from parsed reports
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

    # Markdown for Teams
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
    body_md = "\n".join(lines)

    # HTML dashboard email
    subtitle = (
        f"Reporter: <strong style='color:#e2e8f0'>{report.org_name}</strong> &nbsp;&bull;&nbsp; "
        f"Domain: <strong style='color:#e2e8f0'>{report.domain}</strong> &nbsp;&bull;&nbsp; "
        f"Period: <strong style='color:#e2e8f0'>{report.date_begin:%Y-%m-%d}</strong> to "
        f"<strong style='color:#e2e8f0'>{report.date_end:%Y-%m-%d}</strong>"
    )

    pass_rate = f"{pass_count / max(total, 1) * 100:.0f}%"
    stat_cards = (
        _stat_card(str(total), "Total Messages")
        + _stat_card(str(pass_count), "Passing", "#166534")
        + _stat_card(str(fail_count), "Failing", "#991b1b" if fail_count > 0 else "#166534")
        + _stat_card(pass_rate, "Pass Rate", "#166534" if pass_count == total else "#b45309")
        + _stat_card(report.policy.value.upper(), "Policy")
    )

    table_rows = []
    for r in report.records[:50]:
        table_rows.append(
            [
                f'<span style="font-family:monospace;font-size:12px">{html.escape(r.source_ip)}</span>',
                f'<span style="font-weight:600">{r.count}</span>',
                _status_badge(r.dkim_result.value),
                _status_badge(r.spf_result.value),
                html.escape(r.header_from),
                f'<span style="font-size:11px;color:#64748b">{html.escape(r.dkim_domain) or "—"}</span>',
            ]
        )

    table_html = _build_table(
        ["Source IP", "Count", "DKIM", "SPF", "Header From", "Auth Domain"],
        table_rows,
    )

    body_html = _wrap_dashboard(
        title="DMARC Aggregate Report",
        severity=severity,
        subtitle=subtitle,
        stat_cards_html=stat_cards,
        table_html=table_html,
        timestamp=f"{datetime.now(UTC):%Y-%m-%d %H:%M} UTC",
    )

    return AlertSummary(
        title=f"DMARC Report: {report.domain} ({report.org_name})",
        severity=severity,
        body_markdown=body_md,
        body_html=body_html,
    )


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

    # Markdown for Teams
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
    body_md = "\n".join(lines)

    # HTML dashboard email
    subtitle = (
        f"Reporter: <strong style='color:#e2e8f0'>{report.org_name}</strong> &nbsp;&bull;&nbsp; "
        f"Period: <strong style='color:#e2e8f0'>{report.date_begin:%Y-%m-%d}</strong> to "
        f"<strong style='color:#e2e8f0'>{report.date_end:%Y-%m-%d}</strong>"
    )

    success_rate = f"{total_ok / max(total_all, 1) * 100:.0f}%"
    stat_cards = (
        _stat_card(str(total_all), "Total Sessions")
        + _stat_card(str(total_ok), "Successful", "#166534")
        + _stat_card(str(total_fail), "Failed", "#991b1b" if total_fail > 0 else "#166534")
        + _stat_card(success_rate, "Success Rate", "#166534" if total_fail == 0 else "#b45309")
    )

    table_rows = []
    for pol in report.policies:
        if pol.failure_details:
            for fd in pol.failure_details[:20]:
                table_rows.append(
                    [
                        f'<span style="font-weight:600">{html.escape(str(pol.policy_domain))}</span>',
                        html.escape(pol.policy_type.upper()),
                        _status_badge(fd.result_type, pass_value="successful"),
                        html.escape(fd.receiving_mx_hostname),
                        f'<span style="font-weight:600">{fd.failed_session_count}</span>',
                        f'<span style="font-size:11px;color:#64748b">{html.escape(fd.failure_reason_code)}</span>',
                    ]
                )
        else:
            table_rows.append(
                [
                    f'<span style="font-weight:600">{html.escape(str(pol.policy_domain))}</span>',
                    html.escape(pol.policy_type.upper()),
                    _status_badge("successful", pass_value="successful"),
                    "—",
                    "0",
                    "—",
                ]
            )

    table_html = _build_table(
        ["Domain", "Policy", "Result", "MX Host", "Failed", "Reason"],
        table_rows,
    )

    body_html = _wrap_dashboard(
        title="TLS-RPT Report",
        severity=severity,
        subtitle=subtitle,
        stat_cards_html=stat_cards,
        table_html=table_html,
        timestamp=f"{datetime.now(UTC):%Y-%m-%d %H:%M} UTC",
    )

    return AlertSummary(
        title=f"TLS-RPT: {report.org_name}",
        severity=severity,
        body_markdown=body_md,
        body_html=body_html,
    )


# ---------------------------------------------------------------------------
# Delivery
# ---------------------------------------------------------------------------


def send_teams_alert(alert: AlertSummary) -> None:
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
                            "text": alert.title,
                            "color": "Attention" if alert.severity != AlertSeverity.INFO else "Good",
                        },
                        {
                            "type": "TextBlock",
                            "text": alert.body_markdown,
                            "wrap": True,
                        },
                        {
                            "type": "TextBlock",
                            "text": f"_{alert.timestamp:%Y-%m-%d %H:%M UTC}_",
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
    logger.info("Teams alert sent: %s", alert.title)


def send_generic_webhook(alert: AlertSummary) -> None:
    """POST alert as JSON to a generic webhook URL (Slack, Discord, n8n, etc.)."""
    webhook_url = os.environ.get("GENERIC_WEBHOOK_URL", "")
    if not webhook_url:
        return

    payload = {
        "title": alert.title,
        "severity": alert.severity.value,
        "body": alert.body_markdown,
        "timestamp": alert.timestamp.isoformat(),
    }

    resp = requests.post(webhook_url, json=payload, timeout=30)
    resp.raise_for_status()
    logger.info("Generic webhook sent: %s", alert.title)


def send_email_alert(alert: AlertSummary, graph: GraphClient) -> None:
    enabled = os.environ.get("ALERT_EMAIL_ENABLED", "false").lower() == "true"
    if not enabled:
        return

    from_addr = os.environ["ALERT_EMAIL_FROM"]
    to_addr = os.environ["ALERT_EMAIL_TO"]
    graph.send_mail(from_addr, to_addr, alert.title, alert.body_html)
