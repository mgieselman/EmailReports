"""Alert formatting — severity logic and HTML generation.

This module is the ViewModel layer — it prepares data contexts and passes
them to Jinja2 templates for HTML rendering. No HTML is constructed here.
"""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from pathlib import Path

from jinja2 import Environment, FileSystemLoader

from models import (
    AlertSeverity,
    AlertSummary,
    DmarcReport,
    ReportRecord,
    TlsRptReport,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

FAILURE_RATE_CRITICAL_THRESHOLD = 0.1
"""Failure rate above which severity escalates to CRITICAL."""

# ---------------------------------------------------------------------------
# Template engine
# ---------------------------------------------------------------------------

_TEMPLATE_DIR = Path(__file__).resolve().parent / "templates"
_env = Environment(loader=FileSystemLoader(_TEMPLATE_DIR), autoescape=True)

SEVERITY_COLOR = {
    AlertSeverity.INFO: "#4caf50",
    AlertSeverity.WARNING: "#ef6c00",
    AlertSeverity.CRITICAL: "#ef5350",
}

SEVERITY_LABEL = {
    AlertSeverity.INFO: "ALL CLEAR",
    AlertSeverity.WARNING: "WARNING",
    AlertSeverity.CRITICAL: "CRITICAL",
}

SEVERITY_BG = {
    AlertSeverity.INFO: "#1c1c1c",
    AlertSeverity.WARNING: "#1c1c1c",
    AlertSeverity.CRITICAL: "#1c1c1c",
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


def _card(value: str, label: str, color: str = "#ffffff") -> dict:
    """Build a stat card dict. Default color is white for dark theme."""
    return {"value": value, "label": label, "color": color}


def _classify_severity(fail_count: int, total: int, *, has_failures: bool) -> AlertSeverity:
    """Determine severity from failure count and total."""
    if not has_failures:
        return AlertSeverity.INFO
    if fail_count / max(total, 1) > FAILURE_RATE_CRITICAL_THRESHOLD:
        return AlertSeverity.CRITICAL
    return AlertSeverity.WARNING


# ---------------------------------------------------------------------------
# DMARC alert
# ---------------------------------------------------------------------------


def build_dmarc_alert(report: DmarcReport) -> AlertSummary:
    failing = report.failing_records
    total = report.total_messages
    fail_count = sum(r.count for r in failing)
    pass_count = total - fail_count

    severity = _classify_severity(fail_count, total, has_failures=bool(failing))

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
            _card(str(pass_count), "Passing"),
            _card(str(fail_count), "Failing"),
            _card(pass_rate, "Pass Rate", "#4caf50" if pass_count == total else "#ef6c00"),
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

    severity = _classify_severity(total_fail, total_all, has_failures=total_fail > 0)

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
            _card(str(total_ok), "Successful"),
            _card(str(total_fail), "Failed"),
            _card(success_rate, "Success Rate", "#4caf50" if total_fail == 0 else "#ef6c00"),
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
# Weekly summary — aggregation helpers
# ---------------------------------------------------------------------------


def _aggregate_org_volumes(records: list[ReportRecord]) -> list[tuple[str, int]]:
    """Return top 10 orgs by total message volume, descending."""
    volumes: dict[str, int] = {}
    for r in records:
        volumes[r.org_name] = volumes.get(r.org_name, 0) + r.total_messages
    return sorted(volumes.items(), key=lambda x: x[1], reverse=True)[:10]


def _aggregate_policy_distribution(dmarc: list[ReportRecord]) -> list[tuple[str, int]]:
    """Return DMARC policy distribution sorted by count, descending."""
    counts: dict[str, int] = {}
    for r in dmarc:
        counts[r.policy] = counts.get(r.policy, 0) + r.total_messages
    return sorted(counts.items(), key=lambda x: x[1], reverse=True)


def _aggregate_failure_orgs(records: list[ReportRecord]) -> dict[str, int]:
    """Return org -> failure count for orgs with failures."""
    orgs: dict[str, int] = {}
    for r in records:
        if r.fail_count > 0:
            orgs[r.org_name] = orgs.get(r.org_name, 0) + r.fail_count
    return orgs


def _aggregate_dmarc_failures(dmarc: list[ReportRecord]) -> list[dict]:
    """Aggregate DMARC failure details across records, top 20 by count."""
    agg: dict[tuple[str, str], dict] = {}
    for r in dmarc:
        if r.dmarc_failure_details_json:
            for fd in json.loads(r.dmarc_failure_details_json):
                key = (fd["source_ip"], fd["header_from"])
                if key in agg:
                    agg[key]["count"] += fd["count"]
                else:
                    agg[key] = {**fd}
    return sorted(agg.values(), key=lambda x: x["count"], reverse=True)[:20]


def _aggregate_tls_failures(tlsrpt: list[ReportRecord]) -> list[dict]:
    """Aggregate TLS failure details across records, top 20 by session count."""
    agg: dict[tuple[str, str, str], dict] = {}
    for r in tlsrpt:
        if r.tls_failure_details_json:
            for fd in json.loads(r.tls_failure_details_json):
                key = (fd["result_type"], fd["receiving_mx_hostname"], fd["failure_reason_code"])
                if key in agg:
                    agg[key]["failed_session_count"] += fd["failed_session_count"]
                else:
                    agg[key] = {**fd}
    return sorted(agg.values(), key=lambda x: x["failed_session_count"], reverse=True)[:20]


def _build_sender_details(
    top_senders: list[tuple[str, int]],
    dmarc: list[ReportRecord],
    tlsrpt: list[ReportRecord],
    failure_orgs: dict[str, int],
) -> list[dict]:
    """Build per-sender detail dicts for the summary template."""
    senders = []
    for org, vol in top_senders:
        org_dmarc = sum(r.total_messages for r in dmarc if r.org_name == org)
        org_tls = sum(r.pass_count + r.fail_count for r in tlsrpt if r.org_name == org)
        org_fails = failure_orgs.get(org, 0)
        senders.append({"org": org, "volume": vol, "dmarc": org_dmarc, "tls": org_tls, "fails": org_fails})
    return senders


# ---------------------------------------------------------------------------
# Weekly summary — main builder
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
    top_senders = _aggregate_org_volumes(records)
    policy_dist = _aggregate_policy_distribution(dmarc)
    failure_orgs = _aggregate_failure_orgs(records)
    top_failures = sorted(failure_orgs.items(), key=lambda x: x[1], reverse=True)[:10]
    dmarc_failures_data = _aggregate_dmarc_failures(dmarc)
    tls_failures_data = _aggregate_tls_failures(tlsrpt)

    # Severity
    total_fail = dmarc_fail + tls_fail
    total_all = dmarc_messages + tls_total
    severity = _classify_severity(total_fail, total_all, has_failures=total_fail > 0)

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
                f"| {fd['result_type']} | {fd['receiving_mx_hostname']} | {fd['failed_session_count']} | {fd['failure_reason_code'] or '\u2014'} |"
            )

    # Structured data for template
    senders = _build_sender_details(top_senders, dmarc, tlsrpt, failure_orgs)

    policy_dist_data = []
    for pol, count in policy_dist:
        pct = f"{count / max(dmarc_messages, 1) * 100:.0f}%"
        color = "#4caf50" if pol == "reject" else "#ef6c00" if pol == "quarantine" else "#ef5350"
        policy_dist_data.append({"policy": pol, "count": count, "pct": pct, "color": color})

    failures_data = [{"org": org, "count": count} for org, count in top_failures]

    ctx = _base_context(
        "Weekly Email Security Summary",
        severity,
        [
            _card(str(total_reports), "Reports"),
            _card(str(dmarc_messages), "DMARC Messages"),
            _card(dmarc_pass_rate, "DMARC Pass Rate", "#4caf50" if dmarc_fail == 0 else "#ef6c00"),
            _card(str(tls_total), "TLS Sessions"),
            _card(tls_pass_rate, "TLS Pass Rate", "#4caf50" if tls_fail == 0 else "#ef6c00"),
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
