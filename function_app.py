"""Azure Function: timer-triggered DMARC & TLS-RPT report processor."""

from __future__ import annotations

import logging
import os
from base64 import b64decode
from collections.abc import Callable
from typing import Any

import azure.functions as func

import abuse
import alert
import delivery
import dmarc_parser
import models
import storage
import tlsrpt_parser
from graph_client import GraphClient
from models import AlertSummary, DmarcReport, ReportRecord, TlsRptReport

app = func.FunctionApp()
logger = logging.getLogger(__name__)


_REQUIRED_ENV_VARS = ["REPORT_MAILBOX", "AZURE_TENANT_ID", "AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET"]


def _validate_config() -> None:
    """Fail fast if required configuration is missing."""
    missing = [v for v in _REQUIRED_ENV_VARS if not os.environ.get(v)]
    if missing:
        raise RuntimeError(f"Missing required environment variables: {', '.join(missing)}")


# ---------------------------------------------------------------------------
# Main timer: process reports every 30 minutes
# ---------------------------------------------------------------------------


@app.timer_trigger(
    schedule="%TIMER_SCHEDULE_CRON%",
    arg_name="timer",
    run_on_startup=False,
)
def process_email_reports(timer: func.TimerRequest) -> None:
    """Poll shared mailbox for DMARC and TLS-RPT reports, parse, and alert."""
    if timer.past_due:
        logger.warning("Timer is past due — running anyway")

    _validate_config()

    try:
        _run()
    except Exception:
        logger.exception("Function failed")
        _send_error_notification()
        raise


def _run() -> None:
    with GraphClient() as graph:
        mailbox = os.environ["REPORT_MAILBOX"]
        mail_folder = os.environ.get("MAIL_FOLDER", "")
        dmarc_alias = os.environ.get("DMARC_ALIAS", "").lower()
        tlsrpt_alias = os.environ.get("TLSRPT_ALIAS", "").lower()
        delete_after_days = int(os.environ.get("DELETE_AFTER_DAYS", "-1"))
        move_to_folder = os.environ.get("MOVE_PROCESSED_TO", "")

        messages = graph.list_unread_messages(mailbox, folder=mail_folder)
        logger.info("Mailbox %s: %d unread messages", mailbox, len(messages))

        alerts: list[AlertSummary] = []
        abuse_candidates: list[tuple[DmarcReport, str, str]] | None = [] if abuse.is_abuse_reporting_enabled() else None
        errors = 0

        for msg in messages:
            try:
                alerts.extend(
                    _process_message(
                        msg,
                        graph,
                        mailbox,
                        dmarc_alias,
                        tlsrpt_alias,
                        delete_after_days,
                        move_to_folder,
                        abuse_candidates,
                    )
                )
            except Exception:
                errors += 1
                logger.exception("Failed to process message %s", msg.get("id", "unknown"))

        for a in alerts:
            try:
                delivery.send_teams_alert(a)
                delivery.send_generic_webhook(a)
                if a.severity != models.AlertSeverity.INFO:
                    delivery.send_email_alert(a, graph)
            except Exception:
                logger.exception("Failed to deliver alert: %s", a.title)

        # Abuse reporting (opt-in, best-effort).
        if abuse_candidates:
            for report, att_name, att_b64 in abuse_candidates:
                try:
                    abuse.send_abuse_reports(report, att_name, att_b64, graph)
                except Exception:
                    logger.exception("Abuse reporting failed for report %s", report.report_id)

        if delete_after_days > 0:
            cleanup_folder = move_to_folder or mail_folder
            _cleanup_old_messages(graph, mailbox, cleanup_folder, delete_after_days)

        logger.info("Run complete — processed %d alert(s), %d error(s)", len(alerts), errors)

        if errors:
            raise RuntimeError(f"{errors} message(s) failed to process")


def _process_message(
    msg: dict,
    graph: GraphClient,
    mailbox: str,
    dmarc_alias: str,
    tlsrpt_alias: str,
    delete_after_days: int,
    move_to_folder: str,
    abuse_candidates: list[tuple[DmarcReport, str, str]] | None = None,
) -> list[AlertSummary]:
    """Route, parse, and handle lifecycle for a single message."""
    msg_id = msg["id"]
    subject = msg.get("subject", "")
    to_addresses = _get_to_addresses(msg)

    if not msg.get("hasAttachments"):
        graph.mark_as_read(mailbox, msg_id)
        return []

    attachments = graph.get_attachments(mailbox, msg_id)

    new_alerts: list[AlertSummary] = []
    if dmarc_alias and dmarc_alias in to_addresses:
        new_alerts.extend(
            _parse_attachments(
                attachments,
                subject,
                dmarc_parser.parse_attachment,
                alert.build_dmarc_alert,
                abuse_candidates=abuse_candidates,
            )
        )
    elif tlsrpt_alias and tlsrpt_alias in to_addresses:
        new_alerts.extend(
            _parse_attachments(attachments, subject, tlsrpt_parser.parse_attachment, alert.build_tlsrpt_alert)
        )
    else:
        logger.debug("No alias match for '%s', trying both parsers", subject)
        new_alerts.extend(
            _parse_attachments(
                attachments,
                subject,
                dmarc_parser.parse_attachment,
                alert.build_dmarc_alert,
                abuse_candidates=abuse_candidates,
            )
        )
        new_alerts.extend(
            _parse_attachments(attachments, subject, tlsrpt_parser.parse_attachment, alert.build_tlsrpt_alert)
        )

    if delete_after_days == 0:
        graph.delete_message(mailbox, msg_id)
        logger.debug("Deleted message '%s' (immediate)", subject)
    else:
        graph.mark_as_read(mailbox, msg_id)
        if move_to_folder:
            graph.move_message(mailbox, msg_id, move_to_folder)
            logger.debug("Moved message '%s' to '%s'", subject, move_to_folder)

    return new_alerts


# ---------------------------------------------------------------------------
# Summary timer: weekly digest
# ---------------------------------------------------------------------------


@app.timer_trigger(
    schedule="%SUMMARY_SCHEDULE_CRON%",
    arg_name="timer",
    run_on_startup=False,
)
def send_weekly_summary(timer: func.TimerRequest) -> None:
    """Send a periodic summary email of all processed reports."""
    enabled = os.environ.get("SUMMARY_ENABLED", "false").lower() == "true"
    if not enabled:
        logger.debug("Summary not enabled; skipping")
        return

    summary_days = int(os.environ.get("SUMMARY_DAYS", "7"))

    try:
        records = storage.query_period(days=summary_days)
        if not records:
            logger.info("No report records found for the last %d days; skipping summary", summary_days)
            return

        prev_records = storage.query_period_range(summary_days * 2, summary_days)
        abuse_reports_sent = storage.count_abuse_reports(days=summary_days)
        summary = alert.build_weekly_summary(
            records,
            days=summary_days,
            prev_records=prev_records if prev_records else None,
            abuse_reports_sent=abuse_reports_sent,
        )

        with GraphClient() as graph:
            delivery.send_teams_alert(summary)
            delivery.send_generic_webhook(summary)
            delivery.send_email_alert(summary, graph)

        logger.info("Weekly summary sent — %d records over %d days", len(records), summary_days)
    except Exception:
        logger.exception("Failed to send weekly summary")
        _send_error_notification()
        raise


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _send_error_notification() -> None:
    """Best-effort error notification through available channels."""
    import sys

    exc_type, exc_value, _ = sys.exc_info()
    exc_name = exc_type.__name__ if exc_type else "Unknown"
    exc_msg = str(exc_value) if exc_value else ""
    error_alert = AlertSummary(
        title="EmailReports Function Error",
        severity=models.AlertSeverity.CRITICAL,
        body_markdown=f"**The EmailReports function failed.**\n\n**{exc_name}:** {exc_msg}",
    )
    try:
        delivery.send_teams_alert(error_alert)
    except Exception:
        logger.debug("Failed to send error to Teams", exc_info=True)
    try:
        delivery.send_generic_webhook(error_alert)
    except Exception:
        logger.debug("Failed to send error to generic webhook", exc_info=True)


def _cleanup_old_messages(graph: GraphClient, mailbox: str, folder: str, days: int) -> None:
    """Delete read messages older than *days* days."""
    old_messages = graph.list_read_messages_older_than(mailbox, days, folder=folder or None)
    if old_messages:
        logger.info("Cleaning up %d read messages older than %d days", len(old_messages), days)
    for msg in old_messages:
        try:
            graph.delete_message(mailbox, msg["id"])
        except Exception:
            logger.exception("Failed to delete message %s", msg["id"])


def _get_to_addresses(msg: dict) -> set[str]:
    """Extract all To: addresses from a message as a lowercase set."""
    recipients = msg.get("toRecipients", [])
    return {r["emailAddress"]["address"].lower() for r in recipients if r.get("emailAddress", {}).get("address")}


def _parse_attachments(
    attachments: list[dict],
    subject: str,
    parser: Callable[[str, str], Any],
    alert_builder: Callable[[Any], AlertSummary],
    *,
    abuse_candidates: list[tuple[DmarcReport, str, str]] | None = None,
) -> list[AlertSummary]:
    """Parse attachments using the given parser and build alerts. Saves records to storage."""
    alerts: list[AlertSummary] = []
    for att in attachments:
        name = att.get("name", "")
        content_b64 = att.get("contentBytes", "")
        if not content_b64:
            continue
        report = parser(name, content_b64)
        if report:
            if storage.report_exists(
                "dmarc" if isinstance(report, DmarcReport) else "tlsrpt",
                report.report_id,
            ):
                logger.info("Skipping duplicate report %s from '%s'", report.report_id, subject)
                continue
            logger.info("Parsed report %s from '%s'", report.report_id, subject)
            alert_summary = alert_builder(report)
            alert_summary.attachments.append(models.AlertAttachment(name=name, content_b64=content_b64))
            alerts.append(alert_summary)
            _save_report(report, content_b64)
            if abuse_candidates is not None and isinstance(report, DmarcReport):
                abuse_candidates.append((report, name, content_b64))
    return alerts


def _save_report(report: DmarcReport | TlsRptReport, content_b64: str) -> None:
    """Best-effort save of report metadata to Table Storage."""
    import json

    try:
        att_size = len(b64decode(content_b64))
        if isinstance(report, DmarcReport):
            fail_count = sum(r.count for r in report.failing_records)
            dmarc_failures = [
                {
                    "source_ip": r.source_ip,
                    "count": r.count,
                    "disposition": r.disposition.value,
                    "dkim_result": r.dkim_result.value,
                    "spf_result": r.spf_result.value,
                    "header_from": r.header_from,
                    "org_name": report.org_name,
                }
                for r in report.failing_records[:50]
            ]
            record = ReportRecord(
                report_type="dmarc",
                report_id=report.report_id,
                org_name=report.org_name,
                domain=report.domain,
                total_messages=report.total_messages,
                pass_count=report.total_messages - fail_count,
                fail_count=fail_count,
                policy=report.policy.value,
                attachment_size_bytes=att_size,
                dmarc_failure_details_json=json.dumps(dmarc_failures) if dmarc_failures else "",
            )
        else:
            tls_failures = [
                {
                    "result_type": fd.result_type,
                    "sending_mta_ip": fd.sending_mta_ip,
                    "receiving_mx_hostname": fd.receiving_mx_hostname,
                    "receiving_ip": fd.receiving_ip,
                    "failed_session_count": fd.failed_session_count,
                    "failure_reason_code": fd.failure_reason_code,
                }
                for pol in report.policies
                for fd in pol.failure_details[:20]
            ][:50]
            record = ReportRecord(
                report_type="tlsrpt",
                report_id=report.report_id,
                org_name=report.org_name,
                domain="",
                total_messages=report.total_successful + report.total_failures,
                pass_count=report.total_successful,
                fail_count=report.total_failures,
                policy="",
                attachment_size_bytes=att_size,
                tls_failure_details_json=json.dumps(tls_failures) if tls_failures else "",
            )
        storage.save_report_record(record)
    except Exception:
        logger.warning("Failed to save report record to storage", exc_info=True)
