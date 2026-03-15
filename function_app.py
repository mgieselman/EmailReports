"""Azure Function: timer-triggered DMARC & TLS-RPT report processor."""

from __future__ import annotations

import logging
import os

import azure.functions as func

import alert
import dmarc_parser
import models
import tlsrpt_parser
from graph_client import GraphClient
from models import AlertSummary

app = func.FunctionApp()
logger = logging.getLogger(__name__)


@app.timer_trigger(
    schedule="%TIMER_SCHEDULE_CRON%",
    arg_name="timer",
    run_on_startup=False,
)
def process_email_reports(timer: func.TimerRequest) -> None:
    """Poll shared mailbox for DMARC and TLS-RPT reports, parse, and alert."""
    if timer.past_due:
        logger.warning("Timer is past due — running anyway")

    try:
        _run(timer)
    except Exception:
        logger.exception("Function failed")
        _send_error_notification()
        raise


def _run(_timer: func.TimerRequest) -> None:
    graph = GraphClient()

    mailbox = os.environ["REPORT_MAILBOX"]
    mail_folder = os.environ.get("MAIL_FOLDER", "")
    dmarc_alias = os.environ.get("DMARC_ALIAS", "").lower()
    tlsrpt_alias = os.environ.get("TLSRPT_ALIAS", "").lower()
    delete_after_days = int(os.environ.get("DELETE_AFTER_DAYS", "-1"))
    move_to_folder = os.environ.get("MOVE_PROCESSED_TO", "")

    messages = graph.list_unread_messages(mailbox, folder=mail_folder)
    logger.info("Mailbox %s: %d unread messages", mailbox, len(messages))

    alerts: list[AlertSummary] = []

    for msg in messages:
        msg_id = msg["id"]
        subject = msg.get("subject", "")
        to_addresses = _get_to_addresses(msg)

        if not msg.get("hasAttachments"):
            graph.mark_as_read(mailbox, msg_id)
            continue

        attachments = graph.get_attachments(mailbox, msg_id)

        if dmarc_alias and dmarc_alias in to_addresses:
            alerts.extend(_parse_dmarc_attachments(attachments, subject))
        elif tlsrpt_alias and tlsrpt_alias in to_addresses:
            alerts.extend(_parse_tlsrpt_attachments(attachments, subject))
        else:
            # Try both parsers if we can't determine by recipient
            logger.debug("No alias match for '%s', trying both parsers", subject)
            alerts.extend(_parse_dmarc_attachments(attachments, subject))
            alerts.extend(_parse_tlsrpt_attachments(attachments, subject))

        graph.mark_as_read(mailbox, msg_id)

        # Immediate deletion: delete right after processing
        if delete_after_days == 0:
            graph.delete_message(mailbox, msg_id)
            logger.debug("Deleted message '%s' (immediate)", subject)
        elif move_to_folder:
            graph.move_message(mailbox, msg_id, move_to_folder)
            logger.debug("Moved message '%s' to '%s'", subject, move_to_folder)

    for a in alerts:
        alert.send_teams_alert(a)
        alert.send_generic_webhook(a)
        alert.send_email_alert(a, graph)

    # Deferred cleanup: delete read messages older than N days
    if delete_after_days > 0:
        _cleanup_old_messages(graph, mailbox, mail_folder, delete_after_days)

    logger.info("Run complete — processed %d alert(s)", len(alerts))


def _send_error_notification() -> None:
    """Best-effort error notification through available channels."""
    import traceback

    error_text = traceback.format_exc()
    error_alert = AlertSummary(
        title="EmailReports Function Error",
        severity=models.AlertSeverity.CRITICAL,
        body_markdown=f"**The EmailReports function failed.**\n\n```\n{error_text[-1000:]}\n```",
    )
    try:
        alert.send_teams_alert(error_alert)
    except Exception:
        logger.debug("Failed to send error to Teams", exc_info=True)
    try:
        alert.send_generic_webhook(error_alert)
    except Exception:
        logger.debug("Failed to send error to generic webhook", exc_info=True)


def _cleanup_old_messages(graph: GraphClient, mailbox: str, folder: str, days: int) -> None:
    """Delete read messages older than *days* days."""
    old_messages = graph.list_read_messages_older_than(mailbox, days, folder=folder or None)
    if old_messages:
        logger.info("Cleaning up %d read messages older than %d days", len(old_messages), days)
    for msg in old_messages:
        graph.delete_message(mailbox, msg["id"])


def _get_to_addresses(msg: dict) -> set[str]:
    """Extract all To: addresses from a message as a lowercase set."""
    recipients = msg.get("toRecipients", [])
    return {r["emailAddress"]["address"].lower() for r in recipients if r.get("emailAddress", {}).get("address")}


def _parse_dmarc_attachments(attachments: list[dict], subject: str) -> list[AlertSummary]:
    alerts: list[AlertSummary] = []
    for att in attachments:
        name = att.get("name", "")
        content_b64 = att.get("contentBytes", "")
        if not content_b64:
            continue
        report = dmarc_parser.parse_attachment(name, content_b64)
        if report:
            logger.info("Parsed DMARC report %s from '%s'", report.report_id, subject)
            alerts.append(alert.build_dmarc_alert(report))
    return alerts


def _parse_tlsrpt_attachments(attachments: list[dict], subject: str) -> list[AlertSummary]:
    alerts: list[AlertSummary] = []
    for att in attachments:
        name = att.get("name", "")
        content_b64 = att.get("contentBytes", "")
        if not content_b64:
            continue
        report = tlsrpt_parser.parse_attachment(name, content_b64)
        if report:
            logger.info("Parsed TLS-RPT report %s from '%s'", report.report_id, subject)
            alerts.append(alert.build_tlsrpt_alert(report))
    return alerts
