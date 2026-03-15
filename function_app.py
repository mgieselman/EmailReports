"""Azure Function: timer-triggered DMARC & TLS-RPT report processor."""

from __future__ import annotations

import logging
import os

import azure.functions as func

import alert
import dmarc_parser
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

    graph = GraphClient()

    mailbox = os.environ["REPORT_MAILBOX"]
    mail_folder = os.environ.get("MAIL_FOLDER", "Email Reports")
    dmarc_alias = os.environ.get("DMARC_ALIAS", "dmarc-reports@gieselman.com").lower()
    tlsrpt_alias = os.environ.get("TLSRPT_ALIAS", "tls-reports@gieselman.com").lower()

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

        if dmarc_alias in to_addresses:
            alerts.extend(_parse_dmarc_attachments(attachments, subject))
        elif tlsrpt_alias in to_addresses:
            alerts.extend(_parse_tlsrpt_attachments(attachments, subject))
        else:
            # Try both parsers if we can't determine by recipient
            logger.debug("No alias match for '%s', trying both parsers", subject)
            alerts.extend(_parse_dmarc_attachments(attachments, subject))
            alerts.extend(_parse_tlsrpt_attachments(attachments, subject))

        graph.mark_as_read(mailbox, msg_id)

    for a in alerts:
        alert.send_teams_alert(a)
        alert.send_email_alert(a, graph)

    logger.info("Run complete — processed %d alert(s)", len(alerts))


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
