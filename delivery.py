"""Alert delivery via Teams webhook, generic webhook, and Graph email.

This module handles outbound delivery of AlertSummary objects through
the configured notification channels: Microsoft Teams, generic webhooks
(Slack, Discord, n8n, etc.), and email via Microsoft Graph.
"""

from __future__ import annotations

import logging
import os

import requests

from graph_client import GraphClient
from models import AlertSeverity, AlertSummary

logger = logging.getLogger(__name__)


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
    atts = [{"name": a.name, "content_b64": a.content_b64} for a in alert_summary.attachments] or None
    graph.send_mail(from_addr, to_addr, alert_summary.title, alert_summary.body_html, attachments=atts)
