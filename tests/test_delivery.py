"""Tests for delivery.py — Teams, generic webhook, and email delivery."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import delivery
from models import AlertSeverity, AlertSummary

# ---------------------------------------------------------------------------
# send_teams_alert
# ---------------------------------------------------------------------------


class TestSendTeamsAlert:
    def test_skips_when_no_webhook(self, monkeypatch):
        monkeypatch.setenv("TEAMS_WEBHOOK_URL", "")
        a = AlertSummary(title="t", severity=AlertSeverity.INFO, body_markdown="m")
        # Should not raise
        delivery.send_teams_alert(a)

    def test_posts_to_webhook(self, monkeypatch):
        monkeypatch.setenv("TEAMS_WEBHOOK_URL", "https://webhook.test/hook")
        a = AlertSummary(title="Test", severity=AlertSeverity.INFO, body_markdown="m")
        with patch("delivery.requests.post") as mock_post:
            mock_post.return_value = MagicMock(raise_for_status=MagicMock())
            delivery.send_teams_alert(a)
            mock_post.assert_called_once()
            call_url = mock_post.call_args[0][0]
            assert call_url == "https://webhook.test/hook"

    def test_adaptive_card_severity_attention(self, monkeypatch):
        monkeypatch.setenv("TEAMS_WEBHOOK_URL", "https://webhook.test/hook")
        a = AlertSummary(title="Critical", severity=AlertSeverity.CRITICAL, body_markdown="m")
        with patch("delivery.requests.post") as mock_post:
            mock_post.return_value = MagicMock(raise_for_status=MagicMock())
            delivery.send_teams_alert(a)
            card = mock_post.call_args[1]["json"]
            body = card["attachments"][0]["content"]["body"]
            assert body[0]["color"] == "Attention"

    def test_adaptive_card_severity_good(self, monkeypatch):
        monkeypatch.setenv("TEAMS_WEBHOOK_URL", "https://webhook.test/hook")
        a = AlertSummary(title="OK", severity=AlertSeverity.INFO, body_markdown="m")
        with patch("delivery.requests.post") as mock_post:
            mock_post.return_value = MagicMock(raise_for_status=MagicMock())
            delivery.send_teams_alert(a)
            card = mock_post.call_args[1]["json"]
            body = card["attachments"][0]["content"]["body"]
            assert body[0]["color"] == "Good"


# ---------------------------------------------------------------------------
# send_generic_webhook
# ---------------------------------------------------------------------------


class TestSendGenericWebhook:
    def test_skips_when_no_url(self, monkeypatch):
        monkeypatch.setenv("GENERIC_WEBHOOK_URL", "")
        a = AlertSummary(title="t", severity=AlertSeverity.INFO, body_markdown="m")
        delivery.send_generic_webhook(a)  # should not raise

    def test_posts_json_payload(self, monkeypatch):
        monkeypatch.setenv("GENERIC_WEBHOOK_URL", "https://hook.test/endpoint")
        a = AlertSummary(title="Test Alert", severity=AlertSeverity.WARNING, body_markdown="body")
        with patch("delivery.requests.post") as mock_post:
            mock_post.return_value = MagicMock(raise_for_status=MagicMock())
            delivery.send_generic_webhook(a)
            mock_post.assert_called_once()
            call_url = mock_post.call_args[0][0]
            assert call_url == "https://hook.test/endpoint"
            payload = mock_post.call_args[1]["json"]
            assert payload["title"] == "Test Alert"
            assert payload["severity"] == "warning"
            assert payload["body"] == "body"
            assert "timestamp" in payload


# ---------------------------------------------------------------------------
# send_email_alert
# ---------------------------------------------------------------------------


class TestSendEmailAlert:
    def test_disabled_by_default(self, mock_graph, monkeypatch):
        monkeypatch.setenv("ALERT_EMAIL_ENABLED", "false")
        a = AlertSummary(title="t", severity=AlertSeverity.INFO, body_markdown="m")
        delivery.send_email_alert(a, mock_graph)
        mock_graph.send_mail.assert_not_called()

    def test_enabled_sends_email(self, mock_graph, monkeypatch):
        monkeypatch.setenv("ALERT_EMAIL_ENABLED", "true")
        monkeypatch.setenv("ALERT_EMAIL_FROM", "from@test.com")
        monkeypatch.setenv("ALERT_EMAIL_TO", "to@test.com")
        a = AlertSummary(title="Test", severity=AlertSeverity.INFO, body_markdown="m", body_html="<p>html</p>")
        delivery.send_email_alert(a, mock_graph)
        mock_graph.send_mail.assert_called_once_with("from@test.com", "to@test.com", "Test", "<p>html</p>")

    def test_case_insensitive_enabled(self, mock_graph, monkeypatch):
        monkeypatch.setenv("ALERT_EMAIL_ENABLED", "TRUE")
        a = AlertSummary(title="Test", severity=AlertSeverity.INFO, body_markdown="m", body_html="<p>html</p>")
        delivery.send_email_alert(a, mock_graph)
        mock_graph.send_mail.assert_called_once()
