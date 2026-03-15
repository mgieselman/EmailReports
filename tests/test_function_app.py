"""Tests for function_app.py — orchestration, routing, and message processing."""

from __future__ import annotations

import base64
import gzip
from unittest.mock import MagicMock, patch

import pytest

from models import AlertSeverity


# ---------------------------------------------------------------------------
# _get_to_addresses
# ---------------------------------------------------------------------------

class TestGetToAddresses:
    def _get_fn(self):
        from function_app import _get_to_addresses
        return _get_to_addresses

    def test_normal_recipients(self):
        fn = self._get_fn()
        msg = {"toRecipients": [
            {"emailAddress": {"address": "dmarc-reports@gieselman.com"}},
        ]}
        assert fn(msg) == {"dmarc-reports@gieselman.com"}

    def test_multiple_recipients(self):
        fn = self._get_fn()
        msg = {"toRecipients": [
            {"emailAddress": {"address": "a@test.com"}},
            {"emailAddress": {"address": "b@test.com"}},
        ]}
        assert fn(msg) == {"a@test.com", "b@test.com"}

    def test_lowercase_normalization(self):
        fn = self._get_fn()
        msg = {"toRecipients": [
            {"emailAddress": {"address": "DMARC-Reports@Gieselman.COM"}},
        ]}
        assert fn(msg) == {"dmarc-reports@gieselman.com"}

    def test_missing_to_recipients(self):
        fn = self._get_fn()
        assert fn({}) == set()

    def test_missing_email_address_key(self):
        fn = self._get_fn()
        msg = {"toRecipients": [{"other": "data"}]}
        assert fn(msg) == set()

    def test_missing_address_field(self):
        fn = self._get_fn()
        msg = {"toRecipients": [{"emailAddress": {}}]}
        assert fn(msg) == set()

    def test_deduplication(self):
        fn = self._get_fn()
        msg = {"toRecipients": [
            {"emailAddress": {"address": "a@test.com"}},
            {"emailAddress": {"address": "a@test.com"}},
        ]}
        assert fn(msg) == {"a@test.com"}


# ---------------------------------------------------------------------------
# _parse_dmarc_attachments
# ---------------------------------------------------------------------------

class TestParseDmarcAttachments:
    def _get_fn(self):
        from function_app import _parse_dmarc_attachments
        return _parse_dmarc_attachments

    def test_empty_attachments(self):
        fn = self._get_fn()
        assert fn([], "test subject") == []

    def test_attachment_no_content_bytes(self):
        fn = self._get_fn()
        result = fn([{"name": "report.xml", "contentBytes": ""}], "test")
        assert result == []

    def test_valid_dmarc_attachment(self, dmarc_b64_gz):
        fn = self._get_fn()
        attachments = [{"name": "report.xml.gz", "contentBytes": dmarc_b64_gz}]
        result = fn(attachments, "test subject")
        assert len(result) == 1
        assert result[0].severity in (AlertSeverity.INFO, AlertSeverity.WARNING, AlertSeverity.CRITICAL)

    def test_non_dmarc_attachment_ignored(self):
        fn = self._get_fn()
        attachments = [{"name": "photo.jpg", "contentBytes": base64.b64encode(b"jpeg").decode()}]
        result = fn(attachments, "test")
        assert result == []

    def test_multiple_attachments(self, dmarc_b64_gz):
        fn = self._get_fn()
        attachments = [
            {"name": "report1.xml.gz", "contentBytes": dmarc_b64_gz},
            {"name": "report2.xml.gz", "contentBytes": dmarc_b64_gz},
        ]
        result = fn(attachments, "test")
        assert len(result) == 2


# ---------------------------------------------------------------------------
# _parse_tlsrpt_attachments
# ---------------------------------------------------------------------------

class TestParseTlsRptAttachments:
    def _get_fn(self):
        from function_app import _parse_tlsrpt_attachments
        return _parse_tlsrpt_attachments

    def test_empty_attachments(self):
        fn = self._get_fn()
        assert fn([], "test subject") == []

    def test_valid_tlsrpt_attachment(self, tlsrpt_b64_gz):
        fn = self._get_fn()
        attachments = [{"name": "report.json.gz", "contentBytes": tlsrpt_b64_gz}]
        result = fn(attachments, "test subject")
        assert len(result) == 1

    def test_non_tlsrpt_attachment_ignored(self):
        fn = self._get_fn()
        attachments = [{"name": "data.xml", "contentBytes": base64.b64encode(b"<xml/>").decode()}]
        result = fn(attachments, "test")
        assert result == []

    def test_attachment_no_content_bytes(self):
        fn = self._get_fn()
        result = fn([{"name": "report.json", "contentBytes": ""}], "test")
        assert result == []


# ---------------------------------------------------------------------------
# process_email_reports — full orchestration
# ---------------------------------------------------------------------------

class TestProcessEmailReports:
    def _make_message(self, msg_id, to_address, has_attachments=True):
        return {
            "id": msg_id,
            "subject": f"Report {msg_id}",
            "hasAttachments": has_attachments,
            "toRecipients": [{"emailAddress": {"address": to_address}}],
        }

    @patch("function_app.alert")
    @patch("function_app.GraphClient")
    def test_no_messages(self, MockGraphClient, mock_alert, monkeypatch):
        mock_client = MagicMock()
        mock_client.list_unread_messages.return_value = []
        MockGraphClient.return_value = mock_client

        from function_app import process_email_reports
        timer = MagicMock()
        timer.past_due = False
        process_email_reports(timer)

        mock_alert.send_teams_alert.assert_not_called()
        mock_alert.send_email_alert.assert_not_called()

    @patch("function_app.alert")
    @patch("function_app.GraphClient")
    def test_message_no_attachments_marked_read(self, MockGraphClient, mock_alert):
        mock_client = MagicMock()
        msg = self._make_message("1", "dmarc-reports@gieselman.com", has_attachments=False)
        mock_client.list_unread_messages.return_value = [msg]
        MockGraphClient.return_value = mock_client

        from function_app import process_email_reports
        timer = MagicMock()
        timer.past_due = False
        process_email_reports(timer)

        mock_client.mark_as_read.assert_called_once()

    @patch("function_app.alert")
    @patch("function_app.GraphClient")
    def test_dmarc_message_routed_correctly(self, MockGraphClient, mock_alert, dmarc_b64_gz):
        mock_client = MagicMock()
        msg = self._make_message("1", "dmarc-reports@gieselman.com")
        mock_client.list_unread_messages.return_value = [msg]
        mock_client.get_attachments.return_value = [
            {"name": "report.xml.gz", "contentBytes": dmarc_b64_gz}
        ]
        MockGraphClient.return_value = mock_client

        from function_app import process_email_reports
        timer = MagicMock()
        timer.past_due = False
        process_email_reports(timer)

        mock_alert.build_dmarc_alert.assert_called_once()
        mock_alert.build_tlsrpt_alert.assert_not_called()
        mock_alert.send_teams_alert.assert_called()

    @patch("function_app.alert")
    @patch("function_app.GraphClient")
    def test_tlsrpt_message_routed_correctly(self, MockGraphClient, mock_alert, tlsrpt_b64_gz):
        mock_client = MagicMock()
        msg = self._make_message("1", "tls-reports@gieselman.com")
        mock_client.list_unread_messages.return_value = [msg]
        mock_client.get_attachments.return_value = [
            {"name": "report.json.gz", "contentBytes": tlsrpt_b64_gz}
        ]
        MockGraphClient.return_value = mock_client

        from function_app import process_email_reports
        timer = MagicMock()
        timer.past_due = False
        process_email_reports(timer)

        mock_alert.build_tlsrpt_alert.assert_called_once()
        mock_alert.build_dmarc_alert.assert_not_called()
        mock_alert.send_teams_alert.assert_called()

    @patch("function_app.alert")
    @patch("function_app.GraphClient")
    def test_unknown_recipient_tries_both_parsers(self, MockGraphClient, mock_alert, dmarc_b64_gz):
        mock_client = MagicMock()
        msg = self._make_message("1", "other@gieselman.com")
        mock_client.list_unread_messages.return_value = [msg]
        mock_client.get_attachments.return_value = [
            {"name": "report.xml.gz", "contentBytes": dmarc_b64_gz}
        ]
        MockGraphClient.return_value = mock_client

        from function_app import process_email_reports
        timer = MagicMock()
        timer.past_due = False
        process_email_reports(timer)

        # Fallback: DMARC parser finds it, TLS-RPT parser gets called but returns None
        mock_alert.build_dmarc_alert.assert_called_once()
        mock_alert.send_teams_alert.assert_called()

    @patch("function_app.alert")
    @patch("function_app.GraphClient")
    def test_past_due_still_runs(self, MockGraphClient, mock_alert):
        mock_client = MagicMock()
        mock_client.list_unread_messages.return_value = []
        MockGraphClient.return_value = mock_client

        from function_app import process_email_reports
        timer = MagicMock()
        timer.past_due = True
        process_email_reports(timer)

        mock_client.list_unread_messages.assert_called_once()

    @patch("function_app.alert")
    @patch("function_app.GraphClient")
    def test_all_messages_marked_read(self, MockGraphClient, mock_alert, dmarc_b64_gz, tlsrpt_b64_gz):
        mock_client = MagicMock()
        msgs = [
            self._make_message("1", "dmarc-reports@gieselman.com"),
            self._make_message("2", "tls-reports@gieselman.com"),
            self._make_message("3", "other@gieselman.com", has_attachments=False),
        ]
        mock_client.list_unread_messages.return_value = msgs
        mock_client.get_attachments.side_effect = [
            [{"name": "r.xml.gz", "contentBytes": dmarc_b64_gz}],
            [{"name": "r.json.gz", "contentBytes": tlsrpt_b64_gz}],
        ]
        MockGraphClient.return_value = mock_client

        from function_app import process_email_reports
        timer = MagicMock()
        timer.past_due = False
        process_email_reports(timer)

        assert mock_client.mark_as_read.call_count == 3
