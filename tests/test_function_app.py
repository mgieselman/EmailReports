"""Tests for function_app.py — orchestration, routing, and message processing."""

from __future__ import annotations

import base64
from unittest.mock import MagicMock, patch

import dmarc_parser
import tlsrpt_parser
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
        msg = {
            "toRecipients": [
                {"emailAddress": {"address": "dmarc-reports@gieselman.com"}},
            ]
        }
        assert fn(msg) == {"dmarc-reports@gieselman.com"}

    def test_multiple_recipients(self):
        fn = self._get_fn()
        msg = {
            "toRecipients": [
                {"emailAddress": {"address": "a@test.com"}},
                {"emailAddress": {"address": "b@test.com"}},
            ]
        }
        assert fn(msg) == {"a@test.com", "b@test.com"}

    def test_lowercase_normalization(self):
        fn = self._get_fn()
        msg = {
            "toRecipients": [
                {"emailAddress": {"address": "DMARC-Reports@Gieselman.COM"}},
            ]
        }
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
        msg = {
            "toRecipients": [
                {"emailAddress": {"address": "a@test.com"}},
                {"emailAddress": {"address": "a@test.com"}},
            ]
        }
        assert fn(msg) == {"a@test.com"}


# ---------------------------------------------------------------------------
# _parse_attachments
# ---------------------------------------------------------------------------


class TestParseAttachments:
    def _get_fn(self):
        from function_app import _parse_attachments

        return _parse_attachments

    def test_empty_attachments(self):
        import alert as alert_mod

        fn = self._get_fn()
        assert fn([], "test subject", dmarc_parser.parse_attachment, alert_mod.build_dmarc_alert) == []

    def test_attachment_no_content_bytes(self):
        import alert as alert_mod

        fn = self._get_fn()
        atts = [{"name": "report.xml", "contentBytes": ""}]
        result = fn(atts, "test", dmarc_parser.parse_attachment, alert_mod.build_dmarc_alert)
        assert result == []

    def test_valid_dmarc_attachment(self, dmarc_b64_gz):
        import alert as alert_mod

        fn = self._get_fn()
        attachments = [{"name": "report.xml.gz", "contentBytes": dmarc_b64_gz}]
        result = fn(attachments, "test subject", dmarc_parser.parse_attachment, alert_mod.build_dmarc_alert)
        assert len(result) == 1
        assert result[0].severity in (AlertSeverity.INFO, AlertSeverity.WARNING, AlertSeverity.CRITICAL)

    def test_valid_tlsrpt_attachment(self, tlsrpt_b64_gz):
        import alert as alert_mod

        fn = self._get_fn()
        attachments = [{"name": "report.json.gz", "contentBytes": tlsrpt_b64_gz}]
        result = fn(attachments, "test subject", tlsrpt_parser.parse_attachment, alert_mod.build_tlsrpt_alert)
        assert len(result) == 1

    def test_non_matching_attachment_ignored(self):
        import alert as alert_mod

        fn = self._get_fn()
        attachments = [{"name": "photo.jpg", "contentBytes": base64.b64encode(b"jpeg").decode()}]
        result = fn(attachments, "test", dmarc_parser.parse_attachment, alert_mod.build_dmarc_alert)
        assert result == []

    def test_multiple_attachments(self, dmarc_b64_gz):
        import alert as alert_mod

        fn = self._get_fn()
        attachments = [
            {"name": "report1.xml.gz", "contentBytes": dmarc_b64_gz},
            {"name": "report2.xml.gz", "contentBytes": dmarc_b64_gz},
        ]
        result = fn(attachments, "test", dmarc_parser.parse_attachment, alert_mod.build_dmarc_alert)
        assert len(result) == 2


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

    @staticmethod
    def _setup_graph_mock(MockGraphClient):
        """Configure MockGraphClient to support context manager protocol."""
        mock_client = MagicMock()
        MockGraphClient.return_value.__enter__ = MagicMock(return_value=mock_client)
        MockGraphClient.return_value.__exit__ = MagicMock(return_value=False)
        return mock_client

    @patch("function_app.alert")
    @patch("function_app.GraphClient")
    def test_no_messages(self, MockGraphClient, mock_alert, monkeypatch):
        mock_client = self._setup_graph_mock(MockGraphClient)
        mock_client.list_unread_messages.return_value = []

        from function_app import process_email_reports

        timer = MagicMock()
        timer.past_due = False
        process_email_reports(timer)

        mock_alert.send_teams_alert.assert_not_called()
        mock_alert.send_email_alert.assert_not_called()

    @patch("function_app.alert")
    @patch("function_app.GraphClient")
    def test_message_no_attachments_marked_read(self, MockGraphClient, mock_alert):
        mock_client = self._setup_graph_mock(MockGraphClient)
        msg = self._make_message("1", "dmarc-reports@gieselman.com", has_attachments=False)
        mock_client.list_unread_messages.return_value = [msg]

        from function_app import process_email_reports

        timer = MagicMock()
        timer.past_due = False
        process_email_reports(timer)

        mock_client.mark_as_read.assert_called_once()

    @patch("function_app.alert")
    @patch("function_app.GraphClient")
    def test_dmarc_message_routed_correctly(self, MockGraphClient, mock_alert, dmarc_b64_gz):
        mock_client = self._setup_graph_mock(MockGraphClient)
        msg = self._make_message("1", "dmarc-reports@gieselman.com")
        mock_client.list_unread_messages.return_value = [msg]
        mock_client.get_attachments.return_value = [{"name": "report.xml.gz", "contentBytes": dmarc_b64_gz}]

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
        mock_client = self._setup_graph_mock(MockGraphClient)
        msg = self._make_message("1", "tls-reports@gieselman.com")
        mock_client.list_unread_messages.return_value = [msg]
        mock_client.get_attachments.return_value = [{"name": "report.json.gz", "contentBytes": tlsrpt_b64_gz}]

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
        mock_client = self._setup_graph_mock(MockGraphClient)
        msg = self._make_message("1", "other@gieselman.com")
        mock_client.list_unread_messages.return_value = [msg]
        mock_client.get_attachments.return_value = [{"name": "report.xml.gz", "contentBytes": dmarc_b64_gz}]

        from function_app import process_email_reports

        timer = MagicMock()
        timer.past_due = False
        process_email_reports(timer)

        mock_alert.build_dmarc_alert.assert_called_once()
        mock_alert.send_teams_alert.assert_called()

    @patch("function_app.alert")
    @patch("function_app.GraphClient")
    def test_past_due_still_runs(self, MockGraphClient, mock_alert):
        mock_client = self._setup_graph_mock(MockGraphClient)
        mock_client.list_unread_messages.return_value = []

        from function_app import process_email_reports

        timer = MagicMock()
        timer.past_due = True
        process_email_reports(timer)

        mock_client.list_unread_messages.assert_called_once()

    @patch("function_app.alert")
    @patch("function_app.GraphClient")
    def test_all_messages_marked_read(self, MockGraphClient, mock_alert, dmarc_b64_gz, tlsrpt_b64_gz):
        mock_client = self._setup_graph_mock(MockGraphClient)
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

        from function_app import process_email_reports

        timer = MagicMock()
        timer.past_due = False
        process_email_reports(timer)

        assert mock_client.mark_as_read.call_count == 3

    @patch("function_app.alert")
    @patch("function_app.GraphClient")
    def test_immediate_delete(self, MockGraphClient, mock_alert, monkeypatch, dmarc_b64_gz):
        monkeypatch.setenv("DELETE_AFTER_DAYS", "0")
        mock_client = self._setup_graph_mock(MockGraphClient)
        msg = self._make_message("1", "dmarc-reports@gieselman.com")
        mock_client.list_unread_messages.return_value = [msg]
        mock_client.get_attachments.return_value = [{"name": "r.xml.gz", "contentBytes": dmarc_b64_gz}]

        from function_app import process_email_reports

        timer = MagicMock()
        timer.past_due = False
        process_email_reports(timer)

        mock_client.delete_message.assert_called_once_with("emailreports@gieselman.com", "1")

    @patch("function_app.alert")
    @patch("function_app.GraphClient")
    def test_no_delete_when_minus_one(self, MockGraphClient, mock_alert, monkeypatch, dmarc_b64_gz):
        monkeypatch.setenv("DELETE_AFTER_DAYS", "-1")
        mock_client = self._setup_graph_mock(MockGraphClient)
        msg = self._make_message("1", "dmarc-reports@gieselman.com")
        mock_client.list_unread_messages.return_value = [msg]
        mock_client.get_attachments.return_value = [{"name": "r.xml.gz", "contentBytes": dmarc_b64_gz}]

        from function_app import process_email_reports

        timer = MagicMock()
        timer.past_due = False
        process_email_reports(timer)

        mock_client.delete_message.assert_not_called()

    @patch("function_app.alert")
    @patch("function_app.GraphClient")
    def test_deferred_delete(self, MockGraphClient, mock_alert, monkeypatch):
        monkeypatch.setenv("DELETE_AFTER_DAYS", "30")
        mock_client = self._setup_graph_mock(MockGraphClient)
        mock_client.list_unread_messages.return_value = []
        mock_client.list_read_messages_older_than.return_value = [
            {"id": "old-1", "subject": "old report"},
            {"id": "old-2", "subject": "old report 2"},
        ]

        from function_app import process_email_reports

        timer = MagicMock()
        timer.past_due = False
        process_email_reports(timer)

        assert mock_client.delete_message.call_count == 2
        mock_client.list_read_messages_older_than.assert_called_once_with("emailreports@gieselman.com", 30, folder=None)

    @patch("function_app.alert")
    @patch("function_app.GraphClient")
    def test_move_processed_to_folder(self, MockGraphClient, mock_alert, monkeypatch, dmarc_b64_gz):
        monkeypatch.setenv("DELETE_AFTER_DAYS", "-1")
        monkeypatch.setenv("MOVE_PROCESSED_TO", "Processed")
        mock_client = self._setup_graph_mock(MockGraphClient)
        msg = self._make_message("1", "dmarc-reports@gieselman.com")
        mock_client.list_unread_messages.return_value = [msg]
        mock_client.get_attachments.return_value = [{"name": "r.xml.gz", "contentBytes": dmarc_b64_gz}]

        from function_app import process_email_reports

        timer = MagicMock()
        timer.past_due = False
        process_email_reports(timer)

        mock_client.move_message.assert_called_once_with("emailreports@gieselman.com", "1", "Processed")
        mock_client.delete_message.assert_not_called()

    @patch("function_app.alert")
    @patch("function_app.GraphClient")
    def test_immediate_delete_skips_move(self, MockGraphClient, mock_alert, monkeypatch, dmarc_b64_gz):
        """When DELETE_AFTER_DAYS=0, delete takes priority over move."""
        monkeypatch.setenv("DELETE_AFTER_DAYS", "0")
        monkeypatch.setenv("MOVE_PROCESSED_TO", "Processed")
        mock_client = self._setup_graph_mock(MockGraphClient)
        msg = self._make_message("1", "dmarc-reports@gieselman.com")
        mock_client.list_unread_messages.return_value = [msg]
        mock_client.get_attachments.return_value = [{"name": "r.xml.gz", "contentBytes": dmarc_b64_gz}]

        from function_app import process_email_reports

        timer = MagicMock()
        timer.past_due = False
        process_email_reports(timer)

        mock_client.delete_message.assert_called_once()
        mock_client.move_message.assert_not_called()

    @patch("function_app.alert")
    @patch("function_app.GraphClient")
    def test_generic_webhook_called(self, MockGraphClient, mock_alert, dmarc_b64_gz):
        mock_client = self._setup_graph_mock(MockGraphClient)
        msg = self._make_message("1", "dmarc-reports@gieselman.com")
        mock_client.list_unread_messages.return_value = [msg]
        mock_client.get_attachments.return_value = [{"name": "r.xml.gz", "contentBytes": dmarc_b64_gz}]

        from function_app import process_email_reports

        timer = MagicMock()
        timer.past_due = False
        process_email_reports(timer)

        mock_alert.send_generic_webhook.assert_called()

    @patch("function_app.alert")
    @patch("function_app.GraphClient")
    def test_single_message_failure_continues(self, MockGraphClient, mock_alert, dmarc_b64_gz):
        """A failure on one message should not skip subsequent messages."""
        mock_client = self._setup_graph_mock(MockGraphClient)
        msgs = [
            self._make_message("1", "dmarc-reports@gieselman.com"),
            self._make_message("2", "dmarc-reports@gieselman.com"),
        ]
        mock_client.list_unread_messages.return_value = msgs
        mock_client.get_attachments.side_effect = [
            RuntimeError("transient 503"),
            [{"name": "r.xml.gz", "contentBytes": dmarc_b64_gz}],
        ]

        import pytest

        from function_app import process_email_reports

        timer = MagicMock()
        timer.past_due = False
        with pytest.raises(RuntimeError, match="1 message"):
            process_email_reports(timer)

        # Second message still processed
        mock_alert.build_dmarc_alert.assert_called_once()

    @patch("function_app.alert")
    @patch("function_app.GraphClient")
    def test_cleanup_delete_failure_continues(self, MockGraphClient, mock_alert, monkeypatch):
        """A delete failure on one old message should not abort cleanup."""
        monkeypatch.setenv("DELETE_AFTER_DAYS", "30")
        mock_client = self._setup_graph_mock(MockGraphClient)
        mock_client.list_unread_messages.return_value = []
        mock_client.list_read_messages_older_than.return_value = [
            {"id": "old-1"},
            {"id": "old-2"},
        ]
        mock_client.delete_message.side_effect = [RuntimeError("404"), None]

        from function_app import process_email_reports

        timer = MagicMock()
        timer.past_due = False
        process_email_reports(timer)

        assert mock_client.delete_message.call_count == 2

    @patch("function_app.alert")
    @patch("function_app.GraphClient")
    def test_error_sends_notification_and_reraises(self, MockGraphClient, mock_alert):
        mock_client = self._setup_graph_mock(MockGraphClient)
        mock_client.list_unread_messages.side_effect = RuntimeError("Token expired")

        from function_app import process_email_reports

        timer = MagicMock()
        timer.past_due = False

        import pytest

        with pytest.raises(RuntimeError, match="Token expired"):
            process_email_reports(timer)

        mock_alert.send_teams_alert.assert_called_once()
        error_alert = mock_alert.send_teams_alert.call_args[0][0]
        assert "Error" in error_alert.title
        mock_alert.send_generic_webhook.assert_called_once()

    @patch("function_app.alert")
    @patch("function_app.GraphClient")
    def test_error_notification_failure_doesnt_mask_original(self, MockGraphClient, mock_alert):
        """If error notification itself fails, the original error still propagates."""
        mock_client = self._setup_graph_mock(MockGraphClient)
        mock_client.list_unread_messages.side_effect = RuntimeError("Graph down")
        mock_alert.send_teams_alert.side_effect = Exception("Teams also down")
        mock_alert.send_generic_webhook.side_effect = Exception("Webhook also down")

        from function_app import process_email_reports

        timer = MagicMock()
        timer.past_due = False

        import pytest

        with pytest.raises(RuntimeError, match="Graph down"):
            process_email_reports(timer)
