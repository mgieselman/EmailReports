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

    @patch("function_app.storage")
    def test_empty_attachments(self, mock_storage):
        import alert as alert_mod

        fn = self._get_fn()
        assert fn([], "test subject", dmarc_parser.parse_attachment, alert_mod.build_dmarc_alert) == []

    @patch("function_app.storage")
    def test_attachment_no_content_bytes(self, mock_storage):
        import alert as alert_mod

        fn = self._get_fn()
        atts = [{"name": "report.xml", "contentBytes": ""}]
        result = fn(atts, "test", dmarc_parser.parse_attachment, alert_mod.build_dmarc_alert)
        assert result == []

    @patch("function_app.storage")
    def test_valid_dmarc_attachment(self, mock_storage, dmarc_b64_gz):
        import alert as alert_mod

        mock_storage.report_exists.return_value = False
        fn = self._get_fn()
        attachments = [{"name": "report.xml.gz", "contentBytes": dmarc_b64_gz}]
        result = fn(attachments, "test subject", dmarc_parser.parse_attachment, alert_mod.build_dmarc_alert)
        assert len(result) == 1
        assert result[0].severity in (AlertSeverity.INFO, AlertSeverity.WARNING, AlertSeverity.CRITICAL)

    @patch("function_app.storage")
    def test_valid_tlsrpt_attachment(self, mock_storage, tlsrpt_b64_gz):
        import alert as alert_mod

        mock_storage.report_exists.return_value = False
        fn = self._get_fn()
        attachments = [{"name": "report.json.gz", "contentBytes": tlsrpt_b64_gz}]
        result = fn(attachments, "test subject", tlsrpt_parser.parse_attachment, alert_mod.build_tlsrpt_alert)
        assert len(result) == 1

    @patch("function_app.storage")
    def test_non_matching_attachment_ignored(self, mock_storage):
        import alert as alert_mod

        fn = self._get_fn()
        attachments = [{"name": "photo.jpg", "contentBytes": base64.b64encode(b"jpeg").decode()}]
        result = fn(attachments, "test", dmarc_parser.parse_attachment, alert_mod.build_dmarc_alert)
        assert result == []

    @patch("function_app.storage")
    def test_multiple_attachments(self, mock_storage, dmarc_b64_gz):
        import alert as alert_mod

        mock_storage.report_exists.return_value = False
        fn = self._get_fn()
        attachments = [
            {"name": "report1.xml.gz", "contentBytes": dmarc_b64_gz},
            {"name": "report2.xml.gz", "contentBytes": dmarc_b64_gz},
        ]
        result = fn(attachments, "test", dmarc_parser.parse_attachment, alert_mod.build_dmarc_alert)
        assert len(result) == 2

    @patch("function_app.storage")
    def test_duplicate_report_skipped(self, mock_storage, dmarc_b64_gz):
        """A report already in storage should not produce an alert."""
        import alert as alert_mod

        mock_storage.report_exists.return_value = True
        fn = self._get_fn()
        attachments = [{"name": "report.xml.gz", "contentBytes": dmarc_b64_gz}]
        result = fn(attachments, "test", dmarc_parser.parse_attachment, alert_mod.build_dmarc_alert)
        assert result == []
        mock_storage.save_report_record.assert_not_called()


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

    @patch("function_app.delivery")
    @patch("function_app.GraphClient")
    def test_no_messages(self, MockGraphClient, mock_delivery, monkeypatch):
        mock_client = self._setup_graph_mock(MockGraphClient)
        mock_client.list_unread_messages.return_value = []

        from function_app import process_email_reports

        timer = MagicMock()
        timer.past_due = False
        process_email_reports(timer)

        mock_delivery.send_teams_alert.assert_not_called()
        mock_delivery.send_email_alert.assert_not_called()

    @patch("function_app.delivery")
    @patch("function_app.GraphClient")
    def test_message_no_attachments_marked_read(self, MockGraphClient, mock_delivery):
        mock_client = self._setup_graph_mock(MockGraphClient)
        msg = self._make_message("1", "dmarc-reports@gieselman.com", has_attachments=False)
        mock_client.list_unread_messages.return_value = [msg]

        from function_app import process_email_reports

        timer = MagicMock()
        timer.past_due = False
        process_email_reports(timer)

        mock_client.mark_as_read.assert_called_once()

    @patch("function_app.storage")
    @patch("function_app.delivery")
    @patch("function_app.GraphClient")
    def test_dmarc_message_routed_correctly(self, MockGraphClient, mock_delivery, mock_storage, dmarc_b64_gz):
        mock_storage.report_exists.return_value = False
        mock_client = self._setup_graph_mock(MockGraphClient)
        msg = self._make_message("1", "dmarc-reports@gieselman.com")
        mock_client.list_unread_messages.return_value = [msg]
        mock_client.get_attachments.return_value = [{"name": "report.xml.gz", "contentBytes": dmarc_b64_gz}]

        from function_app import process_email_reports

        timer = MagicMock()
        timer.past_due = False
        process_email_reports(timer)

        mock_delivery.send_teams_alert.assert_called()

    @patch("function_app.storage")
    @patch("function_app.delivery")
    @patch("function_app.GraphClient")
    def test_tlsrpt_message_routed_correctly(self, MockGraphClient, mock_delivery, mock_storage, tlsrpt_b64_gz):
        mock_storage.report_exists.return_value = False
        mock_client = self._setup_graph_mock(MockGraphClient)
        msg = self._make_message("1", "tls-reports@gieselman.com")
        mock_client.list_unread_messages.return_value = [msg]
        mock_client.get_attachments.return_value = [{"name": "report.json.gz", "contentBytes": tlsrpt_b64_gz}]

        from function_app import process_email_reports

        timer = MagicMock()
        timer.past_due = False
        process_email_reports(timer)

        mock_delivery.send_teams_alert.assert_called()

    @patch("function_app.storage")
    @patch("function_app.delivery")
    @patch("function_app.GraphClient")
    def test_unknown_recipient_tries_both_parsers(self, MockGraphClient, mock_delivery, mock_storage, dmarc_b64_gz):
        mock_storage.report_exists.return_value = False
        mock_client = self._setup_graph_mock(MockGraphClient)
        msg = self._make_message("1", "other@gieselman.com")
        mock_client.list_unread_messages.return_value = [msg]
        mock_client.get_attachments.return_value = [{"name": "report.xml.gz", "contentBytes": dmarc_b64_gz}]

        from function_app import process_email_reports

        timer = MagicMock()
        timer.past_due = False
        process_email_reports(timer)

        mock_delivery.send_teams_alert.assert_called()

    @patch("function_app.delivery")
    @patch("function_app.GraphClient")
    def test_past_due_still_runs(self, MockGraphClient, mock_delivery):
        mock_client = self._setup_graph_mock(MockGraphClient)
        mock_client.list_unread_messages.return_value = []

        from function_app import process_email_reports

        timer = MagicMock()
        timer.past_due = True
        process_email_reports(timer)

        mock_client.list_unread_messages.assert_called_once()

    @patch("function_app.storage")
    @patch("function_app.delivery")
    @patch("function_app.GraphClient")
    def test_all_messages_marked_read(self, MockGraphClient, mock_delivery, mock_storage, dmarc_b64_gz, tlsrpt_b64_gz):
        mock_storage.report_exists.return_value = False
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

    @patch("function_app.storage")
    @patch("function_app.delivery")
    @patch("function_app.GraphClient")
    def test_immediate_delete(self, MockGraphClient, mock_delivery, mock_storage, monkeypatch, dmarc_b64_gz):
        monkeypatch.setenv("DELETE_AFTER_DAYS", "0")
        mock_storage.report_exists.return_value = False
        mock_client = self._setup_graph_mock(MockGraphClient)
        msg = self._make_message("1", "dmarc-reports@gieselman.com")
        mock_client.list_unread_messages.return_value = [msg]
        mock_client.get_attachments.return_value = [{"name": "r.xml.gz", "contentBytes": dmarc_b64_gz}]

        from function_app import process_email_reports

        timer = MagicMock()
        timer.past_due = False
        process_email_reports(timer)

        mock_client.delete_message.assert_called_once_with("emailreports@gieselman.com", "1")

    @patch("function_app.storage")
    @patch("function_app.delivery")
    @patch("function_app.GraphClient")
    def test_no_delete_when_minus_one(self, MockGraphClient, mock_delivery, mock_storage, monkeypatch, dmarc_b64_gz):
        monkeypatch.setenv("DELETE_AFTER_DAYS", "-1")
        mock_storage.report_exists.return_value = False
        mock_client = self._setup_graph_mock(MockGraphClient)
        msg = self._make_message("1", "dmarc-reports@gieselman.com")
        mock_client.list_unread_messages.return_value = [msg]
        mock_client.get_attachments.return_value = [{"name": "r.xml.gz", "contentBytes": dmarc_b64_gz}]

        from function_app import process_email_reports

        timer = MagicMock()
        timer.past_due = False
        process_email_reports(timer)

        mock_client.delete_message.assert_not_called()

    @patch("function_app.delivery")
    @patch("function_app.GraphClient")
    def test_deferred_delete(self, MockGraphClient, mock_delivery, monkeypatch):
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

    @patch("function_app.storage")
    @patch("function_app.delivery")
    @patch("function_app.GraphClient")
    def test_move_processed_to_folder(self, MockGraphClient, mock_delivery, mock_storage, monkeypatch, dmarc_b64_gz):
        monkeypatch.setenv("DELETE_AFTER_DAYS", "-1")
        monkeypatch.setenv("MOVE_PROCESSED_TO", "Processed")
        mock_storage.report_exists.return_value = False
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

    @patch("function_app.storage")
    @patch("function_app.delivery")
    @patch("function_app.GraphClient")
    def test_immediate_delete_skips_move(self, MockGraphClient, mock_delivery, mock_storage, monkeypatch, dmarc_b64_gz):
        """When DELETE_AFTER_DAYS=0, delete takes priority over move."""
        monkeypatch.setenv("DELETE_AFTER_DAYS", "0")
        monkeypatch.setenv("MOVE_PROCESSED_TO", "Processed")
        mock_storage.report_exists.return_value = False
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

    @patch("function_app.storage")
    @patch("function_app.delivery")
    @patch("function_app.GraphClient")
    def test_generic_webhook_called(self, MockGraphClient, mock_delivery, mock_storage, dmarc_b64_gz):
        mock_storage.report_exists.return_value = False
        mock_client = self._setup_graph_mock(MockGraphClient)
        msg = self._make_message("1", "dmarc-reports@gieselman.com")
        mock_client.list_unread_messages.return_value = [msg]
        mock_client.get_attachments.return_value = [{"name": "r.xml.gz", "contentBytes": dmarc_b64_gz}]

        from function_app import process_email_reports

        timer = MagicMock()
        timer.past_due = False
        process_email_reports(timer)

        mock_delivery.send_generic_webhook.assert_called()

    @patch("function_app.storage")
    @patch("function_app.delivery")
    @patch("function_app.GraphClient")
    def test_single_message_failure_continues(self, MockGraphClient, mock_delivery, mock_storage, dmarc_b64_gz):
        """A failure on one message should not skip subsequent messages."""
        mock_storage.report_exists.return_value = False
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
        mock_delivery.send_teams_alert.assert_called()

    @patch("function_app.delivery")
    @patch("function_app.GraphClient")
    def test_cleanup_delete_failure_continues(self, MockGraphClient, mock_delivery, monkeypatch):
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

    @patch("function_app.delivery")
    @patch("function_app.GraphClient")
    def test_error_sends_notification_and_reraises(self, MockGraphClient, mock_delivery):
        mock_client = self._setup_graph_mock(MockGraphClient)
        mock_client.list_unread_messages.side_effect = RuntimeError("Token expired")

        from function_app import process_email_reports

        timer = MagicMock()
        timer.past_due = False

        import pytest

        with pytest.raises(RuntimeError, match="Token expired"):
            process_email_reports(timer)

        mock_delivery.send_teams_alert.assert_called_once()
        error_alert = mock_delivery.send_teams_alert.call_args[0][0]
        assert "Error" in error_alert.title
        mock_delivery.send_generic_webhook.assert_called_once()

    @patch("function_app.delivery")
    @patch("function_app.GraphClient")
    def test_error_notification_failure_doesnt_mask_original(self, MockGraphClient, mock_delivery):
        """If error notification itself fails, the original error still propagates."""
        mock_client = self._setup_graph_mock(MockGraphClient)
        mock_client.list_unread_messages.side_effect = RuntimeError("Graph down")
        mock_delivery.send_teams_alert.side_effect = Exception("Teams also down")
        mock_delivery.send_generic_webhook.side_effect = Exception("Webhook also down")

        from function_app import process_email_reports

        timer = MagicMock()
        timer.past_due = False

        import pytest

        with pytest.raises(RuntimeError, match="Graph down"):
            process_email_reports(timer)

    @patch("function_app.storage")
    @patch("function_app.delivery")
    @patch("function_app.GraphClient")
    def test_alert_delivery_failure_continues(self, MockGraphClient, mock_delivery, mock_storage, dmarc_b64_gz):
        """A failure delivering one alert should not prevent delivering the rest."""
        mock_storage.report_exists.return_value = False
        mock_client = self._setup_graph_mock(MockGraphClient)
        msgs = [
            self._make_message("1", "dmarc-reports@gieselman.com"),
            self._make_message("2", "dmarc-reports@gieselman.com"),
        ]
        mock_client.list_unread_messages.return_value = msgs
        mock_client.get_attachments.return_value = [{"name": "r.xml.gz", "contentBytes": dmarc_b64_gz}]
        # First Teams call fails, second should still happen
        mock_delivery.send_teams_alert.side_effect = [Exception("webhook down"), None]

        from function_app import process_email_reports

        timer = MagicMock()
        timer.past_due = False
        process_email_reports(timer)

        assert mock_delivery.send_teams_alert.call_count == 2

    @patch("function_app.delivery")
    @patch("function_app.GraphClient")
    def test_cleanup_uses_move_folder(self, MockGraphClient, mock_delivery, monkeypatch):
        """Cleanup should look in the move-to folder, not the source folder."""
        monkeypatch.setenv("DELETE_AFTER_DAYS", "30")
        monkeypatch.setenv("MOVE_PROCESSED_TO", "Processed")
        mock_client = self._setup_graph_mock(MockGraphClient)
        mock_client.list_unread_messages.return_value = []
        mock_client.list_read_messages_older_than.return_value = []

        from function_app import process_email_reports

        timer = MagicMock()
        timer.past_due = False
        process_email_reports(timer)

        mock_client.list_read_messages_older_than.assert_called_once_with(
            "emailreports@gieselman.com", 30, folder="Processed"
        )

    def test_validate_config_missing_var(self, monkeypatch):
        monkeypatch.delenv("REPORT_MAILBOX", raising=False)

        import pytest

        from function_app import _validate_config

        with pytest.raises(RuntimeError, match="REPORT_MAILBOX"):
            _validate_config()

    def test_validate_config_passes(self):
        from function_app import _validate_config

        _validate_config()  # should not raise with env defaults from conftest


# ---------------------------------------------------------------------------
# Weekly summary timer
# ---------------------------------------------------------------------------


class TestWeeklySummary:
    @patch("function_app.storage")
    @patch("function_app.delivery")
    @patch("function_app.GraphClient")
    def test_skips_when_disabled(self, MockGraphClient, mock_delivery, mock_storage, monkeypatch):
        monkeypatch.setenv("SUMMARY_ENABLED", "false")

        from function_app import send_weekly_summary

        timer = MagicMock()
        send_weekly_summary(timer)

        mock_storage.query_period.assert_not_called()

    @patch("function_app.storage")
    @patch("function_app.delivery")
    @patch("function_app.GraphClient")
    def test_sends_when_enabled(self, MockGraphClient, mock_delivery, mock_storage, monkeypatch):
        monkeypatch.setenv("SUMMARY_ENABLED", "true")
        monkeypatch.setenv("SUMMARY_DAYS", "7")

        from models import ReportRecord

        mock_storage.query_period.return_value = [
            ReportRecord(report_type="dmarc", report_id="1", org_name="google.com", domain="test.com")
        ]
        mock_storage.query_period_range.return_value = []

        mock_client = MagicMock()
        MockGraphClient.return_value.__enter__ = MagicMock(return_value=mock_client)
        MockGraphClient.return_value.__exit__ = MagicMock(return_value=False)

        from function_app import send_weekly_summary

        timer = MagicMock()
        send_weekly_summary(timer)

        mock_storage.query_period.assert_called_once_with(days=7)
        mock_storage.query_period_range.assert_called_once_with(14, 7)
        mock_delivery.send_teams_alert.assert_called()
        mock_delivery.send_email_alert.assert_called()

    @patch("function_app.storage")
    @patch("function_app.delivery")
    @patch("function_app.GraphClient")
    def test_skips_when_no_records(self, MockGraphClient, mock_delivery, mock_storage, monkeypatch):
        monkeypatch.setenv("SUMMARY_ENABLED", "true")
        mock_storage.query_period.return_value = []

        from function_app import send_weekly_summary

        timer = MagicMock()
        send_weekly_summary(timer)

        mock_delivery.send_teams_alert.assert_not_called()

    @patch("function_app._send_error_notification")
    @patch("function_app.storage")
    @patch("function_app.delivery")
    @patch("function_app.GraphClient")
    def test_error_sends_notification(self, MockGraphClient, mock_delivery, mock_storage, mock_notify, monkeypatch):
        monkeypatch.setenv("SUMMARY_ENABLED", "true")
        mock_storage.query_period.side_effect = RuntimeError("storage down")

        import pytest

        from function_app import send_weekly_summary

        timer = MagicMock()
        with pytest.raises(RuntimeError, match="storage down"):
            send_weekly_summary(timer)

        mock_notify.assert_called_once()


# ---------------------------------------------------------------------------
# _save_report
# ---------------------------------------------------------------------------


class TestSaveReport:
    @patch("function_app.storage")
    def test_saves_dmarc_report(self, mock_storage):
        from models import DmarcDisposition, DmarcReport

        report = DmarcReport(
            org_name="google.com",
            report_id="test-1",
            date_begin=MagicMock(),
            date_end=MagicMock(),
            domain="test.com",
            policy=DmarcDisposition.REJECT,
        )

        from function_app import _save_report

        _save_report(report, base64.b64encode(b"test-data").decode())
        mock_storage.save_report_record.assert_called_once()
        record = mock_storage.save_report_record.call_args[0][0]
        assert record.report_type == "dmarc"
        assert record.org_name == "google.com"
        assert record.dmarc_failure_details_json == ""

    @patch("function_app.storage")
    def test_saves_dmarc_failure_details(self, mock_storage):
        import json

        from models import DmarcDisposition, DmarcRecord, DmarcReport, DmarcResult

        report = DmarcReport(
            org_name="google.com",
            report_id="test-fail",
            date_begin=MagicMock(),
            date_end=MagicMock(),
            domain="test.com",
            policy=DmarcDisposition.REJECT,
            records=[
                DmarcRecord(
                    source_ip="5.6.7.8",
                    count=3,
                    disposition=DmarcDisposition.NONE,
                    dkim_result=DmarcResult.FAIL,
                    spf_result=DmarcResult.FAIL,
                    header_from="test.com",
                )
            ],
        )

        from function_app import _save_report

        _save_report(report, base64.b64encode(b"test-data").decode())
        record = mock_storage.save_report_record.call_args[0][0]
        details = json.loads(record.dmarc_failure_details_json)
        assert len(details) == 1
        assert details[0]["source_ip"] == "5.6.7.8"
        assert details[0]["count"] == 3
        assert details[0]["dkim_result"] == "fail"
        assert details[0]["spf_result"] == "fail"
        assert details[0]["org_name"] == "google.com"

    @patch("function_app.storage")
    def test_saves_tlsrpt_report(self, mock_storage):
        from models import TlsPolicy, TlsRptReport

        report = TlsRptReport(
            org_name="microsoft.com",
            report_id="tls-1",
            date_begin=MagicMock(),
            date_end=MagicMock(),
            policies=[
                TlsPolicy(
                    policy_type="sts", policy_domain="test.com", successful_session_count=100, failed_session_count=2
                )
            ],
        )

        from function_app import _save_report

        _save_report(report, base64.b64encode(b"test-data").decode())
        mock_storage.save_report_record.assert_called_once()
        record = mock_storage.save_report_record.call_args[0][0]
        assert record.report_type == "tlsrpt"
        assert record.pass_count == 100
        assert record.fail_count == 2
        assert record.tls_failure_details_json == ""

    @patch("function_app.storage")
    def test_saves_tlsrpt_failure_details(self, mock_storage):
        import json

        from models import TlsFailureDetail, TlsPolicy, TlsRptReport

        report = TlsRptReport(
            org_name="google.com",
            report_id="tls-fail",
            date_begin=MagicMock(),
            date_end=MagicMock(),
            policies=[
                TlsPolicy(
                    policy_type="sts",
                    policy_domain="test.com",
                    successful_session_count=9,
                    failed_session_count=1,
                    failure_details=[
                        TlsFailureDetail(
                            result_type="sts-policy-fetch-error",
                            sending_mta_ip="1.2.3.4",
                            receiving_mx_hostname="mail.test.com",
                            failed_session_count=1,
                            failure_reason_code="",
                        )
                    ],
                )
            ],
        )

        from function_app import _save_report

        _save_report(report, base64.b64encode(b"test-data").decode())
        record = mock_storage.save_report_record.call_args[0][0]
        details = json.loads(record.tls_failure_details_json)
        assert len(details) == 1
        assert details[0]["result_type"] == "sts-policy-fetch-error"
        assert details[0]["receiving_mx_hostname"] == "mail.test.com"

    @patch("function_app.storage")
    def test_save_failure_does_not_raise(self, mock_storage):
        mock_storage.save_report_record.side_effect = Exception("storage down")

        from models import DmarcDisposition, DmarcReport

        report = DmarcReport(
            org_name="test",
            report_id="1",
            date_begin=MagicMock(),
            date_end=MagicMock(),
            domain="test.com",
            policy=DmarcDisposition.NONE,
        )

        from function_app import _save_report

        _save_report(report, base64.b64encode(b"data").decode())  # should not raise


# ---------------------------------------------------------------------------
# Abuse reporting integration
# ---------------------------------------------------------------------------


class TestAbuseReportingIntegration:
    def _make_message(self, msg_id, to_address, has_attachments=True):
        return {
            "id": msg_id,
            "subject": f"Report {msg_id}",
            "hasAttachments": has_attachments,
            "toRecipients": [{"emailAddress": {"address": to_address}}],
        }

    @staticmethod
    def _setup_graph_mock(MockGraphClient):
        mock_client = MagicMock()
        MockGraphClient.return_value.__enter__ = MagicMock(return_value=mock_client)
        MockGraphClient.return_value.__exit__ = MagicMock(return_value=False)
        return mock_client

    @patch("function_app.abuse")
    @patch("function_app.storage")
    @patch("function_app.delivery")
    @patch("function_app.GraphClient")
    def test_abuse_reports_sent_when_enabled(
        self, MockGraphClient, mock_delivery, mock_storage, mock_abuse, monkeypatch, dmarc_b64_gz
    ):
        monkeypatch.setenv("ABUSE_REPORTING_ENABLED", "true")
        mock_storage.report_exists.return_value = False
        mock_abuse.is_abuse_reporting_enabled.return_value = True
        mock_abuse.send_abuse_reports.return_value = 1

        mock_client = self._setup_graph_mock(MockGraphClient)
        msg = self._make_message("1", "dmarc-reports@gieselman.com")
        mock_client.list_unread_messages.return_value = [msg]
        mock_client.get_attachments.return_value = [{"name": "r.xml.gz", "contentBytes": dmarc_b64_gz}]

        from function_app import process_email_reports

        timer = MagicMock()
        timer.past_due = False
        process_email_reports(timer)

        mock_abuse.send_abuse_reports.assert_called_once()

    @patch("function_app.abuse")
    @patch("function_app.storage")
    @patch("function_app.delivery")
    @patch("function_app.GraphClient")
    def test_abuse_reports_skipped_when_disabled(
        self, MockGraphClient, mock_delivery, mock_storage, mock_abuse, dmarc_b64_gz
    ):
        mock_storage.report_exists.return_value = False
        mock_abuse.is_abuse_reporting_enabled.return_value = False

        mock_client = self._setup_graph_mock(MockGraphClient)
        msg = self._make_message("1", "dmarc-reports@gieselman.com")
        mock_client.list_unread_messages.return_value = [msg]
        mock_client.get_attachments.return_value = [{"name": "r.xml.gz", "contentBytes": dmarc_b64_gz}]

        from function_app import process_email_reports

        timer = MagicMock()
        timer.past_due = False
        process_email_reports(timer)

        mock_abuse.send_abuse_reports.assert_not_called()

    @patch("function_app.abuse")
    @patch("function_app.storage")
    @patch("function_app.delivery")
    @patch("function_app.GraphClient")
    def test_abuse_report_failure_does_not_stop_run(
        self, MockGraphClient, mock_delivery, mock_storage, mock_abuse, dmarc_b64_gz
    ):
        mock_storage.report_exists.return_value = False
        mock_abuse.is_abuse_reporting_enabled.return_value = True
        mock_abuse.send_abuse_reports.side_effect = Exception("RDAP down")

        mock_client = self._setup_graph_mock(MockGraphClient)
        msg = self._make_message("1", "dmarc-reports@gieselman.com")
        mock_client.list_unread_messages.return_value = [msg]
        mock_client.get_attachments.return_value = [{"name": "r.xml.gz", "contentBytes": dmarc_b64_gz}]

        from function_app import process_email_reports

        timer = MagicMock()
        timer.past_due = False
        process_email_reports(timer)  # should not raise

    @patch("function_app.storage")
    def test_parse_attachments_collects_abuse_candidates(self, mock_storage, dmarc_b64_gz):
        import alert as alert_mod

        mock_storage.report_exists.return_value = False

        from function_app import _parse_attachments

        candidates: list = []
        attachments = [{"name": "report.xml.gz", "contentBytes": dmarc_b64_gz}]
        _parse_attachments(
            attachments,
            "test",
            dmarc_parser.parse_attachment,
            alert_mod.build_dmarc_alert,
            abuse_candidates=candidates,
        )
        assert len(candidates) == 1

    @patch("function_app.storage")
    def test_parse_attachments_no_candidates_for_tlsrpt(self, mock_storage, tlsrpt_b64_gz):
        import alert as alert_mod

        mock_storage.report_exists.return_value = False

        from function_app import _parse_attachments

        candidates: list = []
        attachments = [{"name": "report.json.gz", "contentBytes": tlsrpt_b64_gz}]
        _parse_attachments(
            attachments,
            "test",
            tlsrpt_parser.parse_attachment,
            alert_mod.build_tlsrpt_alert,
            abuse_candidates=candidates,
        )
        assert len(candidates) == 0

    @patch("function_app.storage")
    @patch("function_app.delivery")
    @patch("function_app.GraphClient")
    def test_weekly_summary_includes_abuse_count(self, MockGraphClient, mock_delivery, mock_storage, monkeypatch):
        monkeypatch.setenv("SUMMARY_ENABLED", "true")
        monkeypatch.setenv("SUMMARY_DAYS", "7")

        from models import ReportRecord

        mock_storage.query_period.return_value = [
            ReportRecord(report_type="dmarc", report_id="1", org_name="google.com", domain="test.com")
        ]
        mock_storage.query_period_range.return_value = []
        mock_storage.count_abuse_reports.return_value = 3

        mock_client = MagicMock()
        MockGraphClient.return_value.__enter__ = MagicMock(return_value=mock_client)
        MockGraphClient.return_value.__exit__ = MagicMock(return_value=False)

        from function_app import send_weekly_summary

        timer = MagicMock()
        send_weekly_summary(timer)

        mock_storage.count_abuse_reports.assert_called_once_with(days=7)
