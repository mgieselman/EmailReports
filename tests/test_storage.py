"""Tests for storage.py — Table Storage report tracking."""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import MagicMock, patch

import pytest

import storage
from models import AbuseReportRecord, ReportRecord


@pytest.fixture(autouse=True)
def _clear_table_client_cache():
    """Reset the module-level TableClient cache between tests."""
    storage._cached_clients.clear()
    yield
    storage._cached_clients.clear()


class TestGetTable:
    @patch("storage.TableServiceClient")
    def test_creates_table_if_not_exists(self, MockTableService):
        mock_service = MagicMock()
        MockTableService.from_connection_string.return_value = mock_service

        client = storage._get_table("reporthistory")

        mock_service.create_table_if_not_exists.assert_called_once_with("reporthistory")
        mock_service.get_table_client.assert_called_once_with("reporthistory")
        assert client == mock_service.get_table_client.return_value

    @patch("storage.TableServiceClient")
    def test_caches_client(self, MockTableService):
        mock_service = MagicMock()
        MockTableService.from_connection_string.return_value = mock_service

        client1 = storage._get_table("reporthistory")
        client2 = storage._get_table("reporthistory")

        assert client1 is client2
        MockTableService.from_connection_string.assert_called_once()


class TestBuildTableService:
    @patch("storage.TableServiceClient")
    def test_uses_connection_string_when_available(self, MockTableService):
        mock_service = MagicMock()
        MockTableService.from_connection_string.return_value = mock_service

        result = storage._build_table_service()

        MockTableService.from_connection_string.assert_called_once()
        assert result == mock_service

    @patch("storage.TableServiceClient")
    def test_uses_managed_identity_when_no_connection_string(self, MockTableService, monkeypatch):
        monkeypatch.delenv("AzureWebJobsStorage", raising=False)
        monkeypatch.setenv("AzureWebJobsStorage__accountName", "mystorageaccount")
        mock_service = MagicMock()
        MockTableService.return_value = mock_service

        with patch("azure.identity.DefaultAzureCredential") as MockCredential:
            mock_cred = MagicMock()
            MockCredential.return_value = mock_cred

            result = storage._build_table_service()

            MockTableService.assert_called_once_with(
                endpoint="https://mystorageaccount.table.core.windows.net",
                credential=mock_cred,
            )
            assert result == mock_service

    def test_raises_when_no_storage_config(self, monkeypatch):
        monkeypatch.delenv("AzureWebJobsStorage", raising=False)
        monkeypatch.delenv("AzureWebJobsStorage__accountName", raising=False)

        with pytest.raises(RuntimeError, match="No storage configuration"):
            storage._build_table_service()


class TestSaveReportRecord:
    @patch("storage._get_table")
    def test_saves_entity(self, mock_get_client):
        mock_table = MagicMock()
        mock_get_client.return_value = mock_table

        record = ReportRecord(
            report_type="dmarc",
            report_id="test-123",
            org_name="google.com",
            domain="example.com",
            total_messages=100,
            pass_count=95,
            fail_count=5,
            policy="reject",
            attachment_size_bytes=4000,
            received_at=datetime(2026, 3, 17, tzinfo=UTC),
        )
        storage.save_report_record(record)

        mock_table.upsert_entity.assert_called_once()
        entity = mock_table.upsert_entity.call_args[0][0]
        assert entity["report_type"] == "dmarc"
        assert entity["org_name"] == "google.com"
        assert entity["total_messages"] == 100
        assert entity["PartitionKey"] == "2026-W11"
        assert "dmarc_test-123" in entity["RowKey"]
        assert entity["dmarc_failure_details_json"] == ""
        assert entity["tls_failure_details_json"] == ""

    @patch("storage._get_table")
    def test_saves_failure_details_json(self, mock_get_client):
        mock_table = MagicMock()
        mock_get_client.return_value = mock_table

        record = ReportRecord(
            report_type="dmarc",
            report_id="test-456",
            org_name="google.com",
            domain="example.com",
            total_messages=10,
            pass_count=8,
            fail_count=2,
            received_at=datetime(2026, 3, 17, tzinfo=UTC),
            dmarc_failure_details_json='[{"source_ip":"1.2.3.4","count":2}]',
        )
        storage.save_report_record(record)

        entity = mock_table.upsert_entity.call_args[0][0]
        assert entity["dmarc_failure_details_json"] == '[{"source_ip":"1.2.3.4","count":2}]'


class TestReportExists:
    @patch("storage._get_table")
    def test_returns_true_when_found(self, mock_get_client):
        mock_table = MagicMock()
        mock_table.query_entities.return_value = [{"RowKey": "dmarc_test-123"}]
        mock_get_client.return_value = mock_table

        assert storage.report_exists("dmarc", "test-123") is True
        mock_table.query_entities.assert_called_once()

    @patch("storage._get_table")
    def test_returns_false_when_not_found(self, mock_get_client):
        mock_table = MagicMock()
        mock_table.query_entities.return_value = []
        mock_get_client.return_value = mock_table

        assert storage.report_exists("dmarc", "nonexistent") is False

    @patch("storage._get_table")
    def test_uses_correct_row_key_format(self, mock_get_client):
        mock_table = MagicMock()
        mock_table.query_entities.return_value = []
        mock_get_client.return_value = mock_table

        storage.report_exists("tlsrpt", "report-456")
        query_filter = mock_table.query_entities.call_args[0][0]
        assert "tlsrpt_report-456" in query_filter


class TestQueryPeriod:
    @patch("storage._get_table")
    def test_returns_records(self, mock_get_client):
        mock_table = MagicMock()
        mock_table.query_entities.return_value = [
            {
                "PartitionKey": "2026-W11",
                "RowKey": "dmarc_test-1",
                "report_type": "dmarc",
                "org_name": "google.com",
                "domain": "example.com",
                "total_messages": 100,
                "pass_count": 95,
                "fail_count": 5,
                "policy": "reject",
                "attachment_size_bytes": 4000,
                "received_at": datetime(2026, 3, 17, tzinfo=UTC),
                "dmarc_failure_details_json": '[{"source_ip":"1.2.3.4"}]',
                "tls_failure_details_json": "",
            }
        ]
        mock_get_client.return_value = mock_table

        records = storage.query_period(days=7)
        assert len(records) == 1
        assert records[0].org_name == "google.com"
        assert records[0].report_id == "test-1"
        assert records[0].dmarc_failure_details_json == '[{"source_ip":"1.2.3.4"}]'
        assert records[0].tls_failure_details_json == ""

    @patch("storage._get_table")
    def test_missing_json_fields_default_to_empty(self, mock_get_client):
        """Old records without failure detail fields should get empty strings."""
        mock_table = MagicMock()
        mock_table.query_entities.return_value = [
            {
                "RowKey": "dmarc_old-1",
                "report_type": "dmarc",
                "org_name": "old.com",
                "received_at": datetime(2026, 3, 17, tzinfo=UTC),
            }
        ]
        mock_get_client.return_value = mock_table

        records = storage.query_period(days=7)
        assert records[0].dmarc_failure_details_json == ""
        assert records[0].tls_failure_details_json == ""

    @patch("storage._get_table")
    def test_empty_result(self, mock_get_client):
        mock_table = MagicMock()
        mock_table.query_entities.return_value = []
        mock_get_client.return_value = mock_table

        records = storage.query_period(days=7)
        assert records == []

    @patch("storage._get_table")
    def test_handles_naive_datetime(self, mock_get_client):
        mock_table = MagicMock()
        mock_table.query_entities.return_value = [
            {
                "RowKey": "dmarc_test-1",
                "report_type": "dmarc",
                "org_name": "test",
                "received_at": datetime(2026, 3, 17),  # naive
            }
        ]
        mock_get_client.return_value = mock_table

        records = storage.query_period(days=7)
        assert records[0].received_at.tzinfo == UTC


class TestQueryPeriodRange:
    @patch("storage._get_table")
    def test_returns_records_in_range(self, mock_get_client):
        mock_table = MagicMock()
        mock_table.query_entities.return_value = [
            {
                "RowKey": "dmarc_prev-1",
                "report_type": "dmarc",
                "org_name": "google.com",
                "domain": "example.com",
                "total_messages": 50,
                "pass_count": 48,
                "fail_count": 2,
                "received_at": datetime(2026, 3, 10, tzinfo=UTC),
            }
        ]
        mock_get_client.return_value = mock_table

        records = storage.query_period_range(14, 7)
        assert len(records) == 1
        assert records[0].report_id == "prev-1"
        # Verify filter uses both ge and lt
        query_filter = mock_table.query_entities.call_args[0][0]
        assert "ge datetime'" in query_filter
        assert "lt datetime'" in query_filter

    @patch("storage._get_table")
    def test_empty_range(self, mock_get_client):
        mock_table = MagicMock()
        mock_table.query_entities.return_value = []
        mock_get_client.return_value = mock_table

        records = storage.query_period_range(14, 7)
        assert records == []


# ---------------------------------------------------------------------------
# Abuse report tracking
# ---------------------------------------------------------------------------


class TestGetTableAbuseReports:
    @patch("storage._build_table_service")
    def test_creates_abuse_table_if_not_exists(self, mock_build):
        mock_service = MagicMock()
        mock_build.return_value = mock_service

        client = storage._get_table("abusereports")

        mock_service.create_table_if_not_exists.assert_called_once_with("abusereports")
        mock_service.get_table_client.assert_called_once_with("abusereports")
        assert client == mock_service.get_table_client.return_value

    @patch("storage._build_table_service")
    def test_different_tables_cached_separately(self, mock_build):
        mock_service = MagicMock()
        mock_build.return_value = mock_service

        storage._get_table("reporthistory")
        storage._get_table("abusereports")

        assert mock_service.create_table_if_not_exists.call_count == 2
        assert len(storage._cached_clients) == 2


class TestAbuseReportExists:
    @patch("storage._get_table")
    def test_returns_true_when_found(self, mock_get_table):
        mock_table = MagicMock()
        mock_table.get_entity.return_value = {"RowKey": "74.208.4.196"}
        mock_get_table.return_value = mock_table

        assert storage.abuse_report_exists("74.208.4.196") is True
        mock_table.get_entity.assert_called_once()

    @patch("storage._get_table")
    def test_returns_false_when_not_found(self, mock_get_table):
        mock_table = MagicMock()
        mock_table.get_entity.side_effect = Exception("not found")
        mock_get_table.return_value = mock_table

        assert storage.abuse_report_exists("74.208.4.196") is False

    @patch("storage._get_table")
    def test_uses_point_read_with_correct_keys(self, mock_get_table):
        mock_table = MagicMock()
        mock_table.get_entity.side_effect = Exception("not found")
        mock_get_table.return_value = mock_table

        storage.abuse_report_exists("1.2.3.4")
        call_args = mock_table.get_entity.call_args
        assert call_args[0][1] == "1.2.3.4"


class TestSaveAbuseReport:
    @patch("storage._get_table")
    def test_saves_entity(self, mock_get_client):
        mock_table = MagicMock()
        mock_get_client.return_value = mock_table

        record = AbuseReportRecord(
            source_ip="74.208.4.196",
            abuse_email="abuse@ionos.com",
            domain="gieselman.com",
            report_count=1,
            sent_at=datetime(2026, 4, 3, tzinfo=UTC),
        )
        storage.save_abuse_report(record)

        mock_table.upsert_entity.assert_called_once()
        entity = mock_table.upsert_entity.call_args[0][0]
        assert entity["RowKey"] == "74.208.4.196"
        assert entity["abuse_email"] == "abuse@ionos.com"
        assert entity["domain"] == "gieselman.com"
        assert entity["report_count"] == 1
        assert entity["PartitionKey"] == "2026-W13"


class TestCountAbuseReports:
    @patch("storage._get_table")
    def test_counts_recent_reports(self, mock_get_client):
        mock_table = MagicMock()
        mock_table.query_entities.return_value = [
            {"RowKey": "1.2.3.4"},
            {"RowKey": "5.6.7.8"},
        ]
        mock_get_client.return_value = mock_table

        assert storage.count_abuse_reports(days=7) == 2

    @patch("storage._get_table")
    def test_returns_zero_when_none(self, mock_get_client):
        mock_table = MagicMock()
        mock_table.query_entities.return_value = []
        mock_get_client.return_value = mock_table

        assert storage.count_abuse_reports(days=7) == 0

    @patch("storage._get_table")
    def test_uses_sent_at_filter(self, mock_get_client):
        mock_table = MagicMock()
        mock_table.query_entities.return_value = []
        mock_get_client.return_value = mock_table

        storage.count_abuse_reports(days=7)
        query_filter = mock_table.query_entities.call_args[0][0]
        assert "sent_at ge datetime'" in query_filter
