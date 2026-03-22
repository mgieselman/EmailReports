"""Tests for storage.py — Table Storage report tracking."""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import MagicMock, patch

import pytest

import storage
from models import ReportRecord


@pytest.fixture(autouse=True)
def _clear_table_client_cache():
    """Reset the module-level TableClient cache between tests."""
    storage._cached_client = None
    yield
    storage._cached_client = None


class TestGetTableClient:
    @patch("storage.TableServiceClient")
    def test_creates_table_if_not_exists(self, MockTableService):
        mock_service = MagicMock()
        MockTableService.from_connection_string.return_value = mock_service

        client = storage._get_table_client()

        mock_service.create_table_if_not_exists.assert_called_once_with("reporthistory")
        mock_service.get_table_client.assert_called_once_with("reporthistory")
        assert client == mock_service.get_table_client.return_value

    @patch("storage.TableServiceClient")
    def test_caches_client(self, MockTableService):
        mock_service = MagicMock()
        MockTableService.from_connection_string.return_value = mock_service

        client1 = storage._get_table_client()
        client2 = storage._get_table_client()

        assert client1 is client2
        MockTableService.from_connection_string.assert_called_once()


class TestSaveReportRecord:
    @patch("storage._get_table_client")
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

    @patch("storage._get_table_client")
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
    @patch("storage._get_table_client")
    def test_returns_true_when_found(self, mock_get_client):
        mock_table = MagicMock()
        mock_table.query_entities.return_value = [{"RowKey": "dmarc_test-123"}]
        mock_get_client.return_value = mock_table

        assert storage.report_exists("dmarc", "test-123") is True
        mock_table.query_entities.assert_called_once()

    @patch("storage._get_table_client")
    def test_returns_false_when_not_found(self, mock_get_client):
        mock_table = MagicMock()
        mock_table.query_entities.return_value = []
        mock_get_client.return_value = mock_table

        assert storage.report_exists("dmarc", "nonexistent") is False

    @patch("storage._get_table_client")
    def test_uses_correct_row_key_format(self, mock_get_client):
        mock_table = MagicMock()
        mock_table.query_entities.return_value = []
        mock_get_client.return_value = mock_table

        storage.report_exists("tlsrpt", "report-456")
        query_filter = mock_table.query_entities.call_args[0][0]
        assert "tlsrpt_report-456" in query_filter


class TestQueryPeriod:
    @patch("storage._get_table_client")
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

    @patch("storage._get_table_client")
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

    @patch("storage._get_table_client")
    def test_empty_result(self, mock_get_client):
        mock_table = MagicMock()
        mock_table.query_entities.return_value = []
        mock_get_client.return_value = mock_table

        records = storage.query_period(days=7)
        assert records == []

    @patch("storage._get_table_client")
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
