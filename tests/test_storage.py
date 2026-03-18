"""Tests for storage.py — Table Storage report tracking."""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import MagicMock, patch

import storage
from models import ReportRecord


class TestGetTableClient:
    @patch("storage.TableServiceClient")
    def test_creates_table_if_not_exists(self, MockTableService):
        mock_service = MagicMock()
        MockTableService.from_connection_string.return_value = mock_service

        client = storage._get_table_client()

        mock_service.create_table_if_not_exists.assert_called_once_with("reporthistory")
        mock_service.get_table_client.assert_called_once_with("reporthistory")
        assert client == mock_service.get_table_client.return_value


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
            }
        ]
        mock_get_client.return_value = mock_table

        records = storage.query_period(days=7)
        assert len(records) == 1
        assert records[0].org_name == "google.com"
        assert records[0].report_id == "test-1"

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
