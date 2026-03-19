"""Azure Table Storage for report tracking."""

from __future__ import annotations

import logging
import os
from datetime import UTC, datetime, timedelta

from azure.data.tables import TableClient, TableServiceClient

from models import ReportRecord

logger = logging.getLogger(__name__)

TABLE_NAME = "reporthistory"


def _get_table_client() -> TableClient:
    conn_str = os.environ["AzureWebJobsStorage"]
    service = TableServiceClient.from_connection_string(conn_str)
    service.create_table_if_not_exists(TABLE_NAME)
    return service.get_table_client(TABLE_NAME)


def save_report_record(record: ReportRecord) -> None:
    """Save a report record to Table Storage."""
    table = _get_table_client()
    # Partition by year-week for efficient range queries
    year_week = record.received_at.strftime("%Y-W%W")
    entity = {
        "PartitionKey": year_week,
        "RowKey": f"{record.report_type}_{record.report_id}",
        "report_type": record.report_type,
        "org_name": record.org_name,
        "domain": record.domain,
        "total_messages": record.total_messages,
        "pass_count": record.pass_count,
        "fail_count": record.fail_count,
        "policy": record.policy,
        "attachment_size_bytes": record.attachment_size_bytes,
        "received_at": record.received_at,
        "dmarc_failure_details_json": record.dmarc_failure_details_json,
        "tls_failure_details_json": record.tls_failure_details_json,
    }
    table.upsert_entity(entity)
    logger.debug("Saved report record: %s/%s", year_week, entity["RowKey"])


def query_period(days: int = 7) -> list[ReportRecord]:
    """Query report records from the last *days* days."""
    table = _get_table_client()
    cutoff = datetime.now(UTC) - timedelta(days=days)
    cutoff_str = cutoff.strftime("%Y-%m-%dT%H:%M:%SZ")

    records: list[ReportRecord] = []
    entities = table.query_entities(f"received_at ge datetime'{cutoff_str}'")
    for e in entities:
        received = e.get("received_at", cutoff)
        if hasattr(received, "replace"):
            received = received.replace(tzinfo=UTC) if received.tzinfo is None else received
        records.append(
            ReportRecord(
                report_type=e.get("report_type", ""),
                report_id=e.get("RowKey", "").split("_", 1)[-1],
                org_name=e.get("org_name", ""),
                domain=e.get("domain", ""),
                total_messages=e.get("total_messages", 0),
                pass_count=e.get("pass_count", 0),
                fail_count=e.get("fail_count", 0),
                policy=e.get("policy", ""),
                attachment_size_bytes=e.get("attachment_size_bytes", 0),
                received_at=received,
                dmarc_failure_details_json=e.get("dmarc_failure_details_json", ""),
                tls_failure_details_json=e.get("tls_failure_details_json", ""),
            )
        )
    return records
