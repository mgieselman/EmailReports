"""Azure Table Storage for report tracking."""

from __future__ import annotations

import logging
import os
from datetime import UTC, datetime, timedelta

from azure.data.tables import TableClient, TableServiceClient

from models import AbuseReportRecord, ReportRecord

logger = logging.getLogger(__name__)

TABLE_NAME = "reporthistory"
ABUSE_TABLE_NAME = "abusereports"

_cached_clients: dict[str, TableClient] = {}


def _get_table(name: str) -> TableClient:
    """Return a cached TableClient for *name*, creating the table on first access."""
    if name not in _cached_clients:
        conn_str = os.environ["AzureWebJobsStorage"]
        service = TableServiceClient.from_connection_string(conn_str)
        service.create_table_if_not_exists(name)
        _cached_clients[name] = service.get_table_client(name)
    return _cached_clients[name]


def save_report_record(record: ReportRecord) -> None:
    """Save a report record to Table Storage."""
    table = _get_table(TABLE_NAME)
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


def _escape_odata(value: str) -> str:
    """Escape single quotes for OData filter strings."""
    return value.replace("'", "''")


def report_exists(report_type: str, report_id: str) -> bool:
    """Check whether a report has already been saved (deduplication)."""
    table = _get_table(TABLE_NAME)
    # report_id is unique but partition varies by week — use RowKey filter
    row_key = _escape_odata(f"{report_type}_{report_id}")
    entities = list(table.query_entities(f"RowKey eq '{row_key}'", select=["RowKey"]))
    return len(entities) > 0


def query_period(days: int = 7) -> list[ReportRecord]:
    """Query report records from the last *days* days."""
    cutoff = datetime.now(UTC) - timedelta(days=days)
    return _query_since(cutoff)


def query_period_range(start_days_ago: int, end_days_ago: int) -> list[ReportRecord]:
    """Query report records between *start_days_ago* and *end_days_ago* days ago."""
    now = datetime.now(UTC)
    start = now - timedelta(days=start_days_ago)
    end = now - timedelta(days=end_days_ago)
    table = _get_table(TABLE_NAME)
    start_str = start.strftime("%Y-%m-%dT%H:%M:%SZ")
    end_str = end.strftime("%Y-%m-%dT%H:%M:%SZ")
    entities = table.query_entities(f"received_at ge datetime'{start_str}' and received_at lt datetime'{end_str}'")
    return [_entity_to_record(e, start) for e in entities]


def _query_since(cutoff: datetime) -> list[ReportRecord]:
    """Internal: query all records since *cutoff*."""
    table = _get_table(TABLE_NAME)
    cutoff_str = cutoff.strftime("%Y-%m-%dT%H:%M:%SZ")
    entities = table.query_entities(f"received_at ge datetime'{cutoff_str}'")
    return [_entity_to_record(e, cutoff) for e in entities]


def _entity_to_record(e: dict, fallback_date: datetime) -> ReportRecord:
    """Convert a Table Storage entity to a ReportRecord."""
    received = e.get("received_at", fallback_date)
    if hasattr(received, "replace"):
        received = received.replace(tzinfo=UTC) if received.tzinfo is None else received
    return ReportRecord(
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


# ---------------------------------------------------------------------------
# Abuse report tracking
# ---------------------------------------------------------------------------


def abuse_report_exists(source_ip: str) -> bool:
    """Check whether an abuse report was already sent for *source_ip* this week."""
    table = _get_table(ABUSE_TABLE_NAME)
    year_week = datetime.now(UTC).strftime("%Y-W%W")
    try:
        table.get_entity(year_week, source_ip, select=["RowKey"])
        return True
    except Exception:
        return False


def save_abuse_report(record: AbuseReportRecord) -> None:
    """Save an abuse report record to Table Storage."""
    table = _get_table(ABUSE_TABLE_NAME)
    year_week = record.sent_at.strftime("%Y-W%W")
    entity = {
        "PartitionKey": year_week,
        "RowKey": record.source_ip,
        "abuse_email": record.abuse_email,
        "domain": record.domain,
        "report_count": record.report_count,
        "sent_at": record.sent_at,
    }
    table.upsert_entity(entity)
    logger.debug("Saved abuse report: %s/%s", year_week, record.source_ip)


def count_abuse_reports(days: int = 7) -> int:
    """Count abuse reports sent in the last *days* days."""
    table = _get_table(ABUSE_TABLE_NAME)
    cutoff = datetime.now(UTC) - timedelta(days=days)
    cutoff_str = cutoff.strftime("%Y-%m-%dT%H:%M:%SZ")
    entities = table.query_entities(
        f"sent_at ge datetime'{cutoff_str}'",
        select=["RowKey"],
    )
    return sum(1 for _ in entities)
