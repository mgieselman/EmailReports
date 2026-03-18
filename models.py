"""Dataclasses for DMARC, TLS-RPT, and alert models."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum

# ---------------------------------------------------------------------------
# DMARC
# ---------------------------------------------------------------------------


class DmarcDisposition(StrEnum):
    NONE = "none"
    QUARANTINE = "quarantine"
    REJECT = "reject"


class DmarcResult(StrEnum):
    PASS = "pass"
    FAIL = "fail"


@dataclass
class DmarcRecord:
    source_ip: str
    count: int
    disposition: DmarcDisposition
    dkim_result: DmarcResult
    spf_result: DmarcResult
    header_from: str
    envelope_from: str = ""
    dkim_domain: str = ""
    spf_domain: str = ""


@dataclass
class DmarcReport:
    org_name: str
    report_id: str
    date_begin: datetime
    date_end: datetime
    domain: str
    policy: DmarcDisposition
    records: list[DmarcRecord] = field(default_factory=list)

    @property
    def total_messages(self) -> int:
        return sum(r.count for r in self.records)

    @property
    def failing_records(self) -> list[DmarcRecord]:
        return [r for r in self.records if r.dkim_result == DmarcResult.FAIL and r.spf_result == DmarcResult.FAIL]


# ---------------------------------------------------------------------------
# TLS-RPT
# ---------------------------------------------------------------------------


@dataclass
class TlsFailureDetail:
    result_type: str
    sending_mta_ip: str = ""
    receiving_mx_hostname: str = ""
    failed_session_count: int = 0
    failure_reason_code: str = ""


@dataclass
class TlsPolicy:
    policy_type: str
    policy_domain: str
    successful_session_count: int = 0
    failed_session_count: int = 0
    failure_details: list[TlsFailureDetail] = field(default_factory=list)


@dataclass
class TlsRptReport:
    org_name: str
    report_id: str
    date_begin: datetime
    date_end: datetime
    policies: list[TlsPolicy] = field(default_factory=list)

    @property
    def total_failures(self) -> int:
        return sum(p.failed_session_count for p in self.policies)

    @property
    def total_successful(self) -> int:
        return sum(p.successful_session_count for p in self.policies)


# ---------------------------------------------------------------------------
# Alerting
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Report tracking (for weekly summaries)
# ---------------------------------------------------------------------------


@dataclass
class ReportRecord:
    report_type: str  # "dmarc" or "tlsrpt"
    report_id: str
    org_name: str
    domain: str
    total_messages: int = 0
    pass_count: int = 0
    fail_count: int = 0
    policy: str = ""
    attachment_size_bytes: int = 0
    received_at: datetime = field(default_factory=lambda: datetime.now(UTC))


# ---------------------------------------------------------------------------
# Alerting
# ---------------------------------------------------------------------------


class AlertSeverity(StrEnum):
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


@dataclass
class AlertSummary:
    title: str
    severity: AlertSeverity
    body_markdown: str
    body_html: str = ""
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))
