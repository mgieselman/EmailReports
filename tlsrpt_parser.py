"""Parse TLS-RPT (RFC 8460) JSON reports from email attachments."""

from __future__ import annotations

import gzip
import io
import json
import logging
import zipfile
from base64 import b64decode
from datetime import UTC, datetime

from models import TlsFailureDetail, TlsPolicy, TlsRptReport

logger = logging.getLogger(__name__)


def parse_attachment(name: str, content_bytes_b64: str) -> TlsRptReport | None:
    """Decode a Graph attachment and return a TlsRptReport, or None."""
    raw = b64decode(content_bytes_b64)
    json_bytes = _extract_json(name, raw)
    if json_bytes is None:
        return None
    try:
        return _parse_json(json_bytes)
    except (json.JSONDecodeError, ValueError, KeyError):
        logger.debug("Failed to parse JSON from %s", name)
        return None


def _extract_json(filename: str, raw: bytes) -> bytes | None:
    lower = filename.lower()
    if lower.endswith(".json"):
        return raw
    if lower.endswith(".gz"):
        try:
            return gzip.decompress(raw)
        except Exception:
            logger.warning("Failed to gunzip %s", filename)
            return None
    if lower.endswith(".zip"):
        try:
            with zipfile.ZipFile(io.BytesIO(raw)) as zf:
                json_names = [n for n in zf.namelist() if n.lower().endswith(".json")]
                if not json_names:
                    logger.warning("No JSON found inside zip %s", filename)
                    return None
                return zf.read(json_names[0])
        except Exception:
            logger.warning("Failed to unzip %s", filename)
            return None
    logger.debug("Skipping non-TLS-RPT attachment %s", filename)
    return None


def _parse_json(data: bytes) -> TlsRptReport:
    doc = json.loads(data)

    org_name = doc.get("organization-name", doc.get("org_name", ""))
    report_id = str(doc.get("report-id", doc.get("report_id", "")))

    dr = doc.get("date-range", doc.get("date_range", {}))
    date_begin = _parse_ts(dr.get("start-datetime", dr.get("start_datetime", "")))
    date_end = _parse_ts(dr.get("end-datetime", dr.get("end_datetime", "")))

    policies: list[TlsPolicy] = []
    for pol in doc.get("policies", []):
        summary = pol.get("summary", {})
        failure_details: list[TlsFailureDetail] = []
        for fd in pol.get("failure-details", pol.get("failure_details", [])):
            failure_details.append(
                TlsFailureDetail(
                    result_type=fd.get("result-type", fd.get("result_type", "")),
                    sending_mta_ip=fd.get("sending-mta-ip", fd.get("sending_mta_ip", "")),
                    receiving_mx_hostname=fd.get("receiving-mx-hostname", fd.get("receiving_mx_hostname", "")),
                    failed_session_count=fd.get("failed-session-count", fd.get("failed_session_count", 0)),
                    failure_reason_code=fd.get("failure-reason-code", fd.get("failure_reason_code", "")),
                )
            )

        policy_el = pol.get("policy", {})
        policies.append(
            TlsPolicy(
                policy_type=policy_el.get("policy-type", policy_el.get("policy_type", "")),
                policy_domain=policy_el.get("policy-domain", policy_el.get("policy_domain", [None])),
                successful_session_count=summary.get(
                    "total-successful-session-count", summary.get("total_successful_session_count", 0)
                ),
                failed_session_count=summary.get(
                    "total-failure-session-count", summary.get("total_failure_session_count", 0)
                ),
                failure_details=failure_details,
            )
        )

    return TlsRptReport(
        org_name=org_name,
        report_id=report_id,
        date_begin=date_begin,
        date_end=date_end,
        policies=policies,
    )


def _parse_ts(value: str) -> datetime:
    if not value:
        return datetime.fromtimestamp(0, tz=UTC)
    for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%d"):
        try:
            return datetime.strptime(value, fmt).replace(tzinfo=UTC)
        except ValueError:
            continue
    return datetime.fromtimestamp(0, tz=UTC)
