"""Parse DMARC RUA aggregate XML reports from .xml, .gz, and .zip attachments."""

from __future__ import annotations

import gzip
import io
import logging
import zipfile
from base64 import b64decode
from datetime import UTC, datetime

import defusedxml.ElementTree as ET

from models import DmarcDisposition, DmarcRecord, DmarcReport, DmarcResult

logger = logging.getLogger(__name__)


def parse_attachment(name: str, content_bytes_b64: str) -> DmarcReport | None:
    """Decode a Graph attachment and return a DmarcReport, or None on failure."""
    raw = b64decode(content_bytes_b64)
    xml_bytes = _extract_xml(name, raw)
    if xml_bytes is None:
        return None
    return _parse_xml(xml_bytes)


def _extract_xml(filename: str, raw: bytes) -> bytes | None:
    lower = filename.lower()
    if lower.endswith(".xml"):
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
                xml_names = [n for n in zf.namelist() if n.lower().endswith(".xml")]
                if not xml_names:
                    logger.warning("No XML found inside zip %s", filename)
                    return None
                return zf.read(xml_names[0])
        except Exception:
            logger.warning("Failed to unzip %s", filename)
            return None
    logger.debug("Skipping non-DMARC attachment %s", filename)
    return None


def _parse_xml(data: bytes) -> DmarcReport:
    root = ET.fromstring(data)

    # -- report metadata
    meta = root.find("report_metadata")
    org_name = _text(meta, "org_name")
    report_id = _text(meta, "report_id")
    dr = meta.find("date_range") if meta is not None else None
    date_begin = datetime.fromtimestamp(int(_text(dr, "begin", "0")), tz=UTC)
    date_end = datetime.fromtimestamp(int(_text(dr, "end", "0")), tz=UTC)

    # -- policy published
    pp = root.find("policy_published")
    domain = _text(pp, "domain")
    policy = DmarcDisposition(_text(pp, "p", "none"))

    # -- records
    records: list[DmarcRecord] = []
    for rec_el in root.findall("record"):
        row = rec_el.find("row")
        if row is None:
            continue
        source_ip = _text(row, "source_ip")
        count = int(_text(row, "count", "0"))
        policy_eval = row.find("policy_evaluated")
        disposition = DmarcDisposition(_text(policy_eval, "disposition", "none"))
        dkim_result = DmarcResult(_text(policy_eval, "dkim", "fail"))
        spf_result = DmarcResult(_text(policy_eval, "spf", "fail"))

        identifiers = rec_el.find("identifiers")
        header_from = _text(identifiers, "header_from")
        envelope_from = _text(identifiers, "envelope_from")

        auth = rec_el.find("auth_results")
        dkim_domain = ""
        spf_domain = ""
        if auth is not None:
            dkim_el = auth.find("dkim")
            if dkim_el is not None:
                dkim_domain = _text(dkim_el, "domain")
            spf_el = auth.find("spf")
            if spf_el is not None:
                spf_domain = _text(spf_el, "domain")

        records.append(
            DmarcRecord(
                source_ip=source_ip,
                count=count,
                disposition=disposition,
                dkim_result=dkim_result,
                spf_result=spf_result,
                header_from=header_from,
                envelope_from=envelope_from,
                dkim_domain=dkim_domain,
                spf_domain=spf_domain,
            )
        )

    return DmarcReport(
        org_name=org_name,
        report_id=report_id,
        date_begin=date_begin,
        date_end=date_end,
        domain=domain,
        policy=policy,
        records=records,
    )


def _text(parent, tag: str, default: str = "") -> str:
    if parent is None:
        return default
    el = parent.find(tag)
    return el.text.strip() if el is not None and el.text else default
