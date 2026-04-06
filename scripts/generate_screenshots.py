"""Generate sample report screenshots for documentation.

Usage:
    python scripts/generate_screenshots.py

Requires: Pillow, Google Chrome
Output: docs/sample_dmarc.png, docs/sample_tlsrpt.png, docs/sample_weekly.png
"""

from __future__ import annotations

import subprocess
import sys
import tempfile
from datetime import UTC, datetime
from pathlib import Path

# Add project root to path so we can import application modules.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from PIL import Image

import alert
from models import (
    DmarcDisposition,
    DmarcRecord,
    DmarcReport,
    DmarcResult,
    ReportRecord,
    TlsFailureDetail,
    TlsPolicy,
    TlsRptReport,
)

DOCS_DIR = Path(__file__).resolve().parent.parent / "docs"
CHROME = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
VIEWPORT_WIDTH = 720
VIEWPORT_HEIGHT = 1200  # Render tall, then auto-trim
BG_COLOR = (17, 17, 17)  # #111111
PADDING = 16


def _render_html(html: str, out_path: Path) -> None:
    """Render HTML to a PNG via headless Chrome, then trim bottom whitespace."""
    with tempfile.NamedTemporaryFile(suffix=".html", mode="w", delete=False) as f:
        f.write(html)
        html_path = f.name

    with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as f:
        raw_path = f.name

    subprocess.run(
        [
            CHROME,
            "--headless",
            "--disable-gpu",
            f"--screenshot={raw_path}",
            f"--window-size={VIEWPORT_WIDTH},{VIEWPORT_HEIGHT}",
            html_path,
        ],
        capture_output=True,
    )

    # Trim empty rows from the bottom
    img = Image.open(raw_path).convert("RGB")
    w, h = img.size
    trim_y = h
    for y in range(h - 1, -1, -1):
        for x in range(w):
            r, g, b = img.getpixel((x, y))  # type: ignore[misc]
            if abs(r - BG_COLOR[0]) > 5 or abs(g - BG_COLOR[1]) > 5 or abs(b - BG_COLOR[2]) > 5:
                trim_y = min(y + 1 + PADDING, h)
                break
        if trim_y != h:
            break

    img.crop((0, 0, w, trim_y)).save(out_path)
    print(f"  {out_path.name}: {w}x{trim_y}")

    Path(html_path).unlink()
    Path(raw_path).unlink()


def _build_dmarc_html() -> str:
    records = [
        DmarcRecord(
            source_ip="209.85.220.41",
            count=150,
            disposition=DmarcDisposition.NONE,
            dkim_result=DmarcResult.PASS,
            spf_result=DmarcResult.PASS,
            header_from="example.com",
            dkim_domain="example.com",
        ),
        DmarcRecord(
            source_ip="185.99.99.1",
            count=3,
            disposition=DmarcDisposition.REJECT,
            dkim_result=DmarcResult.FAIL,
            spf_result=DmarcResult.FAIL,
            header_from="example.com",
            dkim_domain="spoofed.example.net",
        ),
        DmarcRecord(
            source_ip="74.125.209.11",
            count=42,
            disposition=DmarcDisposition.NONE,
            dkim_result=DmarcResult.PASS,
            spf_result=DmarcResult.PASS,
            header_from="example.com",
            dkim_domain="example.com",
        ),
    ]
    report = DmarcReport(
        org_name="google.com",
        report_id="test-12345",
        date_begin=datetime(2024, 3, 15, tzinfo=UTC),
        date_end=datetime(2024, 3, 16, tzinfo=UTC),
        domain="example.com",
        policy=DmarcDisposition.REJECT,
        records=records,
    )
    return alert.build_dmarc_alert(report).body_html


def _build_tlsrpt_html() -> str:
    fd = TlsFailureDetail(
        result_type="certificate-expired",
        sending_mta_ip="209.85.220.41",
        receiving_mx_hostname="mail.example.com",
        failed_session_count=2,
        failure_reason_code="Certificate has expired",
    )
    report = TlsRptReport(
        org_name="google.com",
        report_id="tls-67890",
        date_begin=datetime(2024, 3, 15, tzinfo=UTC),
        date_end=datetime(2024, 3, 16, tzinfo=UTC),
        policies=[
            TlsPolicy(
                policy_type="sts",
                policy_domain="example.com",
                successful_session_count=485,
                failed_session_count=2,
                failure_details=[fd],
            )
        ],
    )
    return alert.build_tlsrpt_alert(report).body_html


def _build_weekly_html() -> str:
    records = [
        ReportRecord(
            report_type="dmarc",
            report_id="d1",
            org_name="google.com",
            domain="example.com",
            total_messages=150,
            pass_count=147,
            fail_count=3,
            policy="reject",
            attachment_size_bytes=4000,
        ),
        ReportRecord(
            report_type="dmarc",
            report_id="d2",
            org_name="microsoft.com",
            domain="example.com",
            total_messages=42,
            pass_count=42,
            fail_count=0,
            policy="reject",
            attachment_size_bytes=3000,
        ),
        ReportRecord(
            report_type="tlsrpt",
            report_id="t1",
            org_name="google.com",
            domain="",
            total_messages=485,
            pass_count=483,
            fail_count=2,
            attachment_size_bytes=2000,
        ),
    ]
    return alert.build_weekly_summary(records, days=7, abuse_reports_sent=2).body_html


def main() -> None:
    print("Generating sample report screenshots...")

    _render_html(_build_dmarc_html(), DOCS_DIR / "sample_dmarc.png")
    _render_html(_build_tlsrpt_html(), DOCS_DIR / "sample_tlsrpt.png")
    _render_html(_build_weekly_html(), DOCS_DIR / "sample_weekly.png")

    print("Done.")


if __name__ == "__main__":
    main()
