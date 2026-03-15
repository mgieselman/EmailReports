"""Shared fixtures for all tests."""

from __future__ import annotations

import base64
import gzip
import io
import sys
import zipfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# Ensure project root is importable
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

FIXTURES = Path(__file__).resolve().parent / "fixtures"


# ---------------------------------------------------------------------------
# Environment
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _env_defaults(monkeypatch):
    """Set required env vars for all tests so imports don't blow up."""
    defaults = {
        "AZURE_TENANT_ID": "test-tenant-id",
        "AZURE_CLIENT_ID": "test-client-id",
        "AZURE_CLIENT_SECRET": "test-client-secret",
        "REPORT_MAILBOX": "emailreports@gieselman.com",
        "MAIL_FOLDER": "",
        "DMARC_ALIAS": "dmarc-reports@gieselman.com",
        "TLSRPT_ALIAS": "tls-reports@gieselman.com",
        "TEAMS_WEBHOOK_URL": "",
        "ALERT_EMAIL_ENABLED": "false",
        "ALERT_EMAIL_FROM": "emailreports@gieselman.com",
        "ALERT_EMAIL_TO": "matt@gieselman.com",
        "TIMER_SCHEDULE_CRON": "0 */30 * * * *",
    }
    for k, v in defaults.items():
        monkeypatch.setenv(k, v)


# ---------------------------------------------------------------------------
# Raw fixture loaders
# ---------------------------------------------------------------------------


@pytest.fixture
def dmarc_xml_bytes() -> bytes:
    return (FIXTURES / "sample_dmarc.xml").read_bytes()


@pytest.fixture
def dmarc_minimal_xml_bytes() -> bytes:
    return (FIXTURES / "sample_dmarc_minimal.xml").read_bytes()


@pytest.fixture
def dmarc_multi_auth_xml_bytes() -> bytes:
    return (FIXTURES / "sample_dmarc_multi_auth.xml").read_bytes()


@pytest.fixture
def tlsrpt_json_bytes() -> bytes:
    return (FIXTURES / "sample_tlsrpt.json").read_bytes()


@pytest.fixture
def tlsrpt_no_failures_json_bytes() -> bytes:
    return (FIXTURES / "sample_tlsrpt_no_failures.json").read_bytes()


@pytest.fixture
def tlsrpt_underscore_json_bytes() -> bytes:
    return (FIXTURES / "sample_tlsrpt_underscore_keys.json").read_bytes()


# ---------------------------------------------------------------------------
# Encoding helpers (simulate Graph attachment contentBytes)
# ---------------------------------------------------------------------------


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def _gzip_b64(data: bytes) -> str:
    return _b64(gzip.compress(data))


def _zip_b64(data: bytes, inner_name: str) -> str:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(inner_name, data)
    return _b64(buf.getvalue())


@pytest.fixture
def dmarc_b64_xml(dmarc_xml_bytes) -> str:
    return _b64(dmarc_xml_bytes)


@pytest.fixture
def dmarc_b64_gz(dmarc_xml_bytes) -> str:
    return _gzip_b64(dmarc_xml_bytes)


@pytest.fixture
def dmarc_b64_zip(dmarc_xml_bytes) -> str:
    return _zip_b64(dmarc_xml_bytes, "google.com!gieselman.com!1710460800!1710547200.xml")


@pytest.fixture
def tlsrpt_b64_json(tlsrpt_json_bytes) -> str:
    return _b64(tlsrpt_json_bytes)


@pytest.fixture
def tlsrpt_b64_gz(tlsrpt_json_bytes) -> str:
    return _gzip_b64(tlsrpt_json_bytes)


@pytest.fixture
def tlsrpt_b64_zip(tlsrpt_json_bytes) -> str:
    return _zip_b64(tlsrpt_json_bytes, "google.com!gieselman.com.json")


# ---------------------------------------------------------------------------
# Mock Graph client
# ---------------------------------------------------------------------------


@pytest.fixture
def mock_graph():
    """Return a MagicMock of GraphClient with all methods stubbed."""
    with patch("graph_client.msal") as mock_msal:
        mock_msal.ConfidentialClientApplication.return_value.acquire_token_for_client.return_value = {
            "access_token": "fake-token-12345"
        }
        from graph_client import GraphClient

        client = GraphClient()
    client.list_unread_messages = MagicMock(return_value=[])
    client.get_attachments = MagicMock(return_value=[])
    client.mark_as_read = MagicMock()
    client.send_mail = MagicMock()
    return client
