"""Tests for rdap.py — RDAP abuse contact lookup."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import requests

import rdap

# ---------------------------------------------------------------------------
# Sample RDAP responses
# ---------------------------------------------------------------------------

_ARIN_RESPONSE = {
    "entities": [
        {
            "roles": ["registrant"],
            "vcardArray": ["vcard", [["fn", {}, "text", "IONOS Inc."]]],
        },
        {
            "roles": ["abuse"],
            "vcardArray": [
                "vcard",
                [
                    ["fn", {}, "text", "Abuse Contact"],
                    ["email", {}, "text", "abuse@ionos.com"],
                ],
            ],
        },
    ],
}

_NESTED_ABUSE_RESPONSE = {
    "entities": [
        {
            "roles": ["registrant"],
            "vcardArray": ["vcard", [["fn", {}, "text", "Parent Org"]]],
            "entities": [
                {
                    "roles": ["abuse"],
                    "vcardArray": [
                        "vcard",
                        [["email", {}, "text", "nested-abuse@example.com"]],
                    ],
                },
            ],
        },
    ],
}

_NO_ABUSE_RESPONSE = {
    "entities": [
        {
            "roles": ["registrant"],
            "vcardArray": ["vcard", [["fn", {}, "text", "Some Org"]]],
        },
    ],
}

_EMPTY_VCARD_RESPONSE = {
    "entities": [
        {
            "roles": ["abuse"],
            "vcardArray": ["vcard", [["fn", {}, "text", "Abuse Dept"]]],
        },
    ],
}

_NO_ENTITIES_RESPONSE: dict = {"entities": []}


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestLookupAbuseContact:
    """Tests for lookup_abuse_contact()."""

    @patch("rdap.requests.get")
    def test_returns_abuse_email(self, mock_get: MagicMock) -> None:
        mock_get.return_value = MagicMock(status_code=200)
        mock_get.return_value.json.return_value = _ARIN_RESPONSE
        assert rdap.lookup_abuse_contact("74.208.4.196") == "abuse@ionos.com"

    @patch("rdap.requests.get")
    def test_nested_abuse_entity(self, mock_get: MagicMock) -> None:
        mock_get.return_value = MagicMock(status_code=200)
        mock_get.return_value.json.return_value = _NESTED_ABUSE_RESPONSE
        assert rdap.lookup_abuse_contact("1.2.3.4") == "nested-abuse@example.com"

    @patch("rdap.requests.get")
    def test_no_abuse_role_returns_none(self, mock_get: MagicMock) -> None:
        mock_get.return_value = MagicMock(status_code=200)
        mock_get.return_value.json.return_value = _NO_ABUSE_RESPONSE
        assert rdap.lookup_abuse_contact("1.2.3.4") is None

    @patch("rdap.requests.get")
    def test_abuse_without_email_returns_none(self, mock_get: MagicMock) -> None:
        mock_get.return_value = MagicMock(status_code=200)
        mock_get.return_value.json.return_value = _EMPTY_VCARD_RESPONSE
        assert rdap.lookup_abuse_contact("1.2.3.4") is None

    @patch("rdap.requests.get")
    def test_empty_entities_returns_none(self, mock_get: MagicMock) -> None:
        mock_get.return_value = MagicMock(status_code=200)
        mock_get.return_value.json.return_value = _NO_ENTITIES_RESPONSE
        assert rdap.lookup_abuse_contact("1.2.3.4") is None

    @patch("rdap.requests.get")
    def test_network_error_returns_none(self, mock_get: MagicMock) -> None:
        mock_get.side_effect = requests.ConnectionError("timeout")
        assert rdap.lookup_abuse_contact("1.2.3.4") is None

    @patch("rdap.requests.get")
    def test_http_error_returns_none(self, mock_get: MagicMock) -> None:
        resp = MagicMock(status_code=404)
        resp.raise_for_status.side_effect = requests.HTTPError("not found")
        mock_get.return_value = resp
        assert rdap.lookup_abuse_contact("1.2.3.4") is None

    def test_private_ip_skipped(self) -> None:
        assert rdap.lookup_abuse_contact("192.168.1.1") is None
        assert rdap.lookup_abuse_contact("10.0.0.1") is None
        assert rdap.lookup_abuse_contact("172.16.0.1") is None

    def test_loopback_skipped(self) -> None:
        assert rdap.lookup_abuse_contact("127.0.0.1") is None

    def test_reserved_skipped(self) -> None:
        assert rdap.lookup_abuse_contact("240.0.0.1") is None

    def test_invalid_ip_returns_none(self) -> None:
        assert rdap.lookup_abuse_contact("not-an-ip") is None

    @patch("rdap.requests.get")
    def test_missing_vcard_array_returns_none(self, mock_get: MagicMock) -> None:
        mock_get.return_value = MagicMock(status_code=200)
        mock_get.return_value.json.return_value = {
            "entities": [{"roles": ["abuse"]}],
        }
        assert rdap.lookup_abuse_contact("1.2.3.4") is None

    @patch("rdap.requests.get")
    def test_short_vcard_array_returns_none(self, mock_get: MagicMock) -> None:
        mock_get.return_value = MagicMock(status_code=200)
        mock_get.return_value.json.return_value = {
            "entities": [{"roles": ["abuse"], "vcardArray": ["vcard"]}],
        }
        assert rdap.lookup_abuse_contact("1.2.3.4") is None

    @patch("rdap.requests.get")
    def test_uses_correct_url_and_headers(self, mock_get: MagicMock) -> None:
        mock_get.return_value = MagicMock(status_code=200)
        mock_get.return_value.json.return_value = _ARIN_RESPONSE
        rdap.lookup_abuse_contact("74.208.4.196")
        mock_get.assert_called_once_with(
            "https://rdap.arin.net/registry/ip/74.208.4.196",
            headers={"Accept": "application/rdap+json"},
            timeout=10,
        )


class TestExtractAbuseEmail:
    """Tests for _extract_abuse_email()."""

    def test_direct_abuse_entity(self) -> None:
        assert rdap._extract_abuse_email(_ARIN_RESPONSE) == "abuse@ionos.com"

    def test_nested_abuse_entity(self) -> None:
        assert rdap._extract_abuse_email(_NESTED_ABUSE_RESPONSE) == "nested-abuse@example.com"

    def test_no_abuse_returns_none(self) -> None:
        assert rdap._extract_abuse_email(_NO_ABUSE_RESPONSE) is None

    def test_empty_data(self) -> None:
        assert rdap._extract_abuse_email({}) is None


class TestEmailFromVcard:
    """Tests for _email_from_vcard()."""

    def test_extracts_email(self) -> None:
        entity = {
            "vcardArray": [
                "vcard",
                [["email", {}, "text", "test@example.com"]],
            ],
        }
        assert rdap._email_from_vcard(entity) == "test@example.com"

    def test_no_vcard_returns_none(self) -> None:
        assert rdap._email_from_vcard({}) is None

    def test_short_vcard_returns_none(self) -> None:
        assert rdap._email_from_vcard({"vcardArray": ["vcard"]}) is None

    def test_no_email_entry_returns_none(self) -> None:
        entity = {
            "vcardArray": [
                "vcard",
                [["fn", {}, "text", "Name Only"]],
            ],
        }
        assert rdap._email_from_vcard(entity) is None

    def test_short_entry_skipped(self) -> None:
        entity = {
            "vcardArray": [
                "vcard",
                [["email", {}]],
            ],
        }
        assert rdap._email_from_vcard(entity) is None
