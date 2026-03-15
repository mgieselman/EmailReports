"""Tests for graph_client.py — MSAL auth and Graph API calls."""

from __future__ import annotations

from unittest.mock import MagicMock, PropertyMock, patch

import pytest

# ---------------------------------------------------------------------------
# Token acquisition
# ---------------------------------------------------------------------------


class TestTokenAcquisition:
    def test_successful_token(self, mock_graph):
        # mock_graph was already constructed; verify it didn't blow up
        assert mock_graph is not None

    def test_failed_token_raises(self, monkeypatch):
        with patch("graph_client.msal") as mock_msal:
            mock_msal.ConfidentialClientApplication.return_value.acquire_token_for_client.return_value = {
                "error": "invalid_client",
                "error_description": "Bad credentials",
            }
            from graph_client import GraphClient

            client = GraphClient()
            with pytest.raises(RuntimeError, match="Bad credentials"):
                client._get_token()

    def test_failed_token_no_description(self, monkeypatch):
        with patch("graph_client.msal") as mock_msal:
            mock_msal.ConfidentialClientApplication.return_value.acquire_token_for_client.return_value = {
                "error": "unknown"
            }
            from graph_client import GraphClient

            client = GraphClient()
            with pytest.raises(RuntimeError):
                client._get_token()


# ---------------------------------------------------------------------------
# _get_folder_id
# ---------------------------------------------------------------------------


class TestGetFolderId:
    def test_folder_found(self, mock_graph):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"value": [{"id": "folder-123", "displayName": "Email Reports"}]}
        mock_resp.raise_for_status = MagicMock()
        mock_graph._session = MagicMock()
        mock_graph._session.get.return_value = mock_resp

        # Call the real method
        from graph_client import GraphClient

        result = GraphClient._get_folder_id(mock_graph, "emailreports@gieselman.com", "Email Reports")
        assert result == "folder-123"

    def test_folder_not_found(self, mock_graph):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"value": []}
        mock_resp.raise_for_status = MagicMock()
        mock_graph._session = MagicMock()
        mock_graph._session.get.return_value = mock_resp

        from graph_client import GraphClient

        result = GraphClient._get_folder_id(mock_graph, "emailreports@gieselman.com", "NonExistent")
        assert result is None


# ---------------------------------------------------------------------------
# list_unread_messages
# ---------------------------------------------------------------------------


class TestListUnreadMessages:
    def _setup_client(self, mock_graph, responses):
        """Set up mock_graph with sequential GET responses."""
        mock_graph._session = MagicMock()
        mock_resps = []
        for resp_data in responses:
            mock_resp = MagicMock()
            mock_resp.json.return_value = resp_data
            mock_resp.raise_for_status = MagicMock()
            mock_resps.append(mock_resp)
        mock_graph._session.get.side_effect = mock_resps
        mock_graph._get_folder_id = MagicMock(return_value=None)
        # Provide a real _headers property
        type(mock_graph)._headers = PropertyMock(return_value={"Authorization": "Bearer fake"})
        return mock_graph

    def test_no_messages(self, mock_graph):
        from graph_client import GraphClient

        client = self._setup_client(mock_graph, [{"value": []}])
        result = GraphClient.list_unread_messages(client, "mb@test.com")
        assert result == []

    def test_single_page(self, mock_graph):
        from graph_client import GraphClient

        msgs = [{"id": "1", "subject": "Test"}]
        client = self._setup_client(mock_graph, [{"value": msgs}])
        result = GraphClient.list_unread_messages(client, "mb@test.com")
        assert len(result) == 1
        assert result[0]["id"] == "1"

    def test_pagination(self, mock_graph):
        from graph_client import GraphClient

        page1 = {"value": [{"id": "1"}], "@odata.nextLink": "https://graph.microsoft.com/next"}
        page2 = {"value": [{"id": "2"}]}
        client = self._setup_client(mock_graph, [page1, page2])
        result = GraphClient.list_unread_messages(client, "mb@test.com")
        assert len(result) == 2

    def test_folder_specified_and_found(self, mock_graph):
        from graph_client import GraphClient

        mock_graph._session = MagicMock()
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"value": []}
        mock_resp.raise_for_status = MagicMock()
        mock_graph._session.get.return_value = mock_resp
        mock_graph._get_folder_id = MagicMock(return_value="folder-abc")
        type(mock_graph)._headers = PropertyMock(return_value={"Authorization": "Bearer fake"})

        GraphClient.list_unread_messages(mock_graph, "mb@test.com", folder="Inbox")

        call_url = mock_graph._session.get.call_args[0][0]
        assert "mailFolders/folder-abc/messages" in call_url

    def test_subject_filter_appended(self, mock_graph):
        from graph_client import GraphClient

        mock_graph._session = MagicMock()
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"value": []}
        mock_resp.raise_for_status = MagicMock()
        mock_graph._session.get.return_value = mock_resp
        mock_graph._get_folder_id = MagicMock(return_value=None)
        type(mock_graph)._headers = PropertyMock(return_value={"Authorization": "Bearer fake"})

        GraphClient.list_unread_messages(mock_graph, "mb@test.com", subject_filter="DMARC")

        call_params = mock_graph._session.get.call_args[1]["params"]
        assert "contains(subject, 'DMARC')" in call_params["$filter"]

    def test_folder_specified_not_found_falls_back(self, mock_graph):
        from graph_client import GraphClient

        mock_graph._session = MagicMock()
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"value": []}
        mock_resp.raise_for_status = MagicMock()
        mock_graph._session.get.return_value = mock_resp
        mock_graph._get_folder_id = MagicMock(return_value=None)
        type(mock_graph)._headers = PropertyMock(return_value={"Authorization": "Bearer fake"})

        GraphClient.list_unread_messages(mock_graph, "mb@test.com", folder="Missing")

        call_url = mock_graph._session.get.call_args[0][0]
        assert "mailFolders" not in call_url
        assert "/messages" in call_url


# ---------------------------------------------------------------------------
# get_attachments
# ---------------------------------------------------------------------------


class TestGetAttachments:
    def test_returns_attachments(self, mock_graph):
        from graph_client import GraphClient

        mock_resp = MagicMock()
        mock_resp.json.return_value = {"value": [{"id": "att-1", "name": "report.xml"}]}
        mock_resp.raise_for_status = MagicMock()
        mock_graph._session = MagicMock()
        mock_graph._session.get.return_value = mock_resp
        type(mock_graph)._headers = PropertyMock(return_value={"Authorization": "Bearer fake"})

        result = GraphClient.get_attachments(mock_graph, "mb@test.com", "msg-1")
        assert len(result) == 1
        assert result[0]["name"] == "report.xml"

    def test_no_attachments(self, mock_graph):
        from graph_client import GraphClient

        mock_resp = MagicMock()
        mock_resp.json.return_value = {"value": []}
        mock_resp.raise_for_status = MagicMock()
        mock_graph._session = MagicMock()
        mock_graph._session.get.return_value = mock_resp
        type(mock_graph)._headers = PropertyMock(return_value={"Authorization": "Bearer fake"})

        result = GraphClient.get_attachments(mock_graph, "mb@test.com", "msg-1")
        assert result == []


# ---------------------------------------------------------------------------
# mark_as_read
# ---------------------------------------------------------------------------


class TestMarkAsRead:
    def test_sends_patch(self, mock_graph):
        from graph_client import GraphClient

        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_graph._session = MagicMock()
        mock_graph._session.patch.return_value = mock_resp
        type(mock_graph)._headers = PropertyMock(return_value={"Authorization": "Bearer fake"})

        GraphClient.mark_as_read(mock_graph, "mb@test.com", "msg-1")
        mock_graph._session.patch.assert_called_once()
        call_json = mock_graph._session.patch.call_args[1]["json"]
        assert call_json == {"isRead": True}


# ---------------------------------------------------------------------------
# send_mail
# ---------------------------------------------------------------------------


class TestSendMail:
    def test_sends_post(self, mock_graph):
        from graph_client import GraphClient

        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_graph._session = MagicMock()
        mock_graph._session.post.return_value = mock_resp
        type(mock_graph)._headers = PropertyMock(return_value={"Authorization": "Bearer fake"})

        GraphClient.send_mail(mock_graph, "from@test.com", "to@test.com", "Subject", "<p>body</p>")
        mock_graph._session.post.assert_called_once()
        call_json = mock_graph._session.post.call_args[1]["json"]
        assert call_json["message"]["subject"] == "Subject"
        assert call_json["message"]["toRecipients"][0]["emailAddress"]["address"] == "to@test.com"
