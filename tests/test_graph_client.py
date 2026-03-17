"""Tests for graph_client.py — MSAL auth and Graph API calls."""

from __future__ import annotations

from unittest.mock import MagicMock, PropertyMock, patch

import pytest

# ---------------------------------------------------------------------------
# Token acquisition
# ---------------------------------------------------------------------------


class TestContextManager:
    def test_context_manager(self, mock_graph):
        from graph_client import GraphClient

        mock_graph._session = MagicMock()
        GraphClient.close(mock_graph)
        mock_graph._session.close.assert_called_once()

    def test_enter_returns_self(self, mock_graph):
        from graph_client import GraphClient

        result = GraphClient.__enter__(mock_graph)
        assert result is mock_graph

    def test_exit_closes(self, mock_graph):
        from graph_client import GraphClient

        mock_graph._session = MagicMock()
        GraphClient.__exit__(mock_graph, None, None, None)
        mock_graph._session.close.assert_called_once()


class TestTokenAcquisition:
    def test_successful_token(self, mock_graph):
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

    def test_folder_cached_on_second_call(self, mock_graph):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"value": [{"id": "folder-123", "displayName": "Email Reports"}]}
        mock_resp.raise_for_status = MagicMock()
        mock_graph._session = MagicMock()
        mock_graph._session.get.return_value = mock_resp
        mock_graph._folder_cache = {}

        from graph_client import GraphClient

        # First call hits API
        result1 = GraphClient._get_folder_id(mock_graph, "mb@test.com", "Inbox")
        # Second call should use cache
        result2 = GraphClient._get_folder_id(mock_graph, "mb@test.com", "Inbox")
        assert result1 == result2 == "folder-123"
        assert mock_graph._session.get.call_count == 1  # only one API call

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
    def test_returns_attachments_with_inline_content(self, mock_graph):
        from graph_client import GraphClient

        mock_resp = MagicMock()
        mock_resp.json.return_value = {"value": [{"id": "att-1", "name": "report.xml", "contentBytes": "AQID"}]}
        mock_resp.raise_for_status = MagicMock()
        mock_graph._session = MagicMock()
        mock_graph._session.get.return_value = mock_resp
        type(mock_graph)._headers = PropertyMock(return_value={"Authorization": "Bearer fake"})

        result = GraphClient.get_attachments(mock_graph, "mb@test.com", "msg-1")
        assert len(result) == 1
        assert result[0]["contentBytes"] == "AQID"

    def test_fetches_content_when_not_inline(self, mock_graph):
        from graph_client import GraphClient

        list_resp = MagicMock()
        list_resp.json.return_value = {"value": [{"id": "att-1", "name": "report.xml"}]}
        list_resp.raise_for_status = MagicMock()

        content_resp = MagicMock()
        content_resp.content = b"<xml>data</xml>"
        content_resp.raise_for_status = MagicMock()

        mock_graph._session = MagicMock()
        mock_graph._session.get.side_effect = [list_resp, content_resp]
        type(mock_graph)._headers = PropertyMock(return_value={"Authorization": "Bearer fake"})

        result = GraphClient.get_attachments(mock_graph, "mb@test.com", "msg-1")
        assert len(result) == 1
        import base64

        assert base64.b64decode(result[0]["contentBytes"]) == b"<xml>data</xml>"

    def test_skips_item_attachments(self, mock_graph):
        from graph_client import GraphClient

        mock_resp = MagicMock()
        mock_resp.json.return_value = {
            "value": [
                {"id": "att-1", "name": "embedded.msg", "@odata.type": "#microsoft.graph.itemAttachment"},
                {"id": "att-2", "name": "report.xml", "contentBytes": "AQID"},
            ]
        }
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


class TestDeleteMessage:
    def test_sends_delete(self, mock_graph):
        from graph_client import GraphClient

        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_graph._session = MagicMock()
        mock_graph._session.delete.return_value = mock_resp
        type(mock_graph)._headers = PropertyMock(return_value={"Authorization": "Bearer fake"})

        GraphClient.delete_message(mock_graph, "mb@test.com", "msg-1")
        mock_graph._session.delete.assert_called_once()
        call_url = mock_graph._session.delete.call_args[0][0]
        assert "msg-1" in call_url


class TestMoveMessage:
    def test_moves_to_folder(self, mock_graph):
        from graph_client import GraphClient

        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_graph._session = MagicMock()
        mock_graph._session.post.return_value = mock_resp
        mock_graph._get_folder_id = MagicMock(return_value="folder-xyz")
        type(mock_graph)._headers = PropertyMock(return_value={"Authorization": "Bearer fake"})

        GraphClient.move_message(mock_graph, "mb@test.com", "msg-1", "Archive")
        mock_graph._session.post.assert_called_once()
        call_json = mock_graph._session.post.call_args[1]["json"]
        assert call_json == {"destinationId": "folder-xyz"}

    def test_skips_when_folder_not_found(self, mock_graph):
        from graph_client import GraphClient

        mock_graph._get_folder_id = MagicMock(return_value=None)
        mock_graph._session = MagicMock()

        GraphClient.move_message(mock_graph, "mb@test.com", "msg-1", "NonExistent")
        mock_graph._session.post.assert_not_called()


class TestListReadMessagesOlderThan:
    def test_returns_old_messages(self, mock_graph):
        from graph_client import GraphClient

        mock_resp = MagicMock()
        mock_resp.json.return_value = {"value": [{"id": "old-1"}]}
        mock_resp.raise_for_status = MagicMock()
        mock_graph._session = MagicMock()
        mock_graph._session.get.return_value = mock_resp
        mock_graph._get_folder_id = MagicMock(return_value=None)
        type(mock_graph)._headers = PropertyMock(return_value={"Authorization": "Bearer fake"})

        result = GraphClient.list_read_messages_older_than(mock_graph, "mb@test.com", 30)
        assert len(result) == 1
        call_params = mock_graph._session.get.call_args[1]["params"]
        assert "isRead eq true" in call_params["$filter"]
        assert "receivedDateTime lt" in call_params["$filter"]

    def test_with_folder_found(self, mock_graph):
        from graph_client import GraphClient

        mock_resp = MagicMock()
        mock_resp.json.return_value = {"value": []}
        mock_resp.raise_for_status = MagicMock()
        mock_graph._session = MagicMock()
        mock_graph._session.get.return_value = mock_resp
        mock_graph._get_folder_id = MagicMock(return_value="folder-abc")
        type(mock_graph)._headers = PropertyMock(return_value={"Authorization": "Bearer fake"})

        GraphClient.list_read_messages_older_than(mock_graph, "mb@test.com", 7, folder="Inbox")
        call_url = mock_graph._session.get.call_args[0][0]
        assert "mailFolders/folder-abc/messages" in call_url

    def test_with_folder_not_found(self, mock_graph):
        from graph_client import GraphClient

        mock_resp = MagicMock()
        mock_resp.json.return_value = {"value": []}
        mock_resp.raise_for_status = MagicMock()
        mock_graph._session = MagicMock()
        mock_graph._session.get.return_value = mock_resp
        mock_graph._get_folder_id = MagicMock(return_value=None)
        type(mock_graph)._headers = PropertyMock(return_value={"Authorization": "Bearer fake"})

        GraphClient.list_read_messages_older_than(mock_graph, "mb@test.com", 7, folder="Missing")
        call_url = mock_graph._session.get.call_args[0][0]
        assert "mailFolders" not in call_url


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
