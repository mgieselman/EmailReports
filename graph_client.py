"""Microsoft Graph client using MSAL client-credentials flow."""

from __future__ import annotations

import logging
import os
from typing import Any

import msal
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

logger = logging.getLogger(__name__)

GRAPH_BASE = "https://graph.microsoft.com/v1.0"
SCOPES = ["https://graph.microsoft.com/.default"]
REQUEST_TIMEOUT = 30


def _escape_odata(value: str) -> str:
    """Escape single quotes for OData filter strings."""
    return value.replace("'", "''")


class GraphClient:
    """Handles MSAL token acquisition and Graph API calls."""

    def __init__(self) -> None:
        self._tenant_id = os.environ["AZURE_TENANT_ID"]
        self._client_id = os.environ["AZURE_CLIENT_ID"]
        self._client_secret = os.environ["AZURE_CLIENT_SECRET"]
        self._app = msal.ConfidentialClientApplication(
            self._client_id,
            authority=f"https://login.microsoftonline.com/{self._tenant_id}",
            client_credential=self._client_secret,
        )
        self._session = requests.Session()
        retry = Retry(
            total=3, backoff_factor=1, status_forcelist=[429, 500, 502, 503, 504], respect_retry_after_header=True
        )
        self._session.mount("https://", HTTPAdapter(max_retries=retry))

    def close(self) -> None:
        self._session.close()

    def __enter__(self) -> GraphClient:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    # -- token ---------------------------------------------------------------

    def _get_token(self) -> str:
        result = self._app.acquire_token_for_client(scopes=SCOPES)
        if "access_token" not in result:
            raise RuntimeError(f"Token acquisition failed: {result.get('error_description', result)}")
        return result["access_token"]

    @property
    def _headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self._get_token()}"}

    # -- folders -------------------------------------------------------------

    def _get_folder_id(self, mailbox: str, folder_name: str) -> str | None:
        """Resolve a mail folder display name to its Graph ID.

        Searches top-level folders only. Returns None if not found.
        """
        url = f"{GRAPH_BASE}/users/{mailbox}/mailFolders"
        safe_name = _escape_odata(folder_name)
        params = {"$filter": f"displayName eq '{safe_name}'", "$select": "id,displayName"}
        resp = self._session.get(url, headers=self._headers, params=params, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        folders = resp.json().get("value", [])
        if folders:
            return folders[0]["id"]
        return None

    # -- messages ------------------------------------------------------------

    def list_unread_messages(
        self,
        mailbox: str,
        folder: str | None = None,
        subject_filter: str | None = None,
    ) -> list[dict[str, Any]]:
        """Return unread messages from *mailbox* (UPN or mail address).

        If *folder* is provided, searches that folder by display name;
        otherwise falls back to the full mailbox.
        """
        if folder:
            folder_id = self._get_folder_id(mailbox, folder)
            if folder_id:
                url = f"{GRAPH_BASE}/users/{mailbox}/mailFolders/{folder_id}/messages"
            else:
                logger.warning("Folder '%s' not found in %s — falling back to Inbox", folder, mailbox)
                url = f"{GRAPH_BASE}/users/{mailbox}/messages"
        else:
            url = f"{GRAPH_BASE}/users/{mailbox}/messages"
        params: dict[str, str] = {
            "$filter": "isRead eq false",
            "$top": "50",
            "$select": "id,subject,from,toRecipients,receivedDateTime,hasAttachments",
            "$orderby": "receivedDateTime desc",
        }
        if subject_filter:
            safe_filter = _escape_odata(subject_filter)
            params["$filter"] += f" and contains(subject, '{safe_filter}')"

        messages: list[dict[str, Any]] = []
        while url:
            resp = self._session.get(url, headers=self._headers, params=params, timeout=REQUEST_TIMEOUT)
            resp.raise_for_status()
            data = resp.json()
            messages.extend(data.get("value", []))
            url = data.get("@odata.nextLink")
            params = {}  # nextLink already contains query params
        return messages

    def get_attachments(self, mailbox: str, message_id: str) -> list[dict[str, Any]]:
        """Return all file attachments for a given message.

        Uses ``$expand`` to inline contentBytes for attachments under 3 MB.
        Falls back to fetching each attachment individually for larger items.
        """
        url = f"{GRAPH_BASE}/users/{mailbox}/messages/{message_id}/attachments"
        resp = self._session.get(url, headers=self._headers, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        attachments = resp.json().get("value", [])

        result: list[dict[str, Any]] = []
        for att in attachments:
            if att.get("@odata.type", "") == "#microsoft.graph.itemAttachment":
                continue  # skip non-file attachments (e.g., embedded messages)
            if "contentBytes" not in att:
                att_url = f"{url}/{att['id']}/$value"
                content_resp = self._session.get(att_url, headers=self._headers, timeout=REQUEST_TIMEOUT)
                content_resp.raise_for_status()
                import base64

                att["contentBytes"] = base64.b64encode(content_resp.content).decode()
            result.append(att)
        return result

    def mark_as_read(self, mailbox: str, message_id: str) -> None:
        url = f"{GRAPH_BASE}/users/{mailbox}/messages/{message_id}"
        resp = self._session.patch(url, headers=self._headers, json={"isRead": True}, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()

    def delete_message(self, mailbox: str, message_id: str) -> None:
        url = f"{GRAPH_BASE}/users/{mailbox}/messages/{message_id}"
        resp = self._session.delete(url, headers=self._headers, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()

    def move_message(self, mailbox: str, message_id: str, destination_folder: str) -> None:
        """Move a message to a folder by display name."""
        folder_id = self._get_folder_id(mailbox, destination_folder)
        if not folder_id:
            logger.warning("Folder '%s' not found — skipping move for message %s", destination_folder, message_id)
            return
        url = f"{GRAPH_BASE}/users/{mailbox}/messages/{message_id}/move"
        resp = self._session.post(
            url, headers=self._headers, json={"destinationId": folder_id}, timeout=REQUEST_TIMEOUT
        )
        resp.raise_for_status()

    def list_read_messages_older_than(
        self,
        mailbox: str,
        days: int,
        folder: str | None = None,
    ) -> list[dict[str, Any]]:
        """Return read messages older than *days* days."""
        from datetime import UTC, datetime, timedelta

        cutoff = (datetime.now(UTC) - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")
        if folder:
            folder_id = self._get_folder_id(mailbox, folder)
            if folder_id:
                url = f"{GRAPH_BASE}/users/{mailbox}/mailFolders/{folder_id}/messages"
            else:
                url = f"{GRAPH_BASE}/users/{mailbox}/messages"
        else:
            url = f"{GRAPH_BASE}/users/{mailbox}/messages"

        params: dict[str, str] = {
            "$filter": f"isRead eq true and receivedDateTime lt {cutoff}",
            "$top": "50",
            "$select": "id,subject,receivedDateTime",
            "$orderby": "receivedDateTime asc",
        }

        messages: list[dict[str, Any]] = []
        while url:
            resp = self._session.get(url, headers=self._headers, params=params, timeout=REQUEST_TIMEOUT)
            resp.raise_for_status()
            data = resp.json()
            messages.extend(data.get("value", []))
            url = data.get("@odata.nextLink")
            params = {}
        return messages

    # -- send mail -----------------------------------------------------------

    def send_mail(self, from_address: str, to_address: str, subject: str, html_body: str) -> None:
        """Send an email via Graph ``/sendMail``."""
        url = f"{GRAPH_BASE}/users/{from_address}/sendMail"
        payload = {
            "message": {
                "subject": subject,
                "body": {"contentType": "HTML", "content": html_body},
                "toRecipients": [{"emailAddress": {"address": to_address}}],
            },
            "saveToSentItems": "false",
        }
        resp = self._session.post(url, headers=self._headers, json=payload, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        logger.info("Alert email sent to %s", to_address)
