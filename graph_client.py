"""Microsoft Graph client using MSAL client-credentials flow."""

from __future__ import annotations

import logging
import os
from typing import Any

import msal
import requests

logger = logging.getLogger(__name__)

GRAPH_BASE = "https://graph.microsoft.com/v1.0"
SCOPES = ["https://graph.microsoft.com/.default"]


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
        params = {"$filter": f"displayName eq '{folder_name}'", "$select": "id,displayName"}
        resp = self._session.get(url, headers=self._headers, params=params)
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
            params["$filter"] += f" and contains(subject, '{subject_filter}')"

        messages: list[dict[str, Any]] = []
        while url:
            resp = self._session.get(url, headers=self._headers, params=params)
            resp.raise_for_status()
            data = resp.json()
            messages.extend(data.get("value", []))
            url = data.get("@odata.nextLink")
            params = {}  # nextLink already contains query params
        return messages

    def get_attachments(self, mailbox: str, message_id: str) -> list[dict[str, Any]]:
        """Return all attachments for a given message."""
        url = f"{GRAPH_BASE}/users/{mailbox}/messages/{message_id}/attachments"
        resp = self._session.get(url, headers=self._headers, params={"$select": "id,name,contentType,contentBytes"})
        resp.raise_for_status()
        return resp.json().get("value", [])

    def mark_as_read(self, mailbox: str, message_id: str) -> None:
        url = f"{GRAPH_BASE}/users/{mailbox}/messages/{message_id}"
        resp = self._session.patch(url, headers=self._headers, json={"isRead": True})
        resp.raise_for_status()

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
        resp = self._session.post(url, headers=self._headers, json=payload)
        resp.raise_for_status()
        logger.info("Alert email sent to %s", to_address)
