"""RDAP abuse contact lookup for IP addresses."""

from __future__ import annotations

import ipaddress
import logging

import requests

logger = logging.getLogger(__name__)

_RDAP_URL = "https://rdap.arin.net/registry/ip/{ip}"
_TIMEOUT = 10


def lookup_abuse_contact(ip: str) -> str | None:
    """Return the abuse contact email for *ip*, or ``None`` if unavailable.

    Skips private/reserved IPs and returns ``None`` on any network or
    parsing error so that callers can treat this as best-effort.
    """
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        logger.warning("Invalid IP address: %s", ip)
        return None

    if addr.is_private or addr.is_reserved or addr.is_loopback:
        logger.debug("Skipping private/reserved IP: %s", ip)
        return None

    try:
        resp = requests.get(
            _RDAP_URL.format(ip=ip),
            headers={"Accept": "application/rdap+json"},
            timeout=_TIMEOUT,
        )
        resp.raise_for_status()
        return _extract_abuse_email(resp.json())
    except requests.RequestException:
        logger.warning("RDAP lookup failed for %s", ip, exc_info=True)
        return None


def _extract_abuse_email(data: dict) -> str | None:
    """Walk RDAP JSON to find the abuse contact email."""
    for entity in data.get("entities", []):
        roles = entity.get("roles", [])
        if "abuse" in roles:
            email = _email_from_vcard(entity)
            if email:
                return email
        # Check nested entities (some RIRs nest the abuse contact).
        for sub in entity.get("entities", []):
            if "abuse" in sub.get("roles", []):
                email = _email_from_vcard(sub)
                if email:
                    return email
    return None


def _email_from_vcard(entity: dict) -> str | None:
    """Extract an email address from a jCard (RFC 7095) vcardArray."""
    vcard = entity.get("vcardArray")
    if not vcard or len(vcard) < 2:
        return None
    for entry in vcard[1]:
        if len(entry) >= 4 and entry[0] == "email":
            return str(entry[3])
    return None
