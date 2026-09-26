"""
scanner/http.py
================
URL validation, target-safety checks, and the shared `requests.Session`
used by every check module.

This module is the gatekeeper that prevents WebSentinel from being
pointed at things it shouldn't touch: localhost, private/internal IP
ranges, or arbitrary IP addresses/networks, unless the operator
explicitly opts in with --allow-private.
"""

import ipaddress
import socket
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urlparse

import requests

USER_AGENT = "WebSentinel/1.0 (+authorized-security-assessment)"

# Ports checked by the "Safe Service Exposure" category. Deliberately a
# short, well-known list -- this is NOT a general-purpose port scanner.
SAFE_EXPOSURE_PORTS = [80, 443, 22, 21, 25, 53, 3306, 5432, 6379, 8080, 8443]


class TargetValidationError(Exception):
    """Raised when a target fails validation and should not be scanned."""


@dataclass
class ResolvedTarget:
    original_input: str
    url: str
    hostname: str
    resolved_ips: list


def normalize_url(raw_url: str) -> str:
    """Ensure the URL has a scheme; default to https://."""
    if not raw_url.startswith(("http://", "https://")):
        raw_url = "https://" + raw_url
    return raw_url


def _is_private_or_reserved(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return True  # unparsable -> treat as unsafe, fail closed
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
    )


def validate_target(raw_url: str, allow_private: bool = False) -> ResolvedTarget:
    """
    Validate and resolve a target URL. Raises TargetValidationError if the
    target is unsafe to scan (localhost, private IP ranges, a bare IP
    network, etc.) unless allow_private=True.
    """
    url = normalize_url(raw_url.strip())
    parsed = urlparse(url)

    if parsed.scheme not in ("http", "https"):
        raise TargetValidationError(f"Unsupported URL scheme: {parsed.scheme!r}")

    hostname = parsed.hostname
    if not hostname:
        raise TargetValidationError(f"Could not parse a hostname from {raw_url!r}")

    # Reject obvious localhost aliases up front, before even attempting DNS.
    localhost_aliases = {"localhost", "127.0.0.1", "::1", "0.0.0.0"}
    if hostname.lower() in localhost_aliases and not allow_private:
        raise TargetValidationError(
            f"Refusing to scan {hostname!r}: this looks like localhost. "
            f"Pass --allow-private if this is an intentional, authorized "
            f"local target."
        )

    # Resolve the hostname so we can check the *actual* IP(s), not just the
    # name -- this catches DNS entries that point at private/internal space.
    try:
        addr_info = socket.getaddrinfo(hostname, None)
    except socket.gaierror as exc:
        raise TargetValidationError(f"Could not resolve hostname {hostname!r}: {exc}")

    resolved_ips = sorted({info[4][0] for info in addr_info})

    if not allow_private:
        for ip_str in resolved_ips:
            if _is_private_or_reserved(ip_str):
                raise TargetValidationError(
                    f"Refusing to scan {hostname!r}: it resolves to {ip_str}, "
                    f"which is a private/reserved/loopback address. Pass "
                    f"--allow-private if this is an intentional, authorized "
                    f"internal target."
                )

    return ResolvedTarget(
        original_input=raw_url,
        url=url,
        hostname=hostname,
        resolved_ips=resolved_ips,
    )


def build_session() -> requests.Session:
    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT})
    return session


def safe_get(session: requests.Session, url: str, timeout: float = 8.0, **kwargs) -> Optional[requests.Response]:
    """
    A GET wrapper that swallows connection-level errors and returns None
    instead of raising, for use in checks that probe several optional
    paths and shouldn't abort the whole scan if one path errors out.
    """
    try:
        return session.get(url, timeout=timeout, **kwargs)
    except requests.exceptions.RequestException:
        return None
