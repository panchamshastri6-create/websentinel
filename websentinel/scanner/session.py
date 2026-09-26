"""
scanner/session.py
=====================
Category: Session Security

Passive only -- re-examines the same Set-Cookie data already read for
the Cookie Security category, this time focused specifically on
session-identifier cookies and what's observable about session
expiration. Never steals, replays, or forges a session.
"""

from scanner.models import CategoryResult, Finding, SEVERITY_LOW, SEVERITY_MEDIUM, SEVERITY_INFO
from scanner.scoring import CATEGORY_WEIGHTS
from scanner.cookies import _get_raw_cookie_headers, _classify

CATEGORY_NAME = "Session Security"


def run(response) -> CategoryResult:
    result = CategoryResult(category=CATEGORY_NAME, weight=CATEGORY_WEIGHTS[CATEGORY_NAME])
    raw_cookie_headers = _get_raw_cookie_headers(response)

    session_cookies = [
        raw for raw in raw_cookie_headers
        if _classify(raw.split("=", 1)[0].strip()) == "session"
    ]

    if not session_cookies:
        result.add(Finding(
            check_id="session_cookie_present",
            name="Session cookie identified",
            passed=True,
            severity=SEVERITY_INFO,
            description="No cookie with a session-like name was set on this "
                        "response. The site may use token-based auth (e.g. a "
                        "bearer token in JS storage) instead, which this passive "
                        "check cannot see.",
        ))
        return result

    for i, raw in enumerate(session_cookies, start=1):
        cookie_name = raw.split("=", 1)[0].strip()
        lowered = raw.lower()

        result.add(Finding(
            check_id=f"session_cookie_{i}_identified",
            name=f"Session cookie '{cookie_name}'",
            passed=True,
            severity=SEVERITY_INFO,
            description="Identified by name pattern as a likely session/auth cookie.",
            evidence=raw,
        ))

        has_expiry = "expires=" in lowered or "max-age=" in lowered
        if has_expiry:
            result.add(Finding(
                check_id=f"session_cookie_{i}_persistence",
                name=f"'{cookie_name}' persistence",
                passed=True,
                severity=SEVERITY_LOW,
                description="This cookie has an explicit expiration, making it a "
                            "persistent (not just session-lifetime) cookie. Confirm "
                            "the expiration window matches your intended session length.",
                manual_verification=True,
            ))
        else:
            result.add(Finding(
                check_id=f"session_cookie_{i}_persistence",
                name=f"'{cookie_name}' persistence",
                passed=True,
                severity=SEVERITY_LOW,
                description="No explicit expiration was set, so this cookie is a "
                            "browser-session cookie (cleared when the browser closes).",
            ))

        if "samesite=none" in lowered and "secure" not in lowered:
            result.add(Finding(
                check_id=f"session_cookie_{i}_samesite_none",
                name=f"'{cookie_name}' SameSite=None without Secure",
                passed=False,
                severity=SEVERITY_MEDIUM,
                description="SameSite=None requires the Secure attribute; without "
                            "it, modern browsers will reject or mishandle the cookie, "
                            "and it also means this session cookie is sent on all "
                            "cross-site requests.",
                evidence=raw,
                recommendation="Add the Secure attribute whenever SameSite=None is used.",
            ))

    return result
