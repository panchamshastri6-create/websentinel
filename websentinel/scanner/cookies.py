"""
scanner/cookies.py
====================
Category: Cookie Security

Passive only -- reads Set-Cookie headers from a normal response.

Per the spec, this module tries to separate likely *session* cookies
(higher-stakes; missing attributes matter more) from analytics/tracking
cookies (lower stakes), and explains context rather than flatly calling
every missing attribute a vulnerability.
"""

from scanner.models import CategoryResult, Finding, SEVERITY_LOW, SEVERITY_MEDIUM
from scanner.scoring import CATEGORY_WEIGHTS

CATEGORY_NAME = "Cookie Security"

_SESSION_NAME_HINTS = (
    "sess", "session", "sid", "auth", "token", "jwt", "csrftoken",
    "phpsessid", "asp.net_sessionid", "connect.sid",
)
_TRACKING_NAME_HINTS = (
    "_ga", "_gid", "_gat", "_fbp", "_fbc", "analytics", "utm_", "ajs_",
)


def _get_raw_cookie_headers(response):
    raw = None
    if hasattr(response, "raw") and hasattr(response.raw, "headers"):
        get_all = getattr(response.raw.headers, "get_all", None)
        if get_all:
            raw = get_all("Set-Cookie")
    if not raw:
        single = response.headers.get("Set-Cookie")
        raw = [single] if single else []
    return raw


def _classify(cookie_name: str) -> str:
    lowered = cookie_name.lower()
    if any(hint in lowered for hint in _SESSION_NAME_HINTS):
        return "session"
    if any(hint in lowered for hint in _TRACKING_NAME_HINTS):
        return "tracking"
    return "other"


def run(response) -> CategoryResult:
    result = CategoryResult(category=CATEGORY_NAME, weight=CATEGORY_WEIGHTS[CATEGORY_NAME])
    raw_cookie_headers = _get_raw_cookie_headers(response)

    if not raw_cookie_headers:
        result.add(Finding(
            check_id="cookies_present",
            name="Cookies set",
            passed=True,
            severity=SEVERITY_LOW,
            description="No cookies were set on the initial response.",
        ))
        return result

    for i, raw in enumerate(raw_cookie_headers, start=1):
        lowered = raw.lower()
        cookie_name = raw.split("=", 1)[0].strip()
        classification = _classify(cookie_name)

        has_secure = "secure" in lowered
        has_httponly = "httponly" in lowered
        has_samesite = "samesite" in lowered
        has_prefix = cookie_name.startswith("__Secure-") or cookie_name.startswith("__Host-")

        # Session-like cookies: missing attributes are treated seriously.
        # Tracking/other cookies: missing Secure/SameSite is noted but at
        # lower severity, and missing HttpOnly on a non-session cookie is
        # not flagged at all (many analytics cookies are read by JS by design).
        if classification == "session":
            missing = []
            if not has_secure:
                missing.append("Secure")
            if not has_httponly:
                missing.append("HttpOnly")
            if not has_samesite:
                missing.append("SameSite")
            if missing:
                result.add(Finding(
                    check_id=f"cookie_{i}_session_attrs",
                    name=f"Session-like cookie '{cookie_name}'",
                    passed=False,
                    severity=SEVERITY_MEDIUM,
                    description=f"'{cookie_name}' looks like a session/auth cookie "
                                f"(by name) and is missing: {', '.join(missing)}.",
                    evidence=raw,
                    recommendation="Session cookies should set Secure, HttpOnly, "
                                   "and an explicit SameSite value (Lax or Strict).",
                ))
            else:
                result.add(Finding(
                    check_id=f"cookie_{i}_session_attrs",
                    name=f"Session-like cookie '{cookie_name}'",
                    passed=True,
                    severity=SEVERITY_MEDIUM,
                    description=f"'{cookie_name}' sets Secure, HttpOnly, and SameSite.",
                    evidence=raw,
                ))
        else:
            missing = []
            if not has_secure:
                missing.append("Secure")
            if not has_samesite:
                missing.append("SameSite")
            if missing:
                result.add(Finding(
                    check_id=f"cookie_{i}_attrs",
                    name=f"Cookie '{cookie_name}' ({classification})",
                    passed=False,
                    severity=SEVERITY_LOW,
                    description=f"'{cookie_name}' (classified as {classification}) "
                                f"is missing: {', '.join(missing)}. This is lower-"
                                f"priority than a missing attribute on a session "
                                f"cookie, but still worth tightening.",
                    evidence=raw,
                    recommendation="Set Secure and an explicit SameSite value on all cookies where possible.",
                ))
            else:
                result.add(Finding(
                    check_id=f"cookie_{i}_attrs",
                    name=f"Cookie '{cookie_name}' ({classification})",
                    passed=True,
                    severity=SEVERITY_LOW,
                    description=f"'{cookie_name}' sets Secure and SameSite.",
                    evidence=raw,
                ))

        if has_prefix:
            result.add(Finding(
                check_id=f"cookie_{i}_prefix",
                name=f"Cookie '{cookie_name}' name prefix",
                passed=True,
                severity=SEVERITY_LOW,
                description=f"Uses a __Secure-/__Host- prefix, which lets the "
                            f"browser itself enforce some of these attributes.",
                evidence=cookie_name,
            ))

    return result
