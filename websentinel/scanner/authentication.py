"""
scanner/authentication.py
============================
Category: Authentication Security Indicators

Passive only -- looks at the HTML already fetched for the main page
for a login-like <form>, and inspects only what's observable from a
normal page load. This module NEVER submits a form, guesses a
password, attempts to log in, or brute-forces anything.
"""

import re

from scanner.models import CategoryResult, Finding, SEVERITY_LOW, SEVERITY_MEDIUM, SEVERITY_HIGH, SEVERITY_INFO
from scanner.scoring import CATEGORY_WEIGHTS

CATEGORY_NAME = "Authentication Security Indicators"

_PASSWORD_INPUT_PATTERN = re.compile(
    r'<input[^>]*type=["\']password["\'][^>]*>', re.IGNORECASE
)
_AUTOCOMPLETE_OFF_PATTERN = re.compile(r'autocomplete=["\']off["\']', re.IGNORECASE)
_FORM_ACTION_PATTERN = re.compile(r'<form[^>]*action=["\']([^"\']*)["\']', re.IGNORECASE)


def run(response, https_ok: bool) -> CategoryResult:
    result = CategoryResult(category=CATEGORY_NAME, weight=CATEGORY_WEIGHTS[CATEGORY_NAME])

    body = response.text if hasattr(response, "text") else ""
    password_inputs = _PASSWORD_INPUT_PATTERN.findall(body)

    if not password_inputs:
        result.add(Finding(
            check_id="login_form_detected",
            name="Login form on this page",
            passed=True,
            severity=SEVERITY_INFO,
            description="No password input was found on the page that was fetched. "
                        "A login page may exist elsewhere on the site; this check "
                        "only looks at the page actually requested.",
        ))
        return result

    result.add(Finding(
        check_id="login_form_detected",
        name="Login form on this page",
        passed=True,
        severity=SEVERITY_INFO,
        description=f"Found {len(password_inputs)} password input field(s) on this page.",
    ))

    result.add(Finding(
        check_id="login_form_https",
        name="Login form served over HTTPS",
        passed=https_ok,
        severity=SEVERITY_HIGH if not https_ok else SEVERITY_MEDIUM,
        description="The page containing the login form was served over HTTPS."
                    if https_ok else
                    "The page containing the login form was NOT served over HTTPS. "
                    "Submitting credentials over plain HTTP exposes them in transit.",
        recommendation="" if https_ok else "Serve all authentication pages exclusively over HTTPS.",
    ))

    autocomplete_off_count = sum(
        1 for field in password_inputs if _AUTOCOMPLETE_OFF_PATTERN.search(field)
    )
    if autocomplete_off_count:
        result.add(Finding(
            check_id="login_form_autocomplete",
            name="Password field autocomplete",
            passed=True,
            severity=SEVERITY_LOW,
            description=f"{autocomplete_off_count} password field(s) disable "
                        f"autocomplete. Modern guidance (NIST/OWASP) actually "
                        f"recommends allowing password managers to autofill, so "
                        f"this is noted for context rather than scored as a "
                        f"straightforward pass.",
        ))
    else:
        result.add(Finding(
            check_id="login_form_autocomplete",
            name="Password field autocomplete",
            passed=True,
            severity=SEVERITY_INFO,
            description="Password field(s) allow normal autocomplete behavior, "
                        "which is compatible with password managers.",
        ))

    # Rate limiting cannot be observed from a single page load.
    result.add(Finding(
        check_id="login_rate_limit",
        name="Login rate limiting",
        passed=True,
        severity=SEVERITY_INFO,
        description="Whether login attempts are rate-limited cannot be determined "
                    "from a single passive page load.",
        manual_verification=True,
        recommendation="Authentication requires manual security testing to confirm "
                       "rate limiting, account lockout, and brute-force protections.",
    ))

    return result
