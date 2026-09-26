"""
scanner/redirects.py
=======================
Category: Redirect Security

Passive only -- follows normal redirects (as a browser would) and
inspects the chain. Never attempts to exploit an open redirect.
"""

from urllib.parse import urlparse

from scanner.models import CategoryResult, Finding, SEVERITY_MEDIUM, SEVERITY_LOW
from scanner.scoring import CATEGORY_WEIGHTS
from scanner.http import safe_get

CATEGORY_NAME = "Redirect Security"

_MAX_REASONABLE_HOPS = 4


def run(session, hostname: str, timeout: float = 8.0) -> CategoryResult:
    result = CategoryResult(category=CATEGORY_NAME, weight=CATEGORY_WEIGHTS[CATEGORY_NAME])

    http_url = f"http://{hostname}/"
    resp = safe_get(session, http_url, timeout=timeout, allow_redirects=True)

    if resp is None:
        result.add(Finding(
            check_id="https_redirect",
            name="HTTP to HTTPS redirect",
            passed=True,
            severity=SEVERITY_MEDIUM,
            description=f"Could not connect over plain HTTP to {http_url} "
                        f"(port 80 may simply be closed, which is not a problem by itself).",
        ))
        return result

    history = resp.history
    final_scheme = urlparse(resp.url).scheme
    final_host = urlparse(resp.url).hostname

    if final_scheme == "https":
        result.add(Finding(
            check_id="https_redirect",
            name="HTTP to HTTPS redirect",
            passed=True,
            severity=SEVERITY_MEDIUM,
            description=f"Plain HTTP request redirected to HTTPS (final URL: {resp.url}).",
        ))
    else:
        result.add(Finding(
            check_id="https_redirect",
            name="HTTP to HTTPS redirect",
            passed=False,
            severity=SEVERITY_MEDIUM,
            description=f"A plain HTTP request did NOT redirect to HTTPS "
                        f"(final URL: {resp.url}). Visitors who omit 'https://' "
                        f"may send traffic unencrypted.",
            recommendation="Configure a permanent (301/308) redirect from HTTP to HTTPS for all paths.",
        ))

    hop_count = len(history)
    if hop_count > _MAX_REASONABLE_HOPS:
        result.add(Finding(
            check_id="redirect_chain_length",
            name="Redirect chain length",
            passed=False,
            severity=SEVERITY_LOW,
            description=f"{hop_count} redirects were followed before reaching a "
                        f"final response, which is more than typically expected.",
            recommendation="Simplify the redirect chain; long chains add latency "
                           "and can indicate configuration drift.",
        ))
    else:
        result.add(Finding(
            check_id="redirect_chain_length",
            name="Redirect chain length",
            passed=True,
            severity=SEVERITY_LOW,
            description=f"{hop_count} redirect(s) followed, which is a reasonable chain length.",
        ))

    # Cross-domain hop check: did the chain ever leave the original registrable host?
    crossed_domain = False
    for h in history:
        hop_host = urlparse(h.url).hostname
        if hop_host and hop_host != hostname and final_host and hop_host != final_host:
            crossed_domain = True
    if crossed_domain:
        result.add(Finding(
            check_id="redirect_cross_domain",
            name="Cross-domain redirect hop",
            passed=False,
            severity=SEVERITY_LOW,
            description="The redirect chain passed through a different domain "
                        "before reaching the final destination.",
            manual_verification=True,
            recommendation="Review the redirect chain manually to confirm every "
                           "hop is intentional and controlled by you.",
        ))
    else:
        result.add(Finding(
            check_id="redirect_cross_domain",
            name="Cross-domain redirect hop",
            passed=True,
            severity=SEVERITY_LOW,
            description="No unexpected cross-domain hops observed in the redirect chain.",
        ))

    return result
