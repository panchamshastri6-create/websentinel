"""
scanner/information.py
=========================
Covers three related weighted categories, since they all boil down to
"make a normal GET request to a public path and look at the response":

  - Information Disclosure  (weight 8)
  - Exposed Files            (weight 3)
  - security.txt             (weight 1)

Passive only. Every URL requested here is a normal, publicly routable
path -- the same kind any browser could request. We only check status
codes (and, for text-like responses, a very small amount of content),
we never download large files, and we never read/store/exfiltrate any
actual secret content even if a file appears exposed.

robots.txt / sitemap.xml (spec category 17) are folded into
Information Disclosure as informational findings: their presence is
reported for security *review*, never treated as a vulnerability by
itself, per the spec.
"""

from scanner.models import CategoryResult, Finding, SEVERITY_LOW, SEVERITY_MEDIUM, SEVERITY_HIGH, SEVERITY_INFO
from scanner.scoring import CATEGORY_WEIGHTS
from scanner.http import safe_get

# path -> (severity if exposed, human description). Deliberately a short,
# conservative list -- never dynamically expanded from crawling.
_SENSITIVE_PATHS = {
    "/.env": (SEVERITY_HIGH, "Often contains database credentials, API keys, or other secrets."),
    "/.git/config": (SEVERITY_HIGH, "Can let anyone reconstruct source history, including old secrets."),
    "/wp-config.php.bak": (SEVERITY_HIGH, "A backup file can expose database credentials in plain text."),
    "/config.json": (SEVERITY_MEDIUM, "May expose application configuration."),
    "/backup.zip": (SEVERITY_MEDIUM, "An accidentally public backup archive."),
    "/phpinfo.php": (SEVERITY_MEDIUM, "Reveals detailed PHP/server configuration."),
    "/server-status": (SEVERITY_LOW, "Apache mod_status can reveal internal IPs and current requests."),
}

_MAX_BYTES_TO_INSPECT = 2048  # never read more than this much of any candidate response body


def run_information_disclosure(response, session, base_url: str, timeout: float = 8.0) -> CategoryResult:
    result = CategoryResult(category="Information Disclosure", weight=CATEGORY_WEIGHTS["Information Disclosure"])
    headers = response.headers

    for header_name in ("Server", "X-Powered-By", "X-AspNet-Version"):
        if header_name in headers:
            result.add(Finding(
                check_id=f"info_header_{header_name.lower()}",
                name=f"{header_name} disclosure",
                passed=False,
                severity=SEVERITY_LOW,
                description=f"{header_name} header discloses implementation detail.",
                evidence=headers[header_name],
                recommendation=f"Suppress or generalize {header_name}.",
            ))

    body_sample = (response.text if hasattr(response, "text") else "")[:_MAX_BYTES_TO_INSPECT]
    debug_markers = ["Traceback (most recent call last)", "Warning: ", "Fatal error:", "DEBUG = True", "stack trace"]
    found_debug = [m for m in debug_markers if m.lower() in body_sample.lower()]
    if found_debug:
        result.add(Finding(
            check_id="info_debug_markers",
            name="Debug output indicator",
            passed=False,
            severity=SEVERITY_MEDIUM,
            description="The page contains text resembling debug/error output, "
                        "which can leak internal paths or logic.",
            manual_verification=True,
            recommendation="Disable debug mode and verbose error output in production.",
        ))
    else:
        result.add(Finding(
            check_id="info_debug_markers",
            name="Debug output indicator",
            passed=True,
            severity=SEVERITY_MEDIUM,
            description="No obvious debug/error output markers found on this page.",
        ))

    # robots.txt / sitemap.xml -- informational only, per spec.
    robots_resp = safe_get(session, base_url.rstrip("/") + "/robots.txt", timeout=timeout)
    if robots_resp is not None and robots_resp.status_code == 200 and robots_resp.text.strip():
        disallow_count = sum(1 for line in robots_resp.text.splitlines() if line.strip().lower().startswith("disallow"))
        result.add(Finding(
            check_id="info_robots_txt",
            name="robots.txt",
            passed=True,
            severity=SEVERITY_INFO,
            description=f"robots.txt is present with {disallow_count} Disallow rule(s). "
                        f"Informational for security review -- not a vulnerability.",
        ))

    sitemap_resp = safe_get(session, base_url.rstrip("/") + "/sitemap.xml", timeout=timeout)
    if sitemap_resp is not None and sitemap_resp.status_code == 200:
        result.add(Finding(
            check_id="info_sitemap_xml",
            name="sitemap.xml",
            passed=True,
            severity=SEVERITY_INFO,
            description="sitemap.xml is present. Informational for security review -- not a vulnerability.",
        ))

    return result


def run_exposed_files(session, base_url: str, timeout: float = 8.0) -> CategoryResult:
    result = CategoryResult(category="Exposed Files", weight=CATEGORY_WEIGHTS["Exposed Files"])

    for path, (severity, description) in _SENSITIVE_PATHS.items():
        url = base_url.rstrip("/") + path
        resp = safe_get(session, url, timeout=timeout, allow_redirects=False)
        if resp is None:
            result.add(Finding(
                check_id=f"exposed_{path}",
                name=f"Exposure of {path}",
                passed=True,
                severity=severity,
                description=f"Could not reach {url}; treating as not exposed.",
            ))
            continue

        if resp.status_code == 200:
            result.add(Finding(
                check_id=f"exposed_{path}",
                name=f"Exposure of {path}",
                passed=False,
                severity=severity,
                description=f"Potentially exposed sensitive resource - manual "
                            f"verification required. {url} returned HTTP 200. {description}",
                manual_verification=True,
                recommendation=f"Remove or block public access to {path}.",
            ))
        else:
            result.add(Finding(
                check_id=f"exposed_{path}",
                name=f"Exposure of {path}",
                passed=True,
                severity=severity,
                description=f"{url} returned HTTP {resp.status_code}; not publicly exposed.",
            ))

    return result


def run_security_txt(session, base_url: str, timeout: float = 8.0) -> CategoryResult:
    result = CategoryResult(category="security.txt", weight=CATEGORY_WEIGHTS["security.txt"])

    candidates = [
        base_url.rstrip("/") + "/.well-known/security.txt",
        base_url.rstrip("/") + "/security.txt",
    ]

    for url in candidates:
        resp = safe_get(session, url, timeout=timeout)
        if resp is not None and resp.status_code == 200 and "contact" in resp.text.lower():
            has_policy = "policy" in resp.text.lower()
            has_expires = "expires" in resp.text.lower()
            result.add(Finding(
                check_id="security_txt_present",
                name="security.txt",
                passed=True,
                severity=SEVERITY_INFO,
                description=f"Found at {url}, with a Contact field. "
                            f"Policy field {'present' if has_policy else 'absent'}; "
                            f"Expires field {'present' if has_expires else 'absent'}.",
            ))
            return result

    result.add(Finding(
        check_id="security_txt_present",
        name="security.txt",
        passed=True,  # absence is informational, not a vulnerability, per spec
        severity=SEVERITY_INFO,
        description="No security.txt found at /.well-known/security.txt or "
                    "/security.txt. Treated as informational, not a vulnerability.",
        recommendation="Consider publishing a security.txt (RFC 9116) so "
                       "researchers know how to report issues responsibly.",
    ))
    return result
