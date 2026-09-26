"""
scanner/technology.py
========================
Category: Technology Detection (also feeds "Known CVE Indicators")

Passive only -- reads headers and the HTML body from the normal
response already fetched elsewhere. No aggressive fingerprinting
(no forced error pages, no parameter injection, no extra requests
beyond re-using what was already fetched).

CVE indicators: this module does NOT call any external vulnerability
database or paid API (per the spec: "do not add unnecessary paid
APIs" and "if an external API is unavailable, the tool must still
work"). Instead it uses a small, clearly-labeled, local table of
"this looks like an old release line" heuristics. This is intentionally
conservative -- it is a starting point for manual research, never a
vulnerability confirmation.
"""

import re

from scanner.models import CategoryResult, Finding, SEVERITY_LOW, SEVERITY_INFO
from scanner.scoring import CATEGORY_WEIGHTS

CATEGORY_NAME = "Technology Detection"

# name -> (regex against the Server/X-Powered-By header, "looks old if major version below")
_VERSIONED_SOFTWARE = {
    "Apache": (re.compile(r"Apache/(\d+)\.(\d+)"), (2, 4)),
    "nginx": (re.compile(r"nginx/(\d+)\.(\d+)"), (1, 20)),
    "PHP": (re.compile(r"PHP/(\d+)\.(\d+)"), (7, 4)),
}

_CMS_SIGNATURES = {
    "WordPress": ["wp-content", "wp-includes", "/wp-json/"],
    "Drupal": ["Drupal.settings", "/sites/default/files"],
    "Joomla": ["/media/jui/", "Joomla!"],
}

_JS_FRAMEWORK_SIGNATURES = {
    "React": ["data-reactroot", "react-dom", "__NEXT_DATA__"],
    "Vue": ["data-v-", "__vue__", "vue.runtime"],
    "Angular": ["ng-version", "ng-app"],
}

_CDN_WAF_HEADER_HINTS = {
    "cf-ray": "Cloudflare",
    "x-amz-cf-id": "Amazon CloudFront",
    "x-sucuri-id": "Sucuri",
    "x-akamai-transformed": "Akamai",
    "server": None,  # handled specially below (cloudflare/openresty in Server header)
}


def run(response) -> CategoryResult:
    result = CategoryResult(category=CATEGORY_NAME, weight=CATEGORY_WEIGHTS[CATEGORY_NAME])

    headers = response.headers
    body = response.text if hasattr(response, "text") else ""
    body_sample = body[:200_000]  # cap how much HTML we scan; this is a header/body read, not a crawl

    server_header = headers.get("Server", "")
    powered_by = headers.get("X-Powered-By", "")
    combined_header_text = f"{server_header} {powered_by}"

    if server_header:
        result.add(Finding(
            check_id="tech_server_header",
            name="Web server",
            passed=True,
            severity=SEVERITY_INFO,
            description=f"Server header identifies: {server_header}",
            evidence=server_header,
        ))
    if powered_by:
        result.add(Finding(
            check_id="tech_powered_by",
            name="Backend framework",
            passed=True,
            severity=SEVERITY_INFO,
            description=f"X-Powered-By identifies: {powered_by}",
            evidence=powered_by,
        ))

    detected_cms = [name for name, sigs in _CMS_SIGNATURES.items() if any(s in body_sample for s in sigs)]
    for cms in detected_cms:
        result.add(Finding(
            check_id=f"tech_cms_{cms.lower()}",
            name="CMS detected",
            passed=True,
            severity=SEVERITY_INFO,
            description=f"Page content matches signatures for {cms}.",
        ))

    detected_js = [name for name, sigs in _JS_FRAMEWORK_SIGNATURES.items() if any(s in body_sample for s in sigs)]
    for js in detected_js:
        result.add(Finding(
            check_id=f"tech_js_{js.lower()}",
            name="JavaScript framework detected",
            passed=True,
            severity=SEVERITY_INFO,
            description=f"Page content matches signatures for {js}.",
        ))

    detected_cdn = []
    for header_name, cdn_name in _CDN_WAF_HEADER_HINTS.items():
        if header_name == "server":
            continue
        if header_name in {k.lower() for k in headers.keys()}:
            detected_cdn.append(cdn_name)
    if "cloudflare" in server_header.lower():
        detected_cdn.append("Cloudflare")
    if "openresty" in server_header.lower():
        detected_cdn.append("OpenResty (often used behind a CDN/WAF)")
    for cdn in sorted(set(detected_cdn)):
        result.add(Finding(
            check_id=f"tech_cdn_{cdn.lower().replace(' ', '_')}",
            name="CDN / WAF indicator",
            passed=True,
            severity=SEVERITY_INFO,
            description=f"Response characteristics suggest {cdn} may be in front of this site.",
        ))

    if not (server_header or powered_by or detected_cms or detected_js or detected_cdn):
        result.add(Finding(
            check_id="tech_none_detected",
            name="Technology fingerprint",
            passed=True,
            severity=SEVERITY_INFO,
            description="No obvious technology-identifying headers or page "
                        "signatures were found; the stack is well-obscured or "
                        "simply not exposed via these passive signals.",
        ))

    # --- lightweight, local, clearly-labeled "old version line" heuristic ---
    for name, (pattern, min_version) in _VERSIONED_SOFTWARE.items():
        match = pattern.search(combined_header_text)
        if not match:
            continue
        major, minor = int(match.group(1)), int(match.group(2))
        min_major, min_minor = min_version
        looks_old = (major, minor) < (min_major, min_minor)
        if looks_old:
            result.add(Finding(
                check_id=f"cve_indicator_{name.lower()}",
                name=f"{name} version indicator",
                passed=False,
                severity=SEVERITY_LOW,
                description=f"{name} {major}.{minor} was disclosed in response "
                            f"headers. This version line is older than "
                            f"{min_major}.{min_minor}, which is a heuristic "
                            f"signal only -- it is NOT a confirmed vulnerability.",
                evidence=match.group(0),
                manual_verification=True,
                recommendation=f"Manually check {name} {major}.{minor} against a "
                               f"current vulnerability database (e.g. NVD, "
                               f"vendor advisories) and upgrade if a real advisory applies.",
            ))
        else:
            result.add(Finding(
                check_id=f"cve_indicator_{name.lower()}",
                name=f"{name} version indicator",
                passed=True,
                severity=SEVERITY_LOW,
                description=f"{name} {major}.{minor} was disclosed; this version "
                            f"line is not flagged by our conservative local heuristic.",
                evidence=match.group(0),
            ))

    return result
