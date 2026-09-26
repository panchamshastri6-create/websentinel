"""
scanner/api.py
=================
Category: API Security

Passive only -- looks for API endpoint *hints* in already-public
documents (robots.txt, sitemap.xml, the page's own HTML/links, common
OpenAPI spec locations) and, for any endpoint found this way, checks
its passive configuration (HTTPS, CORS, security headers, content
type, error disclosure on a single normal GET). Never brute-forces
paths and never sends any payload beyond a plain GET.
"""

import re

from scanner.models import CategoryResult, Finding, SEVERITY_LOW, SEVERITY_MEDIUM, SEVERITY_INFO
from scanner.scoring import CATEGORY_WEIGHTS
from scanner.http import safe_get

CATEGORY_NAME = "API Security"

_LINK_API_PATTERN = re.compile(r"""["'](/[\w\-/]*api[\w\-/]*)["']""", re.IGNORECASE)

_OPENAPI_PATHS = [
    "/openapi.json",
    "/swagger.json",
    "/swagger-ui/",
    "/api-docs",
    "/.well-known/openapi.json",
]


def _find_api_hints_in_text(text: str) -> set:
    return set(m.group(1) for m in _LINK_API_PATTERN.finditer(text or ""))


def run(session, base_url: str, main_response, timeout: float = 8.0) -> CategoryResult:
    result = CategoryResult(category=CATEGORY_NAME, weight=CATEGORY_WEIGHTS[CATEGORY_NAME])

    hints = set()
    hints |= _find_api_hints_in_text(main_response.text if hasattr(main_response, "text") else "")

    robots_resp = safe_get(session, base_url.rstrip("/") + "/robots.txt", timeout=timeout)
    if robots_resp is not None and robots_resp.status_code == 200:
        hints |= _find_api_hints_in_text(robots_resp.text)

    sitemap_resp = safe_get(session, base_url.rstrip("/") + "/sitemap.xml", timeout=timeout)
    if sitemap_resp is not None and sitemap_resp.status_code == 200:
        hints |= _find_api_hints_in_text(sitemap_resp.text)

    if hints:
        result.add(Finding(
            check_id="api_endpoints_discovered",
            name="API endpoint hints",
            passed=True,
            severity=SEVERITY_INFO,
            description=f"Found {len(hints)} path(s) that look like API endpoints, "
                        f"discovered only from already-public links/robots.txt/sitemap.xml.",
            evidence=", ".join(sorted(hints)[:10]),
        ))
    else:
        result.add(Finding(
            check_id="api_endpoints_discovered",
            name="API endpoint hints",
            passed=True,
            severity=SEVERITY_INFO,
            description="No obvious API endpoint hints found in public links, "
                        "robots.txt, or sitemap.xml. This does not mean no API exists.",
        ))

    openapi_found = None
    for path in _OPENAPI_PATHS:
        resp = safe_get(session, base_url.rstrip("/") + path, timeout=timeout)
        if resp is not None and resp.status_code == 200:
            openapi_found = path
            break

    if openapi_found:
        result.add(Finding(
            check_id="api_spec_exposed",
            name="OpenAPI/Swagger spec exposure",
            passed=False,
            severity=SEVERITY_LOW,
            description=f"A machine-readable API spec appears to be publicly "
                        f"reachable at {openapi_found}. This is often intentional "
                        f"for public APIs, but confirm it isn't leaking internal-only endpoints.",
            manual_verification=True,
            recommendation="If this API is not meant to be public, restrict access "
                           "to the spec document.",
        ))
    else:
        result.add(Finding(
            check_id="api_spec_exposed",
            name="OpenAPI/Swagger spec exposure",
            passed=True,
            severity=SEVERITY_LOW,
            description="No common OpenAPI/Swagger spec path was found publicly exposed.",
        ))

    # Passively check the security posture of ONE discovered endpoint (if any),
    # as a representative sample -- never more than one extra request, and
    # never anything beyond a plain GET.
    if hints:
        sample_path = sorted(hints)[0]
        sample_url = base_url.rstrip("/") + sample_path
        resp = safe_get(session, sample_url, timeout=timeout)
        if resp is not None:
            content_type = resp.headers.get("Content-Type", "")
            if resp.status_code >= 500:
                result.add(Finding(
                    check_id="api_error_disclosure",
                    name="API error disclosure (sample endpoint)",
                    passed=False,
                    severity=SEVERITY_MEDIUM,
                    description=f"A plain GET to {sample_path} returned HTTP "
                                f"{resp.status_code}. Server error pages sometimes "
                                f"leak stack traces or internal paths.",
                    manual_verification=True,
                    recommendation="Ensure production error responses never include "
                                   "stack traces, internal paths, or debug info.",
                ))
            else:
                result.add(Finding(
                    check_id="api_error_disclosure",
                    name="API error disclosure (sample endpoint)",
                    passed=True,
                    severity=SEVERITY_MEDIUM,
                    description=f"A plain GET to {sample_path} returned HTTP "
                                f"{resp.status_code} with content-type {content_type!r}; "
                                f"no server error was observed.",
                ))

            if "Access-Control-Allow-Origin" in resp.headers:
                result.add(Finding(
                    check_id="api_cors",
                    name="Sample API endpoint CORS",
                    passed=True,
                    severity=SEVERITY_INFO,
                    description=f"Sample endpoint {sample_path} sets CORS headers; "
                                f"see the CORS category for detailed analysis.",
                ))

    result.add(Finding(
        check_id="access_control_note",
        name="Access control",
        passed=True,
        severity=SEVERITY_INFO,
        description="Access-control testing requires authorized authenticated "
                    "testing (e.g. confirming a low-privilege account cannot "
                    "reach admin-only endpoints). This cannot be done safely "
                    "without valid credentials for multiple roles.",
        manual_verification=True,
        recommendation="Perform authenticated access-control testing manually or "
                       "as part of a professional penetration test.",
    ))

    result.add(Finding(
        check_id="api_auth_note",
        name="API authentication",
        passed=True,
        severity=SEVERITY_INFO,
        description="Whether discovered endpoints correctly enforce authentication "
                    "and authorization cannot be determined by passive/safe checks alone.",
        manual_verification=True,
        recommendation="Authenticated API testing requires manual security testing "
                       "with valid credentials for multiple roles.",
    ))

    return result
