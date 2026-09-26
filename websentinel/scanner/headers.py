"""
scanner/headers.py
====================
Category: HTTP Security Headers

Passive only -- reads headers from a normal GET response. Analyzes CSP
directive *values*, not just presence, per the spec (unsafe-inline,
unsafe-eval, wildcard sources, missing default-src, frame-ancestors,
object-src, base-uri).
"""

from scanner.models import CategoryResult, Finding, SEVERITY_LOW, SEVERITY_MEDIUM, SEVERITY_HIGH
from scanner.scoring import CATEGORY_WEIGHTS

CATEGORY_NAME = "HTTP Security Headers"

_SIMPLE_HEADER_SPECS = {
    "Strict-Transport-Security": (
        SEVERITY_HIGH,
        "Forces browsers to only connect over HTTPS for this host.",
        "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains'.",
    ),
    "X-Content-Type-Options": (
        SEVERITY_MEDIUM,
        "Prevents MIME-sniffing based script-injection tricks.",
        "Add 'X-Content-Type-Options: nosniff'.",
    ),
    "Referrer-Policy": (
        SEVERITY_LOW,
        "Controls how much of the current URL is leaked to other sites via the referrer.",
        "Add 'Referrer-Policy: strict-origin-when-cross-origin'.",
    ),
    "Permissions-Policy": (
        SEVERITY_LOW,
        "Explicitly disables browser features (camera, mic, geolocation, etc.) the site doesn't use.",
        "Add a 'Permissions-Policy' disabling unused features, e.g. 'camera=(), microphone=()'.",
    ),
    "Cross-Origin-Opener-Policy": (
        SEVERITY_LOW,
        "Isolates the browsing context from other origins, mitigating some cross-origin side channels.",
        "Add 'Cross-Origin-Opener-Policy: same-origin'.",
    ),
    "Cross-Origin-Resource-Policy": (
        SEVERITY_LOW,
        "Controls whether other sites may load this site's resources directly.",
        "Add 'Cross-Origin-Resource-Policy: same-origin' or 'same-site'.",
    ),
}

_DISCLOSURE_HEADERS = {
    "Server": "Reveals web server software (and sometimes version).",
    "X-Powered-By": "Reveals backend framework/language in use.",
    "X-AspNet-Version": "Reveals exact ASP.NET version.",
    "X-AspNetMvc-Version": "Reveals exact ASP.NET MVC version.",
}


def _analyze_csp(csp_value: str, result: CategoryResult, has_xfo: bool) -> None:
    directives = {}
    for part in csp_value.split(";"):
        part = part.strip()
        if not part:
            continue
        tokens = part.split()
        if tokens:
            directives[tokens[0].lower()] = tokens[1:]

    if "default-src" not in directives:
        result.add(Finding(
            check_id="csp_default_src",
            name="CSP default-src",
            passed=False,
            severity=SEVERITY_MEDIUM,
            description="Content-Security-Policy has no default-src directive, so "
                        "any resource type not explicitly listed falls back to the "
                        "browser's permissive default.",
            evidence=csp_value,
            recommendation="Add a restrictive default-src (e.g. 'self') as a safety net.",
        ))
    else:
        result.add(Finding(
            check_id="csp_default_src",
            name="CSP default-src",
            passed=True,
            severity=SEVERITY_MEDIUM,
            description="default-src is set.",
            evidence=" ".join(directives["default-src"]),
        ))

    for directive in ("script-src", "style-src"):
        values = directives.get(directive, directives.get("default-src"))
        if values is None:
            continue
        if "'unsafe-inline'" in values or "'unsafe-eval'" in values:
            unsafe_tokens = [v for v in values if v in ("'unsafe-inline'", "'unsafe-eval'")]
            result.add(Finding(
                check_id=f"csp_{directive}_unsafe",
                name=f"CSP {directive} unsafe keywords",
                passed=False,
                severity=SEVERITY_HIGH,
                description=f"{directive} allows {', '.join(unsafe_tokens)}, which "
                            f"substantially weakens CSP's protection against XSS.",
                evidence=" ".join(values),
                recommendation=f"Remove unsafe-inline/unsafe-eval from {directive}; use "
                               f"nonces or hashes for any inline scripts/styles that are required.",
            ))
        if "*" in values:
            result.add(Finding(
                check_id=f"csp_{directive}_wildcard",
                name=f"CSP {directive} wildcard",
                passed=False,
                severity=SEVERITY_MEDIUM,
                description=f"{directive} includes a bare '*' wildcard source.",
                evidence=" ".join(values),
                recommendation=f"Replace the wildcard in {directive} with an explicit allow-list of origins.",
            ))

    if "object-src" not in directives and directives.get("default-src") is None:
        result.add(Finding(
            check_id="csp_object_src",
            name="CSP object-src",
            passed=False,
            severity=SEVERITY_LOW,
            description="No object-src directive and no default-src fallback, so "
                        "plugin content (Flash/Java applets, legacy) is unrestricted.",
            evidence=csp_value,
            recommendation="Add \"object-src 'none'\" unless plugin content is required.",
        ))

    if "base-uri" not in directives:
        result.add(Finding(
            check_id="csp_base_uri",
            name="CSP base-uri",
            passed=False,
            severity=SEVERITY_LOW,
            description="No base-uri directive; a successful injection could still "
                        "rewrite the page's <base> tag to redirect relative URLs.",
            evidence=csp_value,
            recommendation="Add \"base-uri 'self'\".",
        ))
    else:
        result.add(Finding(
            check_id="csp_base_uri",
            name="CSP base-uri",
            passed=True,
            severity=SEVERITY_LOW,
            description="base-uri is restricted.",
            evidence=" ".join(directives["base-uri"]),
        ))

    # frame-ancestors is a modern alternative to X-Frame-Options; give
    # credit for it explicitly, per the spec's note about alternative controls.
    if "frame-ancestors" in directives:
        result.add(Finding(
            check_id="csp_frame_ancestors",
            name="CSP frame-ancestors",
            passed=True,
            severity=SEVERITY_MEDIUM,
            description="CSP frame-ancestors is set, which provides clickjacking "
                        "protection even without X-Frame-Options.",
            evidence=" ".join(directives["frame-ancestors"]),
        ))
    elif not has_xfo:
        result.add(Finding(
            check_id="csp_frame_ancestors",
            name="CSP frame-ancestors",
            passed=False,
            severity=SEVERITY_MEDIUM,
            description="Neither CSP frame-ancestors nor X-Frame-Options is set, "
                        "so this page has no clickjacking protection from either control.",
            recommendation="Add \"frame-ancestors 'self'\" to your CSP, or set X-Frame-Options.",
        ))


def run(response) -> CategoryResult:
    result = CategoryResult(category=CATEGORY_NAME, weight=CATEGORY_WEIGHTS[CATEGORY_NAME])
    headers = response.headers

    has_xfo = "X-Frame-Options" in headers

    # X-Frame-Options is handled specially so it can cross-reference CSP frame-ancestors.
    if has_xfo:
        result.add(Finding(
            check_id="x_frame_options",
            name="X-Frame-Options",
            passed=True,
            severity=SEVERITY_MEDIUM,
            description="Present.",
            evidence=headers["X-Frame-Options"],
        ))
    # (the "missing" case for X-Frame-Options is folded into the CSP
    # frame-ancestors finding above/below so we don't double-penalize a
    # site that correctly uses only the modern CSP control.)

    if "Content-Security-Policy" in headers:
        result.add(Finding(
            check_id="csp_present",
            name="Content-Security-Policy",
            passed=True,
            severity=SEVERITY_HIGH,
            description="Present.",
            evidence=headers["Content-Security-Policy"],
        ))
        _analyze_csp(headers["Content-Security-Policy"], result, has_xfo)
    else:
        result.add(Finding(
            check_id="csp_present",
            name="Content-Security-Policy",
            passed=False,
            severity=SEVERITY_HIGH,
            description="No Content-Security-Policy header found. CSP is one of "
                        "the strongest available defenses against XSS.",
            recommendation="Define a CSP that allow-lists only the origins your "
                           "site actually needs.",
        ))
        if not has_xfo:
            result.add(Finding(
                check_id="csp_frame_ancestors",
                name="Clickjacking protection",
                passed=False,
                severity=SEVERITY_MEDIUM,
                description="Neither X-Frame-Options nor a CSP frame-ancestors "
                            "directive is present.",
                recommendation="Add X-Frame-Options or a CSP frame-ancestors directive.",
            ))

    for header_name, (severity, description, recommendation) in _SIMPLE_HEADER_SPECS.items():
        if header_name in headers:
            result.add(Finding(
                check_id=header_name.lower().replace("-", "_"),
                name=header_name,
                passed=True,
                severity=severity,
                description="Present.",
                evidence=headers[header_name],
            ))
        else:
            result.add(Finding(
                check_id=header_name.lower().replace("-", "_"),
                name=header_name,
                passed=False,
                severity=severity,
                description=f"{header_name} was not found. {description}",
                recommendation=recommendation,
            ))

    for header_name, description in _DISCLOSURE_HEADERS.items():
        if header_name in headers:
            result.add(Finding(
                check_id=f"disclosure_{header_name.lower()}",
                name=f"{header_name} disclosure",
                passed=False,
                severity=SEVERITY_LOW,
                description=f"{description}",
                evidence=headers[header_name],
                recommendation=f"Suppress or generalize {header_name} at the server/proxy level.",
            ))

    return result


def run_content_security(response) -> CategoryResult:
    """
    Category: Content Security (weight 3)

    Checks Content-Type declaration hygiene and looks for mixed-content
    indicators (an HTTPS page loading plain http:// sub-resources) in the
    already-fetched HTML. Passive only -- no active content is executed
    or injected.
    """
    result = CategoryResult(category="Content Security", weight=CATEGORY_WEIGHTS["Content Security"])
    headers = response.headers
    content_type = headers.get("Content-Type", "")

    if content_type:
        result.add(Finding(
            check_id="content_type_declared",
            name="Content-Type header",
            passed=True,
            severity=SEVERITY_LOW,
            description="Content-Type is declared.",
            evidence=content_type,
        ))
    else:
        result.add(Finding(
            check_id="content_type_declared",
            name="Content-Type header",
            passed=False,
            severity=SEVERITY_LOW,
            description="No Content-Type header was returned; combined with a "
                        "missing X-Content-Type-Options, this increases MIME-sniffing risk.",
            recommendation="Always declare an explicit Content-Type.",
        ))

    body = response.text if hasattr(response, "text") else ""
    is_https_page = str(response.url).startswith("https://")
    if is_https_page:
        mixed_content_hits = body.count('src="http://') + body.count("src='http://")
        if mixed_content_hits:
            result.add(Finding(
                check_id="mixed_content",
                name="Mixed content indicator",
                passed=False,
                severity=SEVERITY_MEDIUM,
                description=f"Found {mixed_content_hits} sub-resource reference(s) "
                            f"using plain http:// on an HTTPS page (checked via a "
                            f"simple text scan of the HTML already fetched).",
                manual_verification=True,
                recommendation="Update all sub-resource references to https:// or "
                               "protocol-relative URLs.",
            ))
        else:
            result.add(Finding(
                check_id="mixed_content",
                name="Mixed content indicator",
                passed=True,
                severity=SEVERITY_MEDIUM,
                description="No obvious http:// sub-resource references found in the page HTML.",
            ))

    return result
