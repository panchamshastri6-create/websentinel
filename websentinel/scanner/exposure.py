"""
scanner/exposure.py
======================
Covers three weighted categories:

  - HTTP Methods              (weight 5)
  - Safe Service Exposure     (weight 2)
  - Common Misconfigurations  (weight 4)

HTTP Methods: sends only safe, standard methods (GET, HEAD, OPTIONS)
to discover what the server *advertises* via the Allow header. Never
sends PUT/DELETE/TRACE/PATCH -- those are only flagged as "potentially
exposed" if the server's own OPTIONS response lists them, and are
always marked as requiring manual verification.

Safe Service Exposure: a small, fixed list of well-known ports, TCP
"is something listening" checks only (connect then immediately close --
no banner grabbing, no protocol interaction, no exploitation). This is
NOT a general-purpose port scanner: it only ever targets the single
resolved IP(s) of the authorized target, never ranges or other hosts,
and only runs when the operator opts in (checked in websentinel.py by
requiring --active AND --check-ports together).

Common Misconfigurations: a rollup layer that looks at findings already
collected by other categories and surfaces the handful the spec singles
out as classic misconfiguration patterns, so they're visible together
in one place.
"""

import socket

from scanner.models import CategoryResult, Finding, SEVERITY_LOW, SEVERITY_MEDIUM, SEVERITY_HIGH, SEVERITY_INFO
from scanner.scoring import CATEGORY_WEIGHTS
from scanner.http import safe_get, SAFE_EXPOSURE_PORTS

_DANGEROUS_METHODS = {"PUT", "DELETE", "TRACE", "CONNECT", "PATCH"}
_SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}


def run_http_methods(session, url: str, timeout: float = 8.0) -> CategoryResult:
    result = CategoryResult(category="HTTP Methods", weight=CATEGORY_WEIGHTS["HTTP Methods"])

    resp = safe_get(session, url, timeout=timeout)
    # requests.Session doesn't have a generic verb-agnostic helper beyond
    # .options()/.head() etc, but session.request is the standard, safe way
    # to issue an OPTIONS request -- it is not a "destructive method".
    try:
        options_resp = session.request("OPTIONS", url, timeout=timeout)
    except Exception:
        options_resp = None

    if options_resp is None:
        result.add(Finding(
            check_id="http_methods_options",
            name="OPTIONS request",
            passed=True,
            severity=SEVERITY_LOW,
            description="OPTIONS request did not return a usable response; method "
                        "enumeration via Allow header was skipped.",
        ))
        return result

    allow_header = options_resp.headers.get("Allow", "")
    advertised = {m.strip().upper() for m in allow_header.split(",") if m.strip()}

    if not advertised:
        result.add(Finding(
            check_id="http_methods_options",
            name="OPTIONS request",
            passed=True,
            severity=SEVERITY_LOW,
            description="Server did not return an Allow header listing supported methods.",
        ))
    else:
        result.add(Finding(
            check_id="http_methods_options",
            name="Advertised HTTP methods",
            passed=True,
            severity=SEVERITY_LOW,
            description=f"Server advertises: {', '.join(sorted(advertised))}.",
            evidence=allow_header,
        ))

        dangerous_found = advertised & _DANGEROUS_METHODS
        if dangerous_found:
            result.add(Finding(
                check_id="http_methods_dangerous",
                name="Potentially exposed methods",
                passed=False,
                severity=SEVERITY_MEDIUM,
                description=f"Server advertises {', '.join(sorted(dangerous_found))} "
                            f"in its Allow header. Potentially exposed method - "
                            f"manual verification required. WebSentinel does not "
                            f"send these methods, so it cannot confirm what they "
                            f"actually do server-side.",
                manual_verification=True,
                recommendation="Manually verify whether these methods are actually "
                               "enabled and needed; disable any that aren't required.",
            ))
        else:
            result.add(Finding(
                check_id="http_methods_dangerous",
                name="Potentially exposed methods",
                passed=True,
                severity=SEVERITY_MEDIUM,
                description="No commonly-dangerous methods (PUT/DELETE/TRACE/CONNECT/PATCH) were advertised.",
            ))

    return result


def run_safe_service_exposure(resolved_ips, enabled: bool, timeout: float = 2.0) -> CategoryResult:
    result = CategoryResult(category="Safe Service Exposure", weight=CATEGORY_WEIGHTS["Safe Service Exposure"])

    if not enabled:
        result.add(Finding(
            check_id="service_exposure_skipped",
            name="Port reachability check",
            passed=True,
            severity=SEVERITY_INFO,
            description="Skipped. Enable with --active --check-ports to run a "
                        "short, fixed-list TCP reachability check (connect only, "
                        "no banner grabbing) against this authorized target.",
        ))
        return result

    if not resolved_ips:
        result.skipped_reason = "No resolved IP address available for the target."
        return result

    ip = resolved_ips[0]  # only ever the authorized target's own resolved address
    open_ports = []
    for port in SAFE_EXPOSURE_PORTS:
        try:
            with socket.create_connection((ip, port), timeout=timeout):
                open_ports.append(port)
        except OSError:
            continue

    if open_ports:
        severity = SEVERITY_MEDIUM if any(p not in (80, 443) for p in open_ports) else SEVERITY_LOW
        result.add(Finding(
            check_id="service_exposure_open_ports",
            name="Reachable TCP ports",
            passed=len(open_ports) <= 2 and set(open_ports) <= {80, 443},
            severity=severity,
            description=f"The following ports appear reachable on {ip}: "
                        f"{', '.join(str(p) for p in open_ports)}. This only "
                        f"confirms a TCP connection was accepted -- no banner "
                        f"or protocol interaction was performed.",
            evidence=", ".join(str(p) for p in open_ports),
            manual_verification=True,
            recommendation="Confirm each reachable port is intentionally exposed "
                           "and properly secured/firewalled if not.",
        ))
    else:
        result.add(Finding(
            check_id="service_exposure_open_ports",
            name="Reachable TCP ports",
            passed=True,
            severity=SEVERITY_LOW,
            description=f"None of the checked ports ({', '.join(str(p) for p in SAFE_EXPOSURE_PORTS)}) "
                        f"appeared reachable on {ip}.",
        ))

    return result


def run_common_misconfigurations(category_results_by_name: dict) -> CategoryResult:
    """
    A rollup layer: looks at specific check_ids already produced by other
    categories and surfaces the ones the spec calls out as classic
    misconfiguration patterns, in one place. Does not perform any new
    requests of its own.
    """
    result = CategoryResult(category="Common Misconfigurations", weight=CATEGORY_WEIGHTS["Common Misconfigurations"])

    # (category name, check_id, human label)
    watch_list = [
        ("TLS / HTTPS Security", "https_available", "Missing HTTPS"),
        ("TLS / HTTPS Security", "hsts_present", "Missing HSTS"),
        ("HTTP Security Headers", "csp_present", "Missing CSP"),
        ("HTTP Security Headers", "csp_script_src_unsafe", "Weak CSP (unsafe-inline/unsafe-eval)"),
        ("HTTP Security Headers", "csp_style_src_unsafe", "Weak CSP (unsafe-inline/unsafe-eval)"),
        ("Cookie Security", "cookie_1_session_attrs", "Insecure session cookie"),
        ("CORS", "cors_acao", "Permissive CORS"),
        ("HTTP Security Headers", "disclosure_server", "Verbose Server header"),
        ("HTTP Methods", "http_methods_dangerous", "Unsafe HTTP methods advertised"),
        ("Redirect Security", "https_redirect", "Insecure redirect (no HTTPS enforcement)"),
        ("TLS / HTTPS Security", "cert_valid", "Certificate problem"),
    ]

    matches = 0
    for category_name, check_id, label in watch_list:
        cat = category_results_by_name.get(category_name)
        if not cat:
            continue
        for f in cat.findings:
            if f.check_id == check_id and not f.passed:
                matches += 1
                result.add(Finding(
                    check_id=f"misconfig_{check_id}",
                    name=label,
                    passed=False,
                    severity=f.severity,
                    description=f"{label}: see the '{category_name}' category for full detail.",
                    evidence=f.evidence,
                ))
                break  # only report each watch-list item once

    if matches == 0:
        result.add(Finding(
            check_id="misconfig_none",
            name="Common misconfiguration patterns",
            passed=True,
            severity=SEVERITY_LOW,
            description="None of the classic misconfiguration patterns checked "
                        "here (missing HTTPS/HSTS/CSP, insecure cookies, permissive "
                        "CORS, verbose Server header, unsafe methods, insecure "
                        "redirects, cert problems) were detected.",
        ))

    return result
