"""
scanner/tls.py
================
Category: TLS / HTTPS Security

Passive only -- opens one normal TLS handshake (same as any browser)
and reads the certificate and negotiated protocol. Never attempts a
downgrade, fuzzing, or any active manipulation of the handshake.
"""

import socket
import ssl
from datetime import datetime, timezone

from scanner.models import CategoryResult, Finding, SEVERITY_LOW, SEVERITY_MEDIUM, SEVERITY_HIGH, SEVERITY_INFO
from scanner.scoring import CATEGORY_WEIGHTS

CATEGORY_NAME = "TLS / HTTPS Security"

_WEAK_PROTOCOLS = {"TLSv1", "TLSv1.1", "SSLv3", "SSLv2"}


def _parse_hsts(value: str):
    directives = {}
    for part in value.split(";"):
        part = part.strip()
        if not part:
            continue
        if "=" in part:
            k, v = part.split("=", 1)
            directives[k.strip().lower()] = v.strip()
        else:
            directives[part.strip().lower()] = True
    return directives


def run(hostname: str, https_response, port: int = 443, timeout: float = 5.0) -> CategoryResult:
    result = CategoryResult(category=CATEGORY_NAME, weight=CATEGORY_WEIGHTS[CATEGORY_NAME])

    # --- HTTPS availability was already proven by the caller successfully
    # fetching https_response, so record that as a pass. ---
    result.add(Finding(
        check_id="https_available",
        name="HTTPS available",
        passed=True,
        severity=SEVERITY_HIGH,
        description="The site responded successfully over HTTPS.",
    ))

    context = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                protocol = ssock.version()
    except ssl.SSLCertVerificationError as exc:
        result.add(Finding(
            check_id="cert_valid",
            name="Certificate validity",
            passed=False,
            severity=SEVERITY_HIGH,
            description=f"Certificate verification failed: {exc.verify_message}.",
            recommendation="Install a valid certificate from a trusted CA and serve the full chain.",
        ))
        return result
    except (socket.timeout, socket.gaierror, ConnectionRefusedError, OSError) as exc:
        result.add(Finding(
            check_id="tls_connection",
            name="Direct TLS connection",
            passed=False,
            severity=SEVERITY_MEDIUM,
            description=f"Could not open a direct TLS socket to {hostname}:{port} "
                        f"({exc}) even though an HTTPS request succeeded via the "
                        f"HTTP library. Certificate/protocol detail checks were skipped.",
        ))
        return result

    result.add(Finding(
        check_id="cert_valid",
        name="Certificate validity",
        passed=True,
        severity=SEVERITY_HIGH,
        description="Certificate chain verified successfully against the system trust store.",
    ))

    # --- Certificate hostname match (already enforced by wrap_socket via
    # server_hostname, but we surface it explicitly as its own finding) ---
    result.add(Finding(
        check_id="cert_hostname",
        name="Certificate hostname match",
        passed=True,
        severity=SEVERITY_HIGH,
        description=f"The certificate is valid for {hostname} (hostname checking "
                    f"is enforced automatically by the TLS library; a mismatch "
                    f"would have raised a verification error above).",
    ))

    # --- Chain length (informational) ---
    issuer = dict(x[0] for x in cert.get("issuer", []))
    subject = dict(x[0] for x in cert.get("subject", []))
    result.add(Finding(
        check_id="cert_chain",
        name="Certificate chain",
        passed=True,
        severity=SEVERITY_MEDIUM,
        description=f"Issued by {issuer.get('organizationName', issuer.get('commonName', 'unknown'))} "
                    f"for {subject.get('commonName', hostname)}.",
    ))

    # --- Expiry ---
    not_after_str = cert.get("notAfter")
    if not_after_str:
        expires = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        days_left = (expires - datetime.now(timezone.utc)).days
        if days_left < 0:
            result.add(Finding(
                check_id="cert_expiry",
                name="Certificate expiration",
                passed=False,
                severity=SEVERITY_HIGH,
                description=f"Certificate expired {abs(days_left)} day(s) ago ({not_after_str}).",
                recommendation="Renew the certificate immediately.",
            ))
        elif days_left < 14:
            result.add(Finding(
                check_id="cert_expiry",
                name="Certificate expiration",
                passed=False,
                severity=SEVERITY_MEDIUM,
                description=f"Certificate expires in {days_left} day(s) ({not_after_str}).",
                recommendation="Renew soon, or automate renewal (e.g. certbot).",
            ))
        else:
            result.add(Finding(
                check_id="cert_expiry",
                name="Certificate expiration",
                passed=True,
                severity=SEVERITY_MEDIUM,
                description=f"Valid for {days_left} more day(s) (expires {not_after_str}).",
            ))

    # --- Protocol version ---
    if protocol in _WEAK_PROTOCOLS:
        result.add(Finding(
            check_id="tls_protocol",
            name="TLS protocol version",
            passed=False,
            severity=SEVERITY_HIGH,
            description=f"Negotiated {protocol}, which is outdated and insecure.",
            recommendation="Disable protocols older than TLS 1.2.",
        ))
    else:
        result.add(Finding(
            check_id="tls_protocol",
            name="TLS protocol version",
            passed=True,
            severity=SEVERITY_HIGH,
            description=f"Negotiated {protocol}.",
        ))

    # --- HSTS detail (header comes from the HTTPS response the caller already fetched) ---
    hsts_value = https_response.headers.get("Strict-Transport-Security")
    if not hsts_value:
        result.add(Finding(
            check_id="hsts_present",
            name="HSTS",
            passed=False,
            severity=SEVERITY_HIGH,
            description="No Strict-Transport-Security header.",
            recommendation="Add HSTS once HTTPS is confirmed working site-wide.",
        ))
    else:
        directives = _parse_hsts(hsts_value)
        max_age = int(directives.get("max-age", 0)) if str(directives.get("max-age", "0")).isdigit() else 0
        if max_age < 15552000:  # 180 days
            result.add(Finding(
                check_id="hsts_max_age",
                name="HSTS max-age",
                passed=False,
                severity=SEVERITY_MEDIUM,
                description=f"HSTS max-age is {max_age} seconds, which is under "
                            f"the commonly recommended minimum (~180 days).",
                evidence=hsts_value,
                recommendation="Raise max-age to at least 15552000 (180 days), ideally 31536000 (1 year).",
            ))
        else:
            result.add(Finding(
                check_id="hsts_max_age",
                name="HSTS max-age",
                passed=True,
                severity=SEVERITY_MEDIUM,
                description=f"HSTS max-age is {max_age} seconds.",
                evidence=hsts_value,
            ))

        result.add(Finding(
            check_id="hsts_include_subdomains",
            name="HSTS includeSubDomains",
            passed="includesubdomains" in directives,
            severity=SEVERITY_LOW,
            description="includeSubDomains is set." if "includesubdomains" in directives
                        else "includeSubDomains is not set; subdomains are not covered by this HSTS policy.",
            evidence=hsts_value,
            recommendation="" if "includesubdomains" in directives
                           else "Add includeSubDomains if all subdomains support HTTPS.",
        ))

        result.add(Finding(
            check_id="hsts_preload",
            name="HSTS preload indicator",
            passed="preload" in directives,
            severity=SEVERITY_LOW,
            description="preload directive is present (informational -- actual "
                        "preload-list submission is a separate, manual step)."
                        if "preload" in directives else
                        "No preload directive found. This is informational only.",
            evidence=hsts_value,
        ))

    return result
