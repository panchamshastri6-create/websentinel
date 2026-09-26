"""
scanner/cors.py
=================
Category: CORS

Passive only -- sends one normal GET request with a standard Origin
header (as any cross-origin browser request would) and reads how the
server responds. Never attempts to exploit any misconfiguration found.
"""

from scanner.models import CategoryResult, Finding, SEVERITY_MEDIUM, SEVERITY_HIGH
from scanner.scoring import CATEGORY_WEIGHTS
from scanner.http import safe_get

CATEGORY_NAME = "CORS"

_PROBE_ORIGIN = "https://websentinel-cors-probe.example"


def run(session, url: str, timeout: float = 8.0) -> CategoryResult:
    result = CategoryResult(category=CATEGORY_NAME, weight=CATEGORY_WEIGHTS[CATEGORY_NAME])

    resp = safe_get(session, url, timeout=timeout, headers={"Origin": _PROBE_ORIGIN})
    if resp is None:
        result.skipped_reason = "Could not complete a CORS probe request."
        return result

    acao = resp.headers.get("Access-Control-Allow-Origin")
    acac = resp.headers.get("Access-Control-Allow-Credentials")
    acam = resp.headers.get("Access-Control-Allow-Methods")
    acah = resp.headers.get("Access-Control-Allow-Headers")

    if acao is None:
        result.add(Finding(
            check_id="cors_acao",
            name="Access-Control-Allow-Origin",
            passed=True,
            severity=SEVERITY_MEDIUM,
            description="No Access-Control-Allow-Origin header for a cross-origin "
                        "request; this resource is not opened up to other sites by default.",
        ))
    elif acao == "*":
        if acac and acac.lower() == "true":
            result.add(Finding(
                check_id="cors_acao",
                name="Access-Control-Allow-Origin",
                passed=False,
                severity=SEVERITY_HIGH,
                description="Wildcard origin ('*') combined with "
                            "Access-Control-Allow-Credentials: true. Browsers reject "
                            "this exact combination, but it signals a serious "
                            "misconfiguration that should still be fixed.",
                evidence=f"ACAO={acao}, ACAC={acac}",
                recommendation="Never combine a wildcard origin with credentialed requests.",
            ))
        else:
            result.add(Finding(
                check_id="cors_acao",
                name="Access-Control-Allow-Origin",
                passed=True,
                severity=SEVERITY_MEDIUM,
                description="Wildcard origin ('*') without credentials -- a common, "
                            "generally safe pattern for public APIs.",
                evidence=acao,
            ))
    elif acao == _PROBE_ORIGIN:
        result.add(Finding(
            check_id="cors_acao",
            name="Access-Control-Allow-Origin",
            passed=False,
            severity=SEVERITY_HIGH,
            description="The server reflected our arbitrary, made-up Origin header "
                        "back verbatim, suggesting it trusts any requesting origin "
                        "rather than validating against an allow-list.",
            evidence=f"Probe Origin sent: {_PROBE_ORIGIN}; ACAO returned: {acao}",
            recommendation="Validate Origin against an explicit allow-list before echoing it back.",
        ))
    else:
        result.add(Finding(
            check_id="cors_acao",
            name="Access-Control-Allow-Origin",
            passed=True,
            severity=SEVERITY_MEDIUM,
            description=f"Returned a specific origin ({acao!r}) that does not "
                        f"match our probe, suggesting an allow-list is in use.",
            evidence=acao,
        ))

    if acam and any(m.strip().upper() in ("PUT", "DELETE", "TRACE", "CONNECT") for m in acam.split(",")):
        result.add(Finding(
            check_id="cors_methods",
            name="Access-Control-Allow-Methods",
            passed=False,
            severity=SEVERITY_MEDIUM,
            description=f"CORS advertises potentially dangerous methods: {acam}.",
            evidence=acam,
            recommendation="Restrict Access-Control-Allow-Methods to only what the API genuinely needs.",
        ))
    elif acam:
        result.add(Finding(
            check_id="cors_methods",
            name="Access-Control-Allow-Methods",
            passed=True,
            severity=SEVERITY_MEDIUM,
            description="Advertised methods look reasonable.",
            evidence=acam,
        ))

    if acah == "*":
        result.add(Finding(
            check_id="cors_headers",
            name="Access-Control-Allow-Headers",
            passed=False,
            severity=SEVERITY_MEDIUM,
            description="Access-Control-Allow-Headers is a wildcard, allowing any request header.",
            evidence=acah,
            recommendation="Allow-list only the specific headers your API actually requires.",
        ))

    return result
