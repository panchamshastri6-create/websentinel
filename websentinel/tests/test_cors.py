from scanner import cors
from tests.conftest import FakeResponse, FakeSession


def test_no_acao_header_passes():
    resp = FakeResponse(headers={})
    session = FakeSession(response=resp)
    result = cors.run(session, "https://example.com/api")
    acao_findings = [f for f in result.findings if f.check_id == "cors_acao"]
    assert acao_findings[0].passed is True


def test_wildcard_with_credentials_flagged_high():
    resp = FakeResponse(headers={
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Credentials": "true",
    })
    session = FakeSession(response=resp)
    result = cors.run(session, "https://example.com/api")
    acao_findings = [f for f in result.findings if f.check_id == "cors_acao"]
    assert acao_findings[0].passed is False
    assert acao_findings[0].severity == "HIGH"


def test_wildcard_without_credentials_passes():
    resp = FakeResponse(headers={"Access-Control-Allow-Origin": "*"})
    session = FakeSession(response=resp)
    result = cors.run(session, "https://example.com/api")
    acao_findings = [f for f in result.findings if f.check_id == "cors_acao"]
    assert acao_findings[0].passed is True


def test_reflected_arbitrary_origin_flagged():
    probe_origin = "https://websentinel-cors-probe.example"
    resp = FakeResponse(headers={"Access-Control-Allow-Origin": probe_origin})
    session = FakeSession(response=resp)
    result = cors.run(session, "https://example.com/api")
    acao_findings = [f for f in result.findings if f.check_id == "cors_acao"]
    assert acao_findings[0].passed is False
    assert acao_findings[0].severity == "HIGH"


def test_dangerous_methods_flagged():
    resp = FakeResponse(headers={
        "Access-Control-Allow-Origin": "https://trusted.example",
        "Access-Control-Allow-Methods": "GET, POST, DELETE",
    })
    session = FakeSession(response=resp)
    result = cors.run(session, "https://example.com/api")
    method_findings = [f for f in result.findings if f.check_id == "cors_methods"]
    assert method_findings[0].passed is False
