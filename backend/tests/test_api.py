from fastapi.testclient import TestClient
from app.main import app, documentation_routes

client = TestClient(app)


def test_production_disables_all_api_documentation_routes():
    assert documentation_routes("production") == (None, None, None)
    assert documentation_routes(" Production ") == (None, None, None)
    assert documentation_routes("development") == ("/docs", "/redoc", "/openapi.json")

def test_health_is_not_rate_limited():
    responses = [client.get("/api/health") for _ in range(31)]
    assert all(response.status_code == 200 for response in responses)
    assert responses[-1].json() == {"status": "ok"}

def test_url_validation_returns_controlled_errors():
    for payload in ({}, {"url": None}, {"url": 7}, {"url": ""}, {"url": "file:///etc/passwd"}, {"url": "https://example.com/" + "a" * 4096}):
        response = client.post("/api/analyze/url", json=payload)
        assert response.status_code == 422
        assert "traceback" not in response.text.lower()

def test_url_request_does_not_coerce_external_intelligence_opt_in():
    for payload in (
        {"url": "https://example.com", "external_intelligence": "yes"},
        {"url": "https://example.com", "external_intelligence": 1},
        {"url": "https://example.com", "unexpected": True},
    ):
        response = client.post("/api/analyze/url", json=payload)
        assert response.status_code == 422

def test_private_literal_is_reported_as_blocked_without_connection():
    response = client.post("/api/analyze/url", json={"url": "http://127.0.0.1/"})
    body = response.json()
    assert response.status_code == 200
    assert body["redirects"][-1]["blocked_reason"] == "Destination is a non-public address"
    assert any(item["id"] == "ssrf-block" for item in body["evidence"])

def test_credential_components_are_not_returned_in_url_results():
    response = client.post("/api/analyze/url", json={"url": "http://user:secret@127.0.0.1/login"})
    assert response.status_code == 200
    assert "user:secret" not in response.text
    assert response.json()["submitted_url"] == "http://127.0.0.1/login"
