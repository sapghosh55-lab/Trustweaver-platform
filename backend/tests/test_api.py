from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


def test_health_check_endpoint():
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["service"] == "hackmatrix-backend"


def test_api_status_endpoint():
    response = client.get("/api/status")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "operational"
    assert "tiers" in data
    assert "local_gemma" in data["tiers"]
    assert "cloud_llama" in data["tiers"]


def test_route_endpoint():
    response = client.post("/api/route", json={"text": "Classify URL: https://example.com"})
    assert response.status_code == 200
    data = response.json()
    assert "target" in data
    assert "complexity_score" in data
    assert "is_complex" in data


def test_scan_validation_error():
    # Empty URL should return 400 or 422
    response = client.post("/scan", json={"url": ""})
    assert response.status_code == 400

