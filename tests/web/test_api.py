"""Tests for FastAPI web dashboard endpoints."""

import pytest
from fastapi.testclient import TestClient

from home_net_analyzer.web.api import create_app


@pytest.fixture()
def client() -> TestClient:
    app = create_app(rules_backend="noop")
    return TestClient(app)


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------

def test_dashboard_html(client: TestClient) -> None:
    res = client.get("/")
    assert res.status_code == 200
    assert "Home Network Analyzer" in res.text
    assert "Packets" in res.text
    assert "Rules" in res.text


# ---------------------------------------------------------------------------
# Packets API
# ---------------------------------------------------------------------------

def test_packets_count_empty(client: TestClient) -> None:
    res = client.get("/api/packets/count")
    assert res.status_code == 200
    data = res.json()
    assert "count" in data
    assert isinstance(data["count"], int)


def test_packets_list(client: TestClient) -> None:
    res = client.get("/api/packets?limit=5")
    assert res.status_code == 200
    data = res.json()
    assert "packets" in data
    assert isinstance(data["packets"], list)


def test_packets_query(client: TestClient) -> None:
    res = client.get("/api/packets/query?proto=TCP&limit=10")
    assert res.status_code == 200
    data = res.json()
    assert "packets" in data


# ---------------------------------------------------------------------------
# Rules API
# ---------------------------------------------------------------------------

def test_rules_list(client: TestClient) -> None:
    res = client.get("/api/rules")
    assert res.status_code == 200
    data = res.json()
    assert "rules" in data
    assert isinstance(data["rules"], list)


def test_rules_create_and_get(client: TestClient) -> None:
    # Create
    res = client.post("/api/rules", json={
        "action": "block",
        "target": "ip",
        "value": "192.168.1.50",
    })
    assert res.status_code == 201
    created = res.json()
    assert created["action"] == "block"
    assert created["value"] == "192.168.1.50"
    rid = created["id"]
    assert rid is not None

    # Get
    res = client.get(f"/api/rules/{rid}")
    assert res.status_code == 200
    got = res.json()
    assert got["id"] == rid


def test_rules_create_invalid_target(client: TestClient) -> None:
    res = client.post("/api/rules", json={
        "action": "block",
        "target": "invalid",
        "value": "x",
    })
    assert res.status_code == 400


def test_rules_update(client: TestClient) -> None:
    # Create
    res = client.post("/api/rules", json={"action": "allow", "target": "port", "value": "80"})
    rid = res.json()["id"]

    # Update
    res = client.put(f"/api/rules/{rid}", json={"enabled": False})
    assert res.status_code == 200
    updated = res.json()
    assert updated["enabled"] is False


def test_rules_delete(client: TestClient) -> None:
    res = client.post("/api/rules", json={"action": "block", "target": "ip", "value": "10.0.0.1"})
    rid = res.json()["id"]

    res = client.delete(f"/api/rules/{rid}")
    assert res.status_code == 200
    assert res.json()["deleted"] == rid

    # Now 404
    res = client.get(f"/api/rules/{rid}")
    assert res.status_code == 404


def test_rules_enable_disable(client: TestClient) -> None:
    res = client.post("/api/rules", json={"action": "block", "target": "ip", "value": "10.0.0.5", "enabled": True})
    rid = res.json()["id"]

    res = client.post(f"/api/rules/{rid}/disable")
    assert res.status_code == 200
    assert res.json()["disabled"] == rid

    res = client.post(f"/api/rules/{rid}/enable")
    assert res.status_code == 200
    assert res.json()["enabled"] == rid


def test_rules_not_found(client: TestClient) -> None:
    res = client.get("/api/rules/99999")
    assert res.status_code == 404
    res = client.delete("/api/rules/99999")
    assert res.status_code == 404
    res = client.post("/api/rules/99999/enable")
    assert res.status_code == 404
