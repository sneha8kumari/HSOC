"""
Unit tests for the real-time StreamEngine and /stream API endpoints.
"""

import pytest
from fastapi.testclient import TestClient

from hsoc.api.main import create_app
from hsoc.simulate.stream_engine import engine


@pytest.fixture
def client():
    app = create_app()
    with TestClient(app) as c:
        yield c


def test_stream_status(client):
    res = client.get("/stream/status")
    assert res.status_code == 200
    data = res.json()
    assert "running" in data
    assert "speed" in data
    assert "current_scenario_name" in data
    assert "events_emitted" in data


def test_stream_pause_and_start(client):
    res = client.post("/stream/pause")
    assert res.status_code == 200
    assert res.json()["status"] == "paused"
    assert engine.is_running is False

    res = client.post("/stream/start")
    assert res.status_code == 200
    assert res.json()["status"] == "started"
    assert engine.is_running is True


def test_stream_speed_change(client):
    res = client.post("/stream/speed", json={"speed": 10})
    assert res.status_code == 200
    assert res.json()["speed"] == 10
    assert engine.speed == 10

    # Reset back to 5
    client.post("/stream/speed", json={"speed": 5})
    assert engine.speed == 5


def test_stream_inject_event(client):
    prev_emitted = engine.events_emitted
    res = client.post("/stream/inject", json={"scenario_id": "S8"})
    assert res.status_code == 200
    assert res.json()["status"] == "injected"
    assert engine.events_emitted > prev_emitted
