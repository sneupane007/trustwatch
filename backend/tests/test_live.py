"""Live mode, tested through replay so no capture rights are needed."""

import pytest
from fastapi.testclient import TestClient

from app import live
from app.engine.engine import analyze_file
from app.main import app

ATTACKS = ["arp_spoof", "dns_spoof", "port_scan"]  # all three are in mixed.pcapng


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(live, "SESSIONS_DIR", tmp_path / "sessions")
    monkeypatch.setattr(live, "_current", None)
    with TestClient(app) as client:  # runs the lifespan, which stops any session left running
        yield client


def replay_until_stopped(client) -> list[dict]:
    """Connect first, then replay mixed.pcapng fast, and return every message up to "stopped"."""
    with client.websocket_connect("/api/live/ws") as ws:
        response = client.post("/api/live/start", json={"replay": "mixed.pcapng", "speed": 1000})
        assert response.status_code == 200
        messages = [ws.receive_json()]
        while messages[-1]["type"] != "stopped":
            messages.append(ws.receive_json())
    return messages


def test_replay_streams_snapshots_and_one_alert_per_attack(client):
    messages = replay_until_stopped(client)

    snapshots = [m for m in messages if m["type"] == "snapshot"]
    alerts = [m["alert"] for m in messages if m["type"] == "alert"]
    assert snapshots
    assert snapshots[-1]["source"] == "mixed.pcapng (replay)"
    assert snapshots[-1]["result"]["summary"]["packets"] == 2350
    assert sorted(a["detector"] for a in alerts) == ATTACKS


def test_saved_session_matches_file_mode(client, tmp_path):
    session_id = replay_until_stopped(client)[-1]["session_id"]

    listed = client.get("/api/sessions").json()
    assert [(s["id"], s["packets"], s["alerts"]) for s in listed] == [(session_id, 2350, 3)]

    pcap = tmp_path / "downloaded.pcap"
    pcap.write_bytes(client.get(f"/api/sessions/{session_id}/pcap").content)
    live_alerts = client.get(f"/api/sessions/{session_id}").json()["alerts"]
    file_alerts = analyze_file(pcap)["alerts"]

    def evidence(alerts):
        return [(a["detector"], a["packets"], a["packet_count"]) for a in alerts]

    assert evidence(live_alerts) == evidence(file_alerts)  # same alerts, same frame numbers
    assert sorted(a["detector"] for a in live_alerts) == ATTACKS


def test_only_one_session_at_a_time(client):
    first = client.post("/api/live/start", json={"replay": "mixed.pcapng"})  # real speed: ~90 s
    second = client.post("/api/live/start", json={"replay": "mixed.pcapng"})

    assert second.status_code == 409
    assert client.get("/api/live/status").json()["running"]

    stopped = client.post("/api/live/stop").json()
    assert stopped["session_id"] == first.json()["session_id"]
    assert not client.get("/api/live/status").json()["running"]


def test_replay_only_reads_from_samples_folder(client):
    response = client.post("/api/live/start", json={"replay": "../app/main.py"})

    assert response.status_code == 404
