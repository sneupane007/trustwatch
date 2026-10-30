from fastapi.testclient import TestClient

from app.main import app
from scripts.make_samples import build_captures

client = TestClient(app)


def test_detectors_lists_all_three_attacks():
    response = client.get("/api/detectors")

    assert response.status_code == 200
    assert [d["id"] for d in response.json()] == ["arp_spoof", "dns_spoof", "port_scan"]


def test_analyze_pcapng_upload(capture_file):
    pkts = build_captures()["mixed.pcapng"]
    path = capture_file(pkts, name="mixed.pcapng")

    with path.open("rb") as f:
        response = client.post("/api/analyze", files={"file": ("mixed.pcapng", f)})

    assert response.status_code == 200
    body = response.json()
    assert body["filename"] == "mixed.pcapng"
    assert body["summary"]["packets"] == len(pkts)
    assert {p["name"] for p in body["protocols"]} == {"TCP", "DNS", "ARP", "ICMP"}
    assert [a["detector"] for a in body["alerts"]] == ["arp_spoof", "dns_spoof", "port_scan"]
    assert all(d["implemented"] for d in body["detectors"])
    assert body["timeline"]["points"]


def test_non_capture_file_is_rejected():
    response = client.post("/api/analyze", files={"file": ("notes.txt", b"hello, not a pcap")})

    assert response.status_code == 400
    assert "pcap" in response.json()["detail"]
