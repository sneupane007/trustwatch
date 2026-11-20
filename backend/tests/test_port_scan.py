import random

from app.detectors.port_scan import PortScanDetector
from app.engine.engine import Engine, analyze_file
from app.engine.tshark import read_capture
from scripts.make_samples import ATTACKER_IP, START, VICTIM_IP, baseline, port_scan, web_visit


def port_scan_alerts(result):
    return [a for a in result["alerts"] if a["detector"] == "port_scan"]


def test_syn_scan_is_flagged_once_with_open_ports(capture_file):
    rng = random.Random(1)
    path = capture_file(baseline(START, 30, rng) + port_scan(START + 10, rng))

    alerts = port_scan_alerts(analyze_file(path))

    assert len(alerts) == 1
    alert = alerts[0]
    assert (alert["attacker"], alert["victim"]) == (ATTACKER_IP, VICTIM_IP)
    assert alert["details"]["ports_probed"] == 1000
    assert alert["details"]["open_ports"] == [22, 80]
    assert alert["packet_count"] == 1000


def test_normal_traffic_is_not_flagged(capture_file):
    path = capture_file(baseline(START, 60, random.Random(2)))

    assert port_scan_alerts(analyze_file(path)) == []


def test_slow_connections_to_many_ports_are_not_flagged(capture_file):
    # 30 different ports, one every 2 seconds: never 20 distinct ports inside 5 seconds.
    rng = random.Random(3)
    pkts = []
    for i, port in enumerate(range(8000, 8030)):
        pkts += web_visit(START + i * 2, ATTACKER_IP, port, rng)

    assert port_scan_alerts(analyze_file(capture_file(pkts))) == []


def test_small_scan_below_threshold_is_not_flagged(capture_file):
    ports = range(1, PortScanDetector.port_threshold)  # one port short of the threshold
    path = capture_file(port_scan(START, random.Random(4), ports=ports))

    assert port_scan_alerts(analyze_file(path)) == []


def test_live_style_feed_returns_the_alert_exactly_once(capture_file):
    # Phase 2 feeds packets one at a time; the alert must be "new" only once.
    engine = Engine(detectors=[PortScanDetector()])
    path = capture_file(port_scan(START, random.Random(5)))

    new_alerts = []
    for pkt in read_capture(path):
        new_alerts += engine.process(pkt)

    assert len(new_alerts) == 1
    assert new_alerts[0].details["ports_probed"] == 1000  # kept updating after it was raised
