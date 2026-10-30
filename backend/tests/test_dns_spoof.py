import random

from app.engine.engine import analyze_file
from scripts.make_samples import (
    ATTACKER_IP,
    ATTACKER_MAC,
    SITES,
    START,
    VICTIM_IP,
    baseline,
    dns_answer,
    dns_query,
    dns_spoof,
)


def dns_alerts(result):
    return [a for a in result["alerts"] if a["detector"] == "dns_spoof"]


def test_forged_and_real_answers_are_flagged_once(capture_file):
    path = capture_file(baseline(START, 30, random.Random(1)) + dns_spoof(START + 12, random.Random(3)))

    alerts = dns_alerts(analyze_file(path))

    assert len(alerts) == 1
    alert = alerts[0]
    assert alert["severity"] == "high"
    assert alert["victim"] == VICTIM_IP
    assert alert["attacker"] == ATTACKER_MAC  # the forged answer arrived first
    assert alert["details"]["qname"] == "example.com"
    assert len(alert["details"]["responses"]) == 2


def test_normal_lookups_are_not_flagged(capture_file):
    path = capture_file(baseline(START, 60, random.Random(1)))

    assert dns_alerts(analyze_file(path)) == []


def test_identical_duplicate_answers_are_not_flagged(capture_file):
    name, address = "example.com", SITES["example.com"]
    path = capture_file([
        dns_query(START, name, 4242, 50000),
        dns_answer(START + 0.02, name, address, 4242, 50000),
        dns_answer(START + 0.03, name, address, 4242, 50000),  # retransmission, same answer
    ])

    assert dns_alerts(analyze_file(path)) == []


def test_reused_query_id_much_later_is_not_a_conflict(capture_file):
    # Query IDs are only 16 bits, so they repeat. A different answer minutes later is
    # normal (for example a CDN rotating addresses), not spoofing.
    name = "cdn.example"  # not in the known-good list
    path = capture_file([
        dns_query(START, name, 4242, 50000),
        dns_answer(START + 0.02, name, "203.0.113.50", 4242, 50000),
        dns_query(START + 120, name, 4242, 50000),
        dns_answer(START + 120.02, name, "203.0.113.51", 4242, 50000),
    ])

    assert dns_alerts(analyze_file(path)) == []


def test_answer_that_breaks_the_known_good_list_is_flagged(capture_file):
    # Full man-in-the-middle: the attacker drops the real answer, so only the forged one arrives.
    path = capture_file([
        dns_query(START, "example.com", 4242, 50000),
        dns_answer(START + 0.002, "example.com", ATTACKER_IP, 4242, 50000, src_mac=ATTACKER_MAC),
    ])

    alerts = dns_alerts(analyze_file(path))

    assert len(alerts) == 1
    assert alerts[0]["details"]["reason"] == "known_good_mismatch"
