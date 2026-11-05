import random

from scapy.layers.l2 import ARP, Ether

from app.engine.engine import analyze_file
from scripts.make_samples import (
    ATTACKER_MAC,
    BROADCAST,
    GATEWAY_IP,
    GATEWAY_MAC,
    START,
    VICTIM_IP,
    arp_lookup,
    arp_spoof,
    baseline,
)


def arp_alerts(result):
    return [a for a in result["alerts"] if a["detector"] == "arp_spoof"]


def test_forged_replies_are_flagged_once(capture_file):
    path = capture_file(baseline(START, 40, random.Random(1)) + arp_spoof(START + 10))

    alerts = arp_alerts(analyze_file(path))

    assert len(alerts) == 1
    alert = alerts[0]
    assert alert["severity"] == "high"
    assert alert["attacker"] == ATTACKER_MAC
    assert alert["victim"] == VICTIM_IP
    assert alert["details"]["ip"] == GATEWAY_IP
    assert alert["details"]["original_mac"] == GATEWAY_MAC
    assert alert["packet_count"] == 10  # arp_spoof() sends one forged reply every 2 s for 20 s


def test_normal_arp_is_not_flagged(capture_file):
    path = capture_file(baseline(START, 60, random.Random(1)))

    assert arp_alerts(analyze_file(path)) == []


def test_gratuitous_arp_from_the_same_mac_is_not_flagged(capture_file):
    # Hosts announce their own IP on boot. Same IP, same MAC: nothing suspicious.
    announce = Ether(src=GATEWAY_MAC, dst=BROADCAST) / ARP(
        op=2, psrc=GATEWAY_IP, hwsrc=GATEWAY_MAC, pdst=GATEWAY_IP, hwdst=BROADCAST
    )
    announce.time = START + 5
    path = capture_file(arp_lookup(START) + [announce])

    assert arp_alerts(analyze_file(path)) == []


def test_arp_probe_from_0_0_0_0_is_not_flagged(capture_file):
    # A host checking whether an address is free sends sender IP 0.0.0.0 (RFC 5227).
    probe = Ether(src=ATTACKER_MAC, dst=BROADCAST) / ARP(op=1, psrc="0.0.0.0", hwsrc=ATTACKER_MAC, pdst=GATEWAY_IP)
    probe.time = START + 5
    path = capture_file(arp_lookup(START) + [probe])

    assert arp_alerts(analyze_file(path)) == []
