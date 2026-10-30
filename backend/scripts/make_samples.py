"""Build synthetic lab captures so the app can be demoed and tested without the VMs.

Run from backend/:   .venv/bin/python scripts/make_samples.py

Writes capture files into backend/samples/. Packets are only written to files;
nothing is ever sent on a network. The addresses mirror our lab: one gateway
(which is also the DNS resolver), one victim, one attacker.

These are stand-ins. Phase 1 Part 2 records real captures from the VirtualBox
lab and saves them in samples/lab/.
"""

from __future__ import annotations

import random
from datetime import datetime, timezone
from pathlib import Path

from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Packet, Raw
from scapy.utils import wrpcap, wrpcapng

GATEWAY_IP, GATEWAY_MAC = "10.0.0.1", "02:00:00:00:00:01"  # also the DNS resolver
VICTIM_IP, VICTIM_MAC = "10.0.0.20", "02:00:00:00:00:14"
ATTACKER_IP, ATTACKER_MAC = "10.0.0.66", "02:00:00:00:00:42"
BROADCAST = "ff:ff:ff:ff:ff:ff"
LAN_MACS = {GATEWAY_IP: GATEWAY_MAC, VICTIM_IP: VICTIM_MAC, ATTACKER_IP: ATTACKER_MAC}

SITES = {"example.com": "203.0.113.10", "example.org": "203.0.113.20", "example.net": "203.0.113.30"}
OPEN_PORTS = {22, 80}  # ports the victim answers with SYN/ACK during a scan
START = datetime(2026, 10, 1, 14, 0, tzinfo=timezone.utc).timestamp()

SAMPLES_DIR = Path(__file__).resolve().parent.parent / "samples"


def _at(pkt: Packet, t: float) -> Packet:
    pkt.time = t
    return pkt


def _ether(src_ip: str, dst_ip: str) -> Ether:
    """LAN hosts talk MAC-to-MAC; anything off the LAN goes through the gateway's MAC."""
    return Ether(src=LAN_MACS.get(src_ip, GATEWAY_MAC), dst=LAN_MACS.get(dst_ip, GATEWAY_MAC))


def arp_lookup(t: float) -> list[Packet]:
    """Normal ARP: the victim asks for the gateway and the real gateway answers."""
    return [
        _at(Ether(src=VICTIM_MAC, dst=BROADCAST)
            / ARP(op=1, psrc=VICTIM_IP, hwsrc=VICTIM_MAC, pdst=GATEWAY_IP), t),
        _at(Ether(src=GATEWAY_MAC, dst=VICTIM_MAC)
            / ARP(op=2, psrc=GATEWAY_IP, hwsrc=GATEWAY_MAC, pdst=VICTIM_IP, hwdst=VICTIM_MAC), t + 0.0005),
    ]


def dns_query(t: float, name: str, qid: int, sport: int) -> Packet:
    return _at(_ether(VICTIM_IP, GATEWAY_IP) / IP(src=VICTIM_IP, dst=GATEWAY_IP)
               / UDP(sport=sport, dport=53) / DNS(id=qid, rd=1, qd=DNSQR(qname=name)), t)


def dns_answer(t: float, name: str, address: str, qid: int, sport: int, src_mac: str = GATEWAY_MAC) -> Packet:
    """A response that claims to come from the resolver. src_mac lets the attacker forge it."""
    return _at(Ether(src=src_mac, dst=VICTIM_MAC) / IP(src=GATEWAY_IP, dst=VICTIM_IP)
               / UDP(sport=53, dport=sport)
               / DNS(id=qid, qr=1, rd=1, ra=1, qd=DNSQR(qname=name),
                     an=DNSRR(rrname=name, ttl=300, rdata=address)), t)


def dns_lookup(t: float, name: str, rng: random.Random) -> list[Packet]:
    qid, sport = rng.randint(1, 65535), rng.randint(49152, 65535)
    return [dns_query(t, name, qid, sport), dns_answer(t + 0.02, name, SITES[name], qid, sport)]


def web_visit(t: float, server_ip: str, port: int, rng: random.Random) -> list[Packet]:
    """A complete TCP conversation: handshake, request, response, close."""
    v, s = VICTIM_IP, server_ip
    sport = rng.randint(49152, 65535)
    cs, ss = rng.randint(0, 2**31), rng.randint(0, 2**31)  # client and server sequence numbers

    def out(dt, flags, seq, ack, payload=b""):
        pkt = _ether(v, s) / IP(src=v, dst=s) / TCP(sport=sport, dport=port, flags=flags, seq=seq, ack=ack)
        return _at(pkt / Raw(payload) if payload else pkt, t + dt)

    def back(dt, flags, seq, ack, payload=b""):
        pkt = _ether(s, v) / IP(src=s, dst=v) / TCP(sport=port, dport=sport, flags=flags, seq=seq, ack=ack)
        return _at(pkt / Raw(payload) if payload else pkt, t + dt)

    request, response = b"Q" * 300, b"R" * 1200
    return [
        out(0.000, "S", cs, 0),
        back(0.030, "SA", ss, cs + 1),
        out(0.031, "A", cs + 1, ss + 1),
        out(0.032, "PA", cs + 1, ss + 1, request),
        back(0.070, "PA", ss + 1, cs + 1 + len(request), response),
        out(0.071, "A", cs + 1 + len(request), ss + 1 + len(response)),
        out(0.500, "FA", cs + 1 + len(request), ss + 1 + len(response)),
        back(0.530, "FA", ss + 1 + len(response), cs + 2 + len(request)),
        out(0.531, "A", cs + 2 + len(request), ss + 2 + len(response)),
    ]


def ping(t: float) -> list[Packet]:
    return [
        _at(_ether(VICTIM_IP, GATEWAY_IP) / IP(src=VICTIM_IP, dst=GATEWAY_IP) / ICMP(type=8, id=1, seq=1), t),
        _at(_ether(GATEWAY_IP, VICTIM_IP) / IP(src=GATEWAY_IP, dst=VICTIM_IP) / ICMP(type=0, id=1, seq=1), t + 0.001),
    ]


def baseline(t0: float, seconds: float, rng: random.Random) -> list[Packet]:
    """Normal traffic: ARP refreshes, DNS lookups, HTTPS visits and the odd ping."""
    pkts = arp_lookup(t0 + 0.1) + arp_lookup(t0 + seconds / 2)
    names = list(SITES)
    t, i = t0 + 1.0, 0
    while t < t0 + seconds - 1:
        name = names[i % len(names)]
        pkts += dns_lookup(t, name, rng)
        pkts += web_visit(t + 0.05, SITES[name], 443, rng)
        if i % 4 == 0:
            pkts += ping(t + 1.0)
        t += rng.uniform(2.5, 4.0)
        i += 1
    return pkts


def port_scan(t0: float, rng: random.Random, ports: range = range(1, 1001)) -> list[Packet]:
    """An nmap-style SYN scan: one SYN per port; open ports answer SYN/ACK, closed ones RST."""
    a, v = ATTACKER_IP, VICTIM_IP
    sport = rng.randint(40000, 60000)
    order = list(ports)
    rng.shuffle(order)
    pkts = []
    for i, port in enumerate(order):
        t = t0 + i * 0.002
        seq = rng.randint(0, 2**31)
        pkts.append(_at(_ether(a, v) / IP(src=a, dst=v) / TCP(sport=sport, dport=port, flags="S", seq=seq), t))
        if port in OPEN_PORTS:
            pkts.append(_at(_ether(v, a) / IP(src=v, dst=a)
                            / TCP(sport=port, dport=sport, flags="SA", seq=rng.randint(0, 2**31), ack=seq + 1), t + 0.0005))
            pkts.append(_at(_ether(a, v) / IP(src=a, dst=v)
                            / TCP(sport=sport, dport=port, flags="R", seq=seq + 1), t + 0.0006))
        else:
            pkts.append(_at(_ether(v, a) / IP(src=v, dst=a)
                            / TCP(sport=port, dport=sport, flags="RA", seq=0, ack=seq + 1), t + 0.0005))
    return pkts


def arp_spoof(t0: float, seconds: float = 20, every: float = 2.0) -> list[Packet]:
    """The attacker keeps telling the victim 'the gateway's IP is at MY MAC'."""
    count = int(seconds / every)
    return [
        _at(Ether(src=ATTACKER_MAC, dst=VICTIM_MAC)
            / ARP(op=2, psrc=GATEWAY_IP, hwsrc=ATTACKER_MAC, pdst=VICTIM_IP, hwdst=VICTIM_MAC), t0 + i * every)
        for i in range(count)
    ]


def dns_spoof(t0: float, rng: random.Random, name: str = "example.com") -> list[Packet]:
    """The attacker races the resolver: a forged answer (pointing at the attacker) lands first."""
    qid, sport = rng.randint(1, 65535), rng.randint(49152, 65535)
    return [
        dns_query(t0, name, qid, sport),
        dns_answer(t0 + 0.002, name, ATTACKER_IP, qid, sport, src_mac=ATTACKER_MAC),  # forged
        dns_answer(t0 + 0.025, name, SITES[name], qid, sport),  # real, but too late
        *web_visit(t0 + 0.05, ATTACKER_IP, 80, rng),  # the victim now visits the attacker
    ]


def build_captures() -> dict[str, list[Packet]]:
    """Every sample capture, by file name. Same output on every run (fixed seeds)."""
    # Separate seeds so attack traffic never reuses a baseline DNS query ID or port by accident.
    def rng(seed: int) -> random.Random:
        return random.Random(seed)

    captures = {
        "baseline.pcap": baseline(START, 60, rng(1)),
        "port_scan.pcap": baseline(START, 30, rng(1)) + port_scan(START + 10, rng(2)),
        "arp_spoof.pcap": baseline(START, 40, rng(1)) + arp_spoof(START + 10),
        "dns_spoof.pcap": baseline(START, 30, rng(1)) + dns_spoof(START + 12, rng(3)),
        "mixed.pcapng": (
            baseline(START, 90, rng(1))
            + arp_spoof(START + 15)
            + dns_spoof(START + 40, rng(3))
            + port_scan(START + 60, rng(2))
        ),
    }
    return {name: sorted(pkts, key=lambda p: float(p.time)) for name, pkts in captures.items()}


def write_capture(path: Path, pkts: list[Packet]) -> None:
    (wrpcapng if path.suffix == ".pcapng" else wrpcap)(str(path), pkts)


if __name__ == "__main__":
    SAMPLES_DIR.mkdir(exist_ok=True)
    for name, pkts in build_captures().items():
        write_capture(SAMPLES_DIR / name, pkts)
        print(f"wrote samples/{name}  ({len(pkts):,} packets)")
