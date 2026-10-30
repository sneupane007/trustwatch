"""Turn a Scapy packet into a small, plain record that detectors read.

Detectors never touch Scapy directly. That keeps them easy to test, and it lets
file mode (Phase 1) and live capture (Phase 2) share exactly the same code.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from scapy.layers.dns import DNS
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Packet


@dataclass
class ArpInfo:
    op: int  # 1 = request ("who has 10.0.0.1?"), 2 = reply ("10.0.0.1 is at <mac>")
    sender_ip: str
    sender_mac: str
    target_ip: str
    target_mac: str


@dataclass
class DnsInfo:
    id: int  # query ID: a query and its response share it
    is_response: bool
    qname: str  # e.g. "example.com" (no trailing dot)
    answers: list[str] = field(default_factory=list)  # A / AAAA addresses in a response


@dataclass
class PacketInfo:
    number: int  # frame number, same as Wireshark's "No." column
    time: float  # capture timestamp in seconds since the epoch
    length: int  # bytes on the wire
    protocol: str  # top layer we label: DNS, ARP, TCP, UDP, ICMP, ICMPv6, IPv4, IPv6, Other
    src_mac: str | None = None
    dst_mac: str | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    src_port: int | None = None
    dst_port: int | None = None
    tcp_flags: str | None = None  # Scapy flag letters: "S" = SYN, "SA" = SYN/ACK, "RA" = RST/ACK
    arp: ArpInfo | None = None
    dns: DnsInfo | None = None


def _text(value: bytes | str) -> str:
    return value.decode(errors="replace") if isinstance(value, bytes) else str(value)


def _dns_info(dns: DNS) -> DnsInfo:
    qname = _text(dns.qd[0].qname).rstrip(".") if dns.qd else ""
    answers = [_text(rr.rdata) for rr in (dns.an or []) if getattr(rr, "type", None) in (1, 28)]
    return DnsInfo(id=int(dns.id), is_response=bool(dns.qr), qname=qname, answers=answers)


def to_packet_info(pkt: Packet, number: int) -> PacketInfo:
    info = PacketInfo(number=number, time=float(pkt.time), length=len(pkt), protocol="Other")

    if Ether in pkt:
        info.src_mac, info.dst_mac = pkt[Ether].src, pkt[Ether].dst

    if ARP in pkt:
        arp = pkt[ARP]
        info.protocol = "ARP"
        info.arp = ArpInfo(
            op=int(arp.op),
            sender_ip=arp.psrc,
            sender_mac=arp.hwsrc,
            target_ip=arp.pdst,
            target_mac=arp.hwdst,
        )
        return info

    if IP in pkt:
        info.src_ip, info.dst_ip = pkt[IP].src, pkt[IP].dst
        info.protocol = "IPv4"
    elif IPv6 in pkt:
        info.src_ip, info.dst_ip = pkt[IPv6].src, pkt[IPv6].dst
        info.protocol = "ICMPv6" if pkt[IPv6].nh == 58 else "IPv6"

    if TCP in pkt:
        tcp = pkt[TCP]
        info.src_port, info.dst_port = int(tcp.sport), int(tcp.dport)
        info.tcp_flags = str(tcp.flags)
        info.protocol = "TCP"
    elif UDP in pkt:
        udp = pkt[UDP]
        info.src_port, info.dst_port = int(udp.sport), int(udp.dport)
        info.protocol = "UDP"
    elif ICMP in pkt:
        info.protocol = "ICMP"

    if DNS in pkt:
        info.dns = _dns_info(pkt[DNS])
        info.protocol = "DNS"

    return info
