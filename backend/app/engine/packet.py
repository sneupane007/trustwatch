"""Turn tshark's view of a packet into a small, plain record that detectors read.

tshark (Wireshark's command-line version, see tshark.py) decodes every packet.
Detectors only ever see PacketInfo. That keeps them easy to test, and it lets
file mode (Phase 1) and live capture (Phase 2) share exactly the same code.
"""

from __future__ import annotations

from dataclasses import dataclass, field


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
    tcp_flags: str | None = None  # flag letters: "S" = SYN, "SA" = SYN/ACK, "RA" = RST/ACK
    arp: ArpInfo | None = None
    dns: DnsInfo | None = None


# What we ask tshark for, in this order. parse_fields() reads one output line of them.
TSHARK_FIELDS = [
    "frame.number", "frame.time_epoch", "frame.len", "frame.protocols",
    "eth.src", "eth.dst", "ip.src", "ip.dst", "ipv6.src", "ipv6.dst",
    "tcp.srcport", "tcp.dstport", "tcp.flags", "udp.srcport", "udp.dstport",
    "arp.opcode", "arp.src.proto_ipv4", "arp.src.hw_mac", "arp.dst.proto_ipv4", "arp.dst.hw_mac",
    "dns.id", "dns.flags.response", "dns.qry.name", "dns.count.answers", "dns.resp.type", "dns.a", "dns.aaaa",
]

TCP_FLAG_LETTERS = "FSRPAUECN"  # bit 0 = FIN, bit 1 = SYN, ... so 0x012 is "SA"


def parse_fields(line: str) -> PacketInfo:
    """One line of tshark field output -> PacketInfo. Fields with several values are comma-separated."""
    row = dict(zip(TSHARK_FIELDS, line.rstrip("\r\n").split("\t")))

    def all_of(name: str) -> list[str]:
        value = row.get(name, "")
        return value.split(",") if value else []

    def first(name: str) -> str | None:
        # The outer header. ICMP errors quote the packet that caused them, so tshark also
        # reports that inner packet's addresses and ports after the real ones.
        values = all_of(name)
        return values[0] if values else None

    layers = row["frame.protocols"].split(":")
    for i, layer in enumerate(layers):
        if layer in ("icmp", "icmpv6"):
            layers = layers[: i + 1]  # anything after this is the quoted packet
            break

    info = PacketInfo(
        number=int(row["frame.number"]),
        time=float(row["frame.time_epoch"]),
        length=int(row["frame.len"]),
        protocol="Other",
        src_mac=first("eth.src"),
        dst_mac=first("eth.dst"),
    )

    if "arp" in layers:
        info.protocol = "ARP"
        arp = [first(f) for f in ("arp.opcode", "arp.src.proto_ipv4", "arp.src.hw_mac", "arp.dst.proto_ipv4", "arp.dst.hw_mac")]
        if all(arp):  # non-IPv4 ARP has no addresses we can use
            info.arp = ArpInfo(op=int(arp[0]), sender_ip=arp[1], sender_mac=arp[2], target_ip=arp[3], target_mac=arp[4])
        return info

    if "ip" in layers:
        info.src_ip, info.dst_ip = first("ip.src"), first("ip.dst")
        info.protocol = "IPv4"
    elif "ipv6" in layers:
        info.src_ip, info.dst_ip = first("ipv6.src"), first("ipv6.dst")
        info.protocol = "ICMPv6" if "icmpv6" in layers else "IPv6"

    if "tcp" in layers:
        info.src_port, info.dst_port = int(first("tcp.srcport")), int(first("tcp.dstport"))
        bits = int(first("tcp.flags"), 16)
        info.tcp_flags = "".join(letter for i, letter in enumerate(TCP_FLAG_LETTERS) if bits & (1 << i))
        info.protocol = "TCP"
    elif "udp" in layers:
        info.src_port, info.dst_port = int(first("udp.srcport")), int(first("udp.dstport"))
        info.protocol = "UDP"
    elif "icmp" in layers:
        info.protocol = "ICMP"

    if ("dns" in layers or "mdns" in layers) and first("dns.id"):
        info.dns = DnsInfo(
            id=int(first("dns.id"), 16),
            is_response=first("dns.flags.response") in ("True", "1"),  # Wireshark 4.x prints True, 3.x prints 1
            qname=first("dns.qry.name") or "",
            answers=_answer_addresses(all_of),
        )
        info.protocol = "DNS"

    return info


def _answer_addresses(all_of) -> list[str]:
    """A and AAAA addresses from the answer section only.

    tshark lists the records of every section (answers, authority, additional) together,
    in packet order. The first dns.count.answers records are the answers.
    """
    answers_count = int((all_of("dns.count.answers") or ["0"])[0])
    a, aaaa = iter(all_of("dns.a")), iter(all_of("dns.aaaa"))
    answers = []
    for i, rr_type in enumerate(all_of("dns.resp.type")):
        address = next(a, None) if rr_type == "1" else next(aaaa, None) if rr_type == "28" else None
        if address is not None and i < answers_count:
            answers.append(address)
    return answers
