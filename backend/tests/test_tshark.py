"""tshark decoding: the cases where reading Wireshark's output needs care."""

from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import ICMP, IP, TCP, UDP, IPerror, UDPerror
from scapy.layers.l2 import Ether

from app.engine.tshark import read_capture


def decode(capture_file, *pkts):
    for i, pkt in enumerate(pkts):
        pkt.time = 1790863200 + i
    return read_capture(capture_file(list(pkts)))


def ether():
    return Ether(src="02:00:00:00:00:14", dst="02:00:00:00:00:01")


def test_icmp_error_reports_the_outer_packet_only(capture_file):
    # A "port unreachable" quotes the packet that caused it, and tshark lists that packet's fields too.
    quoted = IPerror(src="10.0.0.1", dst="10.0.0.20") / UDPerror(sport=53, dport=5000) / DNS(id=7, qr=1, qd=[DNSQR(qname="example.com")])
    [pkt] = decode(capture_file, ether() / IP(src="10.0.0.20", dst="10.0.0.1") / ICMP(type=3, code=3) / quoted)

    assert (pkt.protocol, pkt.src_ip, pkt.dst_ip) == ("ICMP", "10.0.0.20", "10.0.0.1")
    assert (pkt.src_port, pkt.dns) == (None, None)


def test_dns_answers_come_from_the_answer_section_only(capture_file):
    response = DNS(
        id=0x1234,
        qr=1,
        qd=[DNSQR(qname="www.example.com")],
        an=[
            DNSRR(rrname="www.example.com", type="CNAME", rdata="example.com"),
            DNSRR(rrname="example.com", type="A", rdata="203.0.113.10"),
        ],
        ar=[DNSRR(rrname="ns1.example.com", type="A", rdata="198.51.100.53")],  # extra record, not an answer
    )
    [pkt] = decode(capture_file, ether() / IP(src="10.0.0.1", dst="10.0.0.20") / UDP(sport=53, dport=5000) / response)

    assert pkt.protocol == "DNS"
    assert (pkt.dns.id, pkt.dns.is_response, pkt.dns.qname) == (0x1234, True, "www.example.com")
    assert pkt.dns.answers == ["203.0.113.10"]


def test_tcp_flags_use_the_letters_detectors_expect(capture_file):
    flags = ["S", "SA", "RA", "FPA"]
    pkts = decode(capture_file, *(ether() / IP(src="10.0.0.20", dst="10.0.0.1") / TCP(flags=f) for f in flags))

    assert [p.tcp_flags for p in pkts] == flags
