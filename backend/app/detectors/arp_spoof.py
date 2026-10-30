"""ARP spoofing detector (Phase 1, Part 2).

From our slides: "Track IP to MAC pairs over time. Flag any IP that suddenly
maps to a second MAC address."

Every ARP packet, request or reply, claims "sender_ip is at sender_mac". The
first MAC we see for an IP is taken as the real owner. Known limitation: if the
capture starts mid-attack, the attacker's MAC is seen first and the roles flip.
The alert still fires (two MACs, one IP) but `attacker` names the real owner.
"""

from __future__ import annotations

from ..engine.detector import Alert, Detector
from ..engine.packet import PacketInfo

NOT_A_CLAIM_MACS = {"00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"}

Claim = tuple[str, str]  # (ip, mac that claimed it)


class ArpSpoofDetector(Detector):
    id = "arp_spoof"
    name = "ARP spoofing"
    description = "One IP address is claimed by two different MAC addresses."

    def __init__(self) -> None:
        super().__init__()
        self._first_seen: dict[str, tuple[str, int]] = {}  # ip -> (first mac, frame number)
        self._alerts: dict[Claim, Alert] = {}

    def on_packet(self, pkt: PacketInfo) -> list[Alert]:
        if pkt.arp is None:
            return []
        ip, mac = pkt.arp.sender_ip, pkt.arp.sender_mac.lower()
        if ip == "0.0.0.0" or mac in NOT_A_CLAIM_MACS:  # ARP probes and malformed claims
            return []

        if ip not in self._first_seen:
            self._first_seen[ip] = (mac, pkt.number)
            return []
        original_mac, _ = self._first_seen[ip]
        if mac == original_mac:  # the real owner answering again is normal
            return []

        claim = (ip, mac)
        if claim in self._alerts:  # arpspoof re-sends every few seconds: same attack
            self._alerts[claim].add_evidence(pkt)
            self._describe(claim)
            return []

        alert = self.new_alert(
            severity="high",  # enables a man-in-the-middle
            title="ARP spoofing",
            summary="",
            attacker=mac,
            victim=pkt.arp.target_ip,
            first_time=pkt.time,
            last_time=pkt.time,
            wireshark_filter=f"arp.src.proto_ipv4 == {ip} && arp.src.hw_mac == {mac}",
        )
        alert.add_evidence(pkt)
        self._alerts[claim] = alert
        self._describe(claim)
        return [alert]

    def _describe(self, claim: Claim) -> None:
        alert = self._alerts[claim]
        ip, new_mac = claim
        original_mac, original_frame = self._first_seen[ip]
        claims = alert.packet_count
        alert.summary = (
            f"{ip} was claimed by a second MAC address, {new_mac} (first seen as "
            f"{original_mac} in frame #{original_frame}). "
            + (f"{claims} forged claims were" if claims != 1 else "1 forged claim was")
            + f" sent to {alert.victim}."
        )
        alert.details = {
            "ip": ip,
            "original_mac": original_mac,
            "original_first_frame": original_frame,
            "new_mac": new_mac,
            "claims": claims,
        }
