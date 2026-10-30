"""ARP spoofing detector: Phase 1, Part 2 (teammate).

Instructions: docs/phase1-part2-detectors.md
Reference implementation to copy the pattern from: port_scan.py
"""

from __future__ import annotations

from ..engine.detector import Alert, Detector
from ..engine.packet import PacketInfo


class ArpSpoofDetector(Detector):
    id = "arp_spoof"
    name = "ARP spoofing"
    description = "One IP address is claimed by two different MAC addresses."
    implemented = False  # set to True once on_packet works

    def on_packet(self, pkt: PacketInfo) -> list[Alert]:
        # TODO (Phase 1, Part 2): remember which MAC each pkt.arp.sender_ip uses and
        # return a new alert the first time an IP shows up with a second MAC.
        return []
