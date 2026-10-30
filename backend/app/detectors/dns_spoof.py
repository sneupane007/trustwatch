"""DNS spoofing detector: Phase 1, Part 2 (teammate).

Instructions: docs/phase1-part2-detectors.md
Reference implementation to copy the pattern from: port_scan.py
"""

from __future__ import annotations

from ..engine.detector import Alert, Detector
from ..engine.packet import PacketInfo


class DnsSpoofDetector(Detector):
    id = "dns_spoof"
    name = "DNS spoofing"
    description = "Two responses to the same DNS query ID give different answers."
    implemented = False  # set to True once on_packet works

    def on_packet(self, pkt: PacketInfo) -> list[Alert]:
        # TODO (Phase 1, Part 2): group DNS responses by (client, query id, name) and
        # return a new alert when two responses for the same query disagree.
        return []
