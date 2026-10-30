"""Runs every detector and the traffic stats over a stream of packets.

The same Engine works for an uploaded file (analyze_file below) and, in Phase 2,
for live capture: feed it packets with process() as they arrive.
"""

from __future__ import annotations

from dataclasses import asdict
from pathlib import Path

from scapy.utils import PcapReader

from ..detectors import ALL_DETECTORS
from .detector import Alert, Detector
from .packet import PacketInfo, to_packet_info
from .stats import TrafficStats


class Engine:
    def __init__(self, detectors: list[Detector] | None = None) -> None:
        self.detectors = detectors if detectors is not None else [cls() for cls in ALL_DETECTORS]
        self.stats = TrafficStats()
        self.alerts: list[Alert] = []

    def process(self, pkt: PacketInfo) -> list[Alert]:
        """Feed one packet. Returns alerts that are new because of it."""
        self.stats.add(pkt)
        new: list[Alert] = []
        for detector in self.detectors:
            new.extend(detector.on_packet(pkt))
        self.alerts.extend(new)
        return new

    def finish(self) -> list[Alert]:
        new: list[Alert] = []
        for detector in self.detectors:
            new.extend(detector.finish())
        self.alerts.extend(new)
        return new

    def result(self) -> dict:
        alerts = sorted(self.alerts, key=lambda a: a.first_time)
        detectors = [
            {**d.info(), "alert_count": sum(a.detector == d.id for a in alerts)}
            for d in self.detectors
        ]
        return {
            **self.stats.to_dict(),
            "alerts": [asdict(a) for a in alerts],
            "detectors": detectors,
        }


def analyze_file(path: str | Path) -> dict:
    """Read a .pcap or .pcapng file and return everything the dashboard shows."""
    engine = Engine()
    with PcapReader(str(path)) as reader:
        for number, pkt in enumerate(reader, start=1):
            engine.process(to_packet_info(pkt, number))
    engine.finish()
    return engine.result()
