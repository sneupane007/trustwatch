"""The contract every attack detector follows.

A detector sees packets one at a time, in capture order, through on_packet().
When it spots an attack it returns a NEW Alert. If the same attack keeps going,
the detector updates that Alert object in place (more evidence, a later
last_time) instead of returning a second one. That way one attack shows up as
one alert, both when reading a file and when watching live traffic.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .packet import PacketInfo

MAX_EVIDENCE = 50  # frame numbers kept per alert; packet_count still counts all of them


@dataclass
class Alert:
    id: str  # unique within one analysis, e.g. "port_scan-1"
    detector: str  # id of the detector that raised it
    severity: str  # "high" | "medium" | "low"
    title: str  # short name, e.g. "Port scan"
    summary: str  # one plain-English sentence for the dashboard
    attacker: str | None  # IP or MAC address of the attacker, if known
    victim: str | None
    first_time: float
    last_time: float
    wireshark_filter: str  # paste into Wireshark's display filter bar to see the evidence
    packets: list[int] = field(default_factory=list)  # evidence frame numbers (first MAX_EVIDENCE)
    packet_count: int = 0
    details: dict = field(default_factory=dict)  # detector-specific numbers

    def add_evidence(self, pkt: PacketInfo) -> None:
        if len(self.packets) < MAX_EVIDENCE:
            self.packets.append(pkt.number)
        self.packet_count += 1
        self.first_time = min(self.first_time, pkt.time)
        self.last_time = max(self.last_time, pkt.time)


class Detector:
    id = ""
    name = ""
    description = ""
    implemented = True  # False shows the detector as "pending" on the dashboard

    def __init__(self) -> None:
        self._alert_count = 0

    def on_packet(self, pkt: PacketInfo) -> list[Alert]:
        """Look at one packet. Return only alerts that are new because of it."""
        raise NotImplementedError

    def finish(self) -> list[Alert]:
        """Called once after the last packet. Override if a check needs the whole capture."""
        return []

    def new_alert(self, **fields) -> Alert:
        self._alert_count += 1
        return Alert(id=f"{self.id}-{self._alert_count}", detector=self.id, **fields)

    def info(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "implemented": self.implemented,
        }


def ip_filter_field(address: str) -> str:
    """Wireshark uses ip.src for IPv4 and ipv6.src for IPv6."""
    return "ipv6" if ":" in address else "ip"
