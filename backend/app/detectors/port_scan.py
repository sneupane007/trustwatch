"""Port scan detector (Phase 1, Part 1).

From our slides: "Count distinct destination ports per source in a sliding
window. Flag any source that crosses a threshold tuned on the baseline."

We count per (attacker, victim) pair so each alert names one victim. The window
uses packet timestamps, not the clock, so a recorded capture gives the same
result it would have given live.
"""

from __future__ import annotations

from collections import Counter, defaultdict, deque

from ..engine.detector import Alert, Detector, ip_filter_field
from ..engine.packet import PacketInfo

Pair = tuple[str, str]  # (attacker ip, victim ip)


class PortScanDetector(Detector):
    id = "port_scan"
    name = "Port scan"
    description = "One source sends SYNs to many different ports on a host within a few seconds."

    window_seconds = 5.0
    port_threshold = 20  # distinct ports inside the window; tune against the baseline capture

    def __init__(self) -> None:
        super().__init__()
        self._window: dict[Pair, deque[PacketInfo]] = defaultdict(deque)
        self._window_ports: dict[Pair, Counter[int]] = defaultdict(Counter)
        self._ports_probed: dict[Pair, set[int]] = defaultdict(set)
        self._open_ports: dict[Pair, set[int]] = defaultdict(set)
        self._alerts: dict[Pair, Alert] = {}

    def on_packet(self, pkt: PacketInfo) -> list[Alert]:
        if pkt.tcp_flags is None or pkt.src_ip is None or pkt.dst_ip is None:
            return []
        syn, ack = "S" in pkt.tcp_flags, "A" in pkt.tcp_flags

        if syn and ack:
            # SYN/ACK travels victim -> attacker and means that port is open.
            pair = (pkt.dst_ip, pkt.src_ip)
            self._open_ports[pair].add(pkt.src_port)
            if pair in self._alerts:
                self._describe(pair)
            return []

        if not syn or ack:
            return []

        pair = (pkt.src_ip, pkt.dst_ip)
        self._ports_probed[pair].add(pkt.dst_port)

        if pair in self._alerts:  # scan already flagged: keep adding evidence
            self._alerts[pair].add_evidence(pkt)
            self._describe(pair)
            return []

        window, ports = self._window[pair], self._window_ports[pair]
        window.append(pkt)
        ports[pkt.dst_port] += 1
        while pkt.time - window[0].time > self.window_seconds:
            old = window.popleft()
            ports[old.dst_port] -= 1
            if ports[old.dst_port] == 0:
                del ports[old.dst_port]

        if len(ports) < self.port_threshold:
            return []

        attacker, victim = pair
        field = ip_filter_field(attacker)
        alert = self.new_alert(
            severity="medium",  # reconnaissance: the step before an attack
            title="Port scan",
            summary="",
            attacker=attacker,
            victim=victim,
            first_time=window[0].time,
            last_time=pkt.time,
            wireshark_filter=(
                f"{field}.src == {attacker} && {field}.dst == {victim} "
                "&& tcp.flags.syn == 1 && tcp.flags.ack == 0"
            ),
        )
        for evidence in window:
            alert.add_evidence(evidence)
        self._alerts[pair] = alert
        del self._window[pair], self._window_ports[pair]  # no longer needed for this pair
        self._describe(pair)
        return [alert]

    def _describe(self, pair: Pair) -> None:
        alert = self._alerts[pair]
        probed = len(self._ports_probed[pair])
        open_ports = sorted(self._open_ports[pair])
        seconds = alert.last_time - alert.first_time
        alert.summary = (
            f"{alert.attacker} sent SYN packets to {probed:,} different ports on "
            f"{alert.victim} in {seconds:.1f} s. "
            + (
                f"Ports that answered SYN/ACK (open): {', '.join(map(str, open_ports))}."
                if open_ports
                else "No port answered SYN/ACK."
            )
        )
        alert.details = {
            "ports_probed": probed,
            "open_ports": open_ports,
            "window_seconds": self.window_seconds,
            "port_threshold": self.port_threshold,
        }
