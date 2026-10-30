"""DNS spoofing detector (Phase 1, Part 2).

From our slides: "Group responses by query ID and name. Flag conflicting
answers, or an answer that differs from a known-good address."

Two checks, because each misses a case the other catches:
- Conflicting answers: the forged answer and the real one both arrive.
- Known-good mismatch: an attacker already in the middle (after ARP spoofing)
  can drop the real answer, so only the forged one arrives.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..engine.detector import Alert, Detector
from ..engine.packet import PacketInfo

# Addresses each name is allowed to resolve to. The example.* entries match SITES
# in scripts/make_samples.py; add our lab's domains after recording them.
KNOWN_GOOD: dict[str, set[str]] = {
    "example.com": {"203.0.113.10"},
    "example.org": {"203.0.113.20"},
    "example.net": {"203.0.113.30"},
}

Key = tuple[str, int, int, str]  # (client ip, client port, query id, qname)


@dataclass
class Response:
    frame: int
    time: float
    answers: frozenset[str]
    src_mac: str | None


class DnsSpoofDetector(Detector):
    id = "dns_spoof"
    name = "DNS spoofing"
    description = "A DNS answer conflicts with another answer to the same query, or with a known-good address."

    # Query IDs are only 16 bits and get reused; a different answer minutes later is normal.
    conflict_window_seconds = 5.0

    def __init__(self) -> None:
        super().__init__()
        self._recent: dict[Key, list[Response]] = {}
        self._responses: dict[Key, list[Response]] = {}  # every response for a flagged key
        self._alerts: dict[Key, Alert] = {}

    def on_packet(self, pkt: PacketInfo) -> list[Alert]:
        dns = pkt.dns
        if not (dns and dns.is_response and dns.answers):
            return []
        if pkt.src_port != 53 or pkt.dst_ip is None or pkt.dst_port is None:
            return []  # skips mDNS (5353) and LLMNR (5355), where several devices answer at once

        key = (pkt.dst_ip, pkt.dst_port, dns.id, dns.qname)
        response = Response(pkt.number, pkt.time, frozenset(dns.answers), pkt.src_mac)

        if key in self._alerts:  # already flagged: keep adding evidence
            self._responses[key].append(response)
            self._alerts[key].add_evidence(pkt)
            self._describe(key)
            return []

        recent = [
            r for r in self._recent.get(key, [])
            if pkt.time - r.time <= self.conflict_window_seconds
        ]
        conflict = any(r.answers != response.answers for r in recent)
        known_good = KNOWN_GOOD.get(dns.qname)
        mismatch = known_good is not None and not response.answers <= known_good
        if not (conflict or mismatch):
            self._recent[key] = recent + [response]
            return []

        self._recent.pop(key, None)
        self._responses[key] = recent + [response]
        alert = self.new_alert(
            severity="high",
            title="DNS spoofing",
            summary="",
            attacker=self._responses[key][0].src_mac,  # the forged answer usually wins the race
            victim=pkt.dst_ip,
            first_time=pkt.time,
            last_time=pkt.time,
            wireshark_filter=f"dns.id == 0x{dns.id:04x} && dns.flags.response == 1",
        )
        for r in recent:
            alert.packets.append(r.frame)
            alert.packet_count += 1
            alert.first_time = min(alert.first_time, r.time)
        alert.add_evidence(pkt)
        self._alerts[key] = alert
        self._describe(key)
        return [alert]

    def _describe(self, key: Key) -> None:
        alert = self._alerts[key]
        client, _, query_id, qname = key
        responses = self._responses[key]

        # Each distinct answer set, with the frame it first appeared in.
        distinct: dict[frozenset[str], int] = {}
        for r in responses:
            distinct.setdefault(r.answers, r.frame)
        winner = ", ".join(sorted(responses[0].answers))
        query = f"{qname} (query ID 0x{query_id:04x})"

        if len(distinct) > 1:
            reason = "conflicting_answers"
            listed = [f"{', '.join(sorted(a))} in frame #{f}" for a, f in distinct.items()]
            count = "Two" if len(listed) == 2 else str(len(listed))
            alert.summary = (
                f"{count} different answers for {query}: {_join(listed)}. "
                f"The first answer wins, so {client} was sent to {winner}."
            )
        else:
            reason = "known_good_mismatch"
            expected = ", ".join(sorted(KNOWN_GOOD[qname]))
            alert.summary = (
                f"{query} was answered with {winner} in frame #{responses[0].frame}, "
                f"not its known-good address {expected}. {client} was sent to {winner}."
            )

        alert.details = {
            "qname": qname,
            "query_id": query_id,
            "client": client,
            "responses": [
                {"frame": r.frame, "answers": sorted(r.answers), "src_mac": r.src_mac}
                for r in responses
            ],
            "reason": reason,
        }


def _join(items: list[str]) -> str:
    return items[0] if len(items) == 1 else ", ".join(items[:-1]) + " and " + items[-1]
