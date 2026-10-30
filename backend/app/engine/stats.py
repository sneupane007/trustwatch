"""Traffic numbers for the dashboard: totals, protocol mix, top talkers, timeline."""

from __future__ import annotations

import math
from collections import Counter

from .packet import PacketInfo

MAX_TIMELINE_POINTS = 120
TOP_TALKERS = 5


class TrafficStats:
    def __init__(self) -> None:
        self.packets = 0
        self.bytes = 0
        self.start: float | None = None
        self.end: float | None = None
        self.protocols: Counter[str] = Counter()
        self.talker_packets: Counter[str] = Counter()
        self.talker_bytes: Counter[str] = Counter()
        self.per_second: Counter[int] = Counter()

    def add(self, pkt: PacketInfo) -> None:
        self.packets += 1
        self.bytes += pkt.length
        self.start = pkt.time if self.start is None else min(self.start, pkt.time)
        self.end = pkt.time if self.end is None else max(self.end, pkt.time)
        self.protocols[pkt.protocol] += 1
        self.per_second[int(pkt.time)] += 1

        source = pkt.src_ip or (pkt.arp.sender_ip if pkt.arp else None)
        if source:
            self.talker_packets[source] += 1
            self.talker_bytes[source] += pkt.length

    def to_dict(self) -> dict:
        duration = (self.end - self.start) if self.start is not None else 0.0
        return {
            "summary": {
                "packets": self.packets,
                "bytes": self.bytes,
                "start": self.start,
                "end": self.end,
                "duration": duration,
            },
            "protocols": [{"name": n, "packets": c} for n, c in self.protocols.most_common()],
            "top_talkers": [
                {"ip": ip, "packets": c, "bytes": self.talker_bytes[ip]}
                for ip, c in self.talker_packets.most_common(TOP_TALKERS)
            ],
            "timeline": self._timeline(),
        }

    def _timeline(self) -> dict:
        """Packets per time bucket, with empty buckets kept so quiet gaps show on the chart."""
        if self.start is None or self.end is None:
            return {"bucket_seconds": 1, "points": []}
        first, last = int(self.start), int(self.end)
        bucket = max(1, math.ceil((last - first + 1) / MAX_TIMELINE_POINTS))
        counts = [0] * ((last - first) // bucket + 1)
        for second, count in self.per_second.items():
            counts[(second - first) // bucket] += count
        return {
            "bucket_seconds": bucket,
            "points": [{"t": first + i * bucket, "packets": c} for i, c in enumerate(counts)],
        }
