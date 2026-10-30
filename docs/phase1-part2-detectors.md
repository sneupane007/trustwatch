# Phase 1 · Part 2: ARP and DNS spoofing detectors

**Owner:** ______________  **Builds on:** Phase 1 Part 1 (the scaffold, already done)
**Source material:** `Attacks_Deck_Detailed.pptx` (slides 3, 4, 6) and `Theory_Why_Attacks_Work.pptx` (slides 3, 4, 6)

## Your goal

Make TrustWatch catch **ARP spoofing** and **DNS spoofing** in a Wireshark capture, the same way it already catches port scans. Then prove it works on real captures from our VirtualBox lab.

When you're done, uploading `backend/samples/mixed.pcapng` shows **three alerts** instead of one, and the dashboard lists all three detectors as **Active**.

---

## 1. What already works

| Piece | Where | What it does |
|---|---|---|
| Upload + dashboard | `frontend/src/` | Drop a `.pcap`/`.pcapng`, see stats, chart, alerts |
| API | `backend/app/main.py` | `POST /api/analyze` runs every detector over the file |
| Engine | `backend/app/engine/engine.py` | Feeds packets one at a time to each detector, collects alerts |
| Packet record | `backend/app/engine/packet.py` | Turns each Scapy packet into a plain `PacketInfo` (you read this, never Scapy) |
| Detector contract | `backend/app/engine/detector.py` | `Detector` base class and the `Alert` fields |
| **Reference detector** | `backend/app/detectors/port_scan.py` | Working example. Copy its pattern. |
| **Your stubs** | `backend/app/detectors/arp_spoof.py`, `dns_spoof.py` | Return no alerts yet; `implemented = False` |
| Sample captures | `backend/samples/` (built by `scripts/make_samples.py`) | Synthetic baseline + each attack + `mixed.pcapng` |
| Tests | `backend/tests/` | `pytest` checks the port scan detector and API |

Setup and run instructions are in the root `README.md`. Get the app running and upload `mixed.pcapng` before you change anything.

---

## 2. How a detector works (read this once)

```python
class MyDetector(Detector):
    id = "my_attack"           # used in alert ids and the API
    name = "My attack"         # shown on the dashboard
    description = "..."        # one sentence, shown under the name
    implemented = True         # flip this when yours works

    def on_packet(self, pkt: PacketInfo) -> list[Alert]:
        ...                    # called once per packet, in capture order
```

The rules (the port scan detector follows all of them):

1. **Return only *new* alerts.** If the same attack keeps going, find your existing `Alert` and update it in place: `alert.add_evidence(pkt)`, and edit `alert.summary` / `alert.details`. One attack = one alert. Phase 2 depends on this, because live mode shows an alert the moment it is returned.
2. **Use packet time (`pkt.time`), never the clock.** Then a recorded file gives the same result as live traffic.
3. **Create alerts with `self.new_alert(...)`**. It fills in `id` and `detector` for you.
4. **Don't import Scapy in a detector.** Everything you need is on `PacketInfo`. If a field is missing, add it in `packet.py` and tell Part 1.

### The `PacketInfo` fields you will use

| Field | Example | Notes |
|---|---|---|
| `pkt.number` | `62` | Same as Wireshark's **No.** column |
| `pkt.time` | `1790863215.0` | Seconds since the epoch |
| `pkt.src_mac`, `pkt.dst_mac` | `"02:00:00:00:00:42"` | Ethernet addresses |
| `pkt.src_ip`, `pkt.dst_ip` | `"10.0.0.1"` | `None` for ARP |
| `pkt.src_port`, `pkt.dst_port` | `53`, `51234` | TCP/UDP only |
| `pkt.arp.op` | `1` request, `2` reply | `pkt.arp` is `None` if not ARP |
| `pkt.arp.sender_ip`, `pkt.arp.sender_mac` | `"10.0.0.1"`, `"02:..:42"` | **The claim**: "this IP is at this MAC" |
| `pkt.arp.target_ip`, `pkt.arp.target_mac` | `"10.0.0.20"` | Who the ARP packet is addressed to |
| `pkt.dns.id` | `15596` (= `0x3cec`) | Query ID; query and response share it |
| `pkt.dns.is_response` | `True` | |
| `pkt.dns.qname` | `"example.com"` | No trailing dot |
| `pkt.dns.answers` | `["10.0.0.66"]` | Only A / AAAA addresses; empty for CNAME-only answers |

---

## 3. Task A: ARP spoofing detector (`arp_spoof.py`)

**From our slides:** *"Track IP to MAC pairs over time. Flag any IP that suddenly maps to a second MAC address."*

### Logic

1. Ignore packets where `pkt.arp is None`.
2. Every ARP packet (request **or** reply) is a claim: `sender_ip` is at `sender_mac`.
3. Skip claims that aren't real: `sender_ip == "0.0.0.0"` (ARP probes) and `sender_mac` of `00:00:00:00:00:00` or `ff:ff:ff:ff:ff:ff`.
4. Remember the **first** MAC seen for each IP, plus the frame number where you saw it.
5. If an IP shows up with a **different** MAC → return a new alert, once per `(ip, new_mac)` pair.
6. Later claims of that same `(ip, new_mac)` pair → `add_evidence` to the existing alert (arpspoof re-sends every ~2 s).
7. If the **original** MAC claims the IP again later (the real gateway answering), that is **not** a new alert.

### Alert to produce

| Field | Value |
|---|---|
| `severity` | `"high"` (it enables a man-in-the-middle) |
| `title` | `"ARP spoofing"` |
| `attacker` | the new MAC, e.g. `"02:00:00:00:00:42"` |
| `victim` | `pkt.arp.target_ip` of the forged packet (the host being lied to) |
| `summary` | e.g. *"10.0.0.1 was claimed by a second MAC address, 02:00:00:00:00:42 (first seen as 02:00:00:00:00:01 in frame #2). 10 forged claims were sent to 10.0.0.20."* (update the count as evidence grows) |
| `wireshark_filter` | `arp.src.proto_ipv4 == 10.0.0.1 && arp.src.hw_mac == 02:00:00:00:00:42` |
| `details` | `{"ip", "original_mac", "original_first_frame", "new_mac", "claims"}` |

Phase 2 Part 2 shows `details` on the alert page, so keep these exact keys.

### Known limitation to mention in the report

"First MAC wins" assumes the capture saw the real owner first. If capture starts mid-attack, the roles flip: the attacker looks original and the real gateway looks new. The alert still fires (two MACs, one IP) but `attacker` is wrong. **Stretch goal:** a `KNOWN_MACS = {"10.0.0.1": "<real gateway MAC>"}` table taken from the baseline capture.

### Cross-check with Wireshark

Wireshark itself flags these packets. Open `samples/mixed.pcapng` and filter `arp.duplicate-address-detected`. It marks the same 10 frames (#62, #74, … #139) your detector should flag.

---

## 4. Task B: DNS spoofing detector (`dns_spoof.py`)

**From our slides:** *"Group responses by query ID and name. Flag conflicting answers, or an answer that differs from a known-good address."*

That is **two checks**, and you need both:

- **Conflicting answers.** The attacker's forged answer and the real answer both arrive. This is our sample capture.
- **Known-good mismatch.** If the attacker is already in the middle (after ARP spoofing), they can **drop** the real answer, so only the forged one arrives and the first check sees nothing.

### Logic

1. Only DNS responses that have answers: `pkt.dns and pkt.dns.is_response and pkt.dns.answers`.
2. Only real DNS: `pkt.src_port == 53`. This skips mDNS (5353) and LLMNR (5355), where query ID is usually `0` and several devices answer at once (instant false positives).
3. Group by `key = (client ip = pkt.dst_ip, client port = pkt.dst_port, dns.id, dns.qname)`.
4. Compare answers as **sets** (`set(pkt.dns.answers)`), so the same addresses in a different order are not a conflict.
5. **Known-good check:** keep a `KNOWN_GOOD = {"example.com": {"203.0.113.10"}, ...}` dict at the top of the file. Start with the three sample sites (see `SITES` in `scripts/make_samples.py`) and add our lab's domains. If a response's addresses aren't all in the known-good set for that name → alert with `reason = "known_good_mismatch"`.
6. **Conflict check:** if a previous response for the same key arrived **within 5 seconds** and had a different answer set → alert with `reason = "conflicting_answers"`.
   - Why 5 s: query IDs are only 16 bits, so the same ID gets reused. A different answer minutes later is normal (e.g. a CDN rotating addresses).
   - Identical duplicates (retransmissions) are not a conflict.
7. One alert per key. Later responses for that key → `add_evidence` and append to `details["responses"]`.

### Alert to produce

| Field | Value |
|---|---|
| `severity` | `"high"` |
| `title` | `"DNS spoofing"` |
| `attacker` | source MAC of the **first** response for that query (the forged answer wins the race, so it usually arrives first; say this in the summary) |
| `victim` | the client IP (`pkt.dst_ip`) |
| `summary` | e.g. *"Two different answers for example.com (query ID 0x3cec): 10.0.0.66 in frame #163 and 203.0.113.10 in frame #164. The first answer wins, so 10.0.0.20 was sent to 10.0.0.66."* |
| `wireshark_filter` | `dns.id == 0x3cec && dns.flags.response == 1` (format the ID with `f"0x{id:04x}"`) |
| `details` | `{"qname", "query_id", "client", "responses": [{"frame", "answers", "src_mac"}], "reason"}` |

### Cross-check with Wireshark

In `samples/mixed.pcapng`, filter `dns.id == 0x3cec`. You'll see the query, the forged answer (frame #163, `10.0.0.66`, from the attacker's MAC `02:00:00:00:00:42`), and the real answer (frame #164, `203.0.113.10`).

---

## 5. Tests to add

Copy these two files into `backend/tests/`. They were checked against a working implementation of the spec above, so if yours follows the spec they will pass. Run them with `cd backend && .venv/bin/python -m pytest`.

<details>
<summary><code>backend/tests/test_arp_spoof.py</code></summary>

```python
import random

from scapy.layers.l2 import ARP, Ether

from app.engine.engine import analyze_file
from scripts.make_samples import (
    ATTACKER_MAC,
    BROADCAST,
    GATEWAY_IP,
    GATEWAY_MAC,
    START,
    VICTIM_IP,
    arp_lookup,
    arp_spoof,
    baseline,
)


def arp_alerts(result):
    return [a for a in result["alerts"] if a["detector"] == "arp_spoof"]


def test_forged_replies_are_flagged_once(capture_file):
    path = capture_file(baseline(START, 40, random.Random(1)) + arp_spoof(START + 10))

    alerts = arp_alerts(analyze_file(path))

    assert len(alerts) == 1
    alert = alerts[0]
    assert alert["severity"] == "high"
    assert alert["attacker"] == ATTACKER_MAC
    assert alert["victim"] == VICTIM_IP
    assert alert["details"]["ip"] == GATEWAY_IP
    assert alert["details"]["original_mac"] == GATEWAY_MAC
    assert alert["packet_count"] == 10  # arp_spoof() sends one forged reply every 2 s for 20 s


def test_normal_arp_is_not_flagged(capture_file):
    path = capture_file(baseline(START, 60, random.Random(1)))

    assert arp_alerts(analyze_file(path)) == []


def test_gratuitous_arp_from_the_same_mac_is_not_flagged(capture_file):
    # Hosts announce their own IP on boot. Same IP, same MAC: nothing suspicious.
    announce = Ether(src=GATEWAY_MAC, dst=BROADCAST) / ARP(
        op=2, psrc=GATEWAY_IP, hwsrc=GATEWAY_MAC, pdst=GATEWAY_IP, hwdst=BROADCAST
    )
    announce.time = START + 5
    path = capture_file(arp_lookup(START) + [announce])

    assert arp_alerts(analyze_file(path)) == []


def test_arp_probe_from_0_0_0_0_is_not_flagged(capture_file):
    # A host checking whether an address is free sends sender IP 0.0.0.0 (RFC 5227).
    probe = Ether(src=ATTACKER_MAC, dst=BROADCAST) / ARP(op=1, psrc="0.0.0.0", hwsrc=ATTACKER_MAC, pdst=GATEWAY_IP)
    probe.time = START + 5
    path = capture_file(arp_lookup(START) + [probe])

    assert arp_alerts(analyze_file(path)) == []
```

</details>

<details>
<summary><code>backend/tests/test_dns_spoof.py</code></summary>

```python
import random

from app.engine.engine import analyze_file
from scripts.make_samples import (
    ATTACKER_IP,
    ATTACKER_MAC,
    SITES,
    START,
    VICTIM_IP,
    baseline,
    dns_answer,
    dns_query,
    dns_spoof,
)


def dns_alerts(result):
    return [a for a in result["alerts"] if a["detector"] == "dns_spoof"]


def test_forged_and_real_answers_are_flagged_once(capture_file):
    path = capture_file(baseline(START, 30, random.Random(1)) + dns_spoof(START + 12, random.Random(3)))

    alerts = dns_alerts(analyze_file(path))

    assert len(alerts) == 1
    alert = alerts[0]
    assert alert["severity"] == "high"
    assert alert["victim"] == VICTIM_IP
    assert alert["attacker"] == ATTACKER_MAC  # the forged answer arrived first
    assert alert["details"]["qname"] == "example.com"
    assert len(alert["details"]["responses"]) == 2


def test_normal_lookups_are_not_flagged(capture_file):
    path = capture_file(baseline(START, 60, random.Random(1)))

    assert dns_alerts(analyze_file(path)) == []


def test_identical_duplicate_answers_are_not_flagged(capture_file):
    name, address = "example.com", SITES["example.com"]
    path = capture_file([
        dns_query(START, name, 4242, 50000),
        dns_answer(START + 0.02, name, address, 4242, 50000),
        dns_answer(START + 0.03, name, address, 4242, 50000),  # retransmission, same answer
    ])

    assert dns_alerts(analyze_file(path)) == []


def test_reused_query_id_much_later_is_not_a_conflict(capture_file):
    # Query IDs are only 16 bits, so they repeat. A different answer minutes later is
    # normal (for example a CDN rotating addresses), not spoofing.
    name = "cdn.example"  # not in the known-good list
    path = capture_file([
        dns_query(START, name, 4242, 50000),
        dns_answer(START + 0.02, name, "203.0.113.50", 4242, 50000),
        dns_query(START + 120, name, 4242, 50000),
        dns_answer(START + 120.02, name, "203.0.113.51", 4242, 50000),
    ])

    assert dns_alerts(analyze_file(path)) == []


def test_answer_that_breaks_the_known_good_list_is_flagged(capture_file):
    # Full man-in-the-middle: the attacker drops the real answer, so only the forged one arrives.
    path = capture_file([
        dns_query(START, "example.com", 4242, 50000),
        dns_answer(START + 0.002, "example.com", ATTACKER_IP, 4242, 50000, src_mac=ATTACKER_MAC),
    ])

    alerts = dns_alerts(analyze_file(path))

    assert len(alerts) == 1
    assert alerts[0]["details"]["reason"] == "known_good_mismatch"
```

</details>

Also update `test_analyze_pcapng_upload` in `tests/test_api.py` to expect all three detectors in the alerts.

---

## 6. Task C: Record real captures in the lab

Synthetic captures prove the logic. Real captures prove it works on our lab traffic. Our proposal's lab: VirtualBox host-only network, Kali attacker, Ubuntu/Windows victim, Wireshark on the victim (the virtual switch doesn't copy other VMs' traffic to a separate monitor unless promiscuous mode is on).

> **Safety:** Only inside the isolated host-only network, only against our own VMs. Never on the campus network or Wi-Fi.

| File to save in `backend/samples/lab/` | How to make it |
|---|---|
| `baseline.pcapng` | ~5 minutes of normal use on the victim: browse, `ping`, look up a few names. No attacks. |
| `arp_spoof.pcapng` | Start capture, then on Kali run `arpspoof` (or ettercap) against the victim and gateway for ~30 s. |
| `dns_spoof.pcapng` | ettercap's `dns_spoof` plugin (or `dnsspoof`) for a lab domain, then look that domain up on the victim. Add that domain's real address to `KNOWN_GOOD`. |
| `port_scan.pcapng` | `nmap -sS <victim-ip>` from Kali. |

Tips:
- Save as **pcapng** (Wireshark's default). Trim long captures with *File → Export Specified Packets* so each file stays under ~10 MB.
- Write the exact commands and IPs you used in `backend/samples/lab/README.md`. The final report needs them.
- Don't record the "unseen" validation capture yet. That's Phase 2 Part 2, and nobody should tune against it.

---

## 7. Task D: Check results and tune

Run every lab capture through the dashboard and fill in this table in `backend/samples/lab/README.md`:

| Capture | Expected | Detected | False alarms | Notes |
|---|---|---|---|---|
| baseline | none | | | |
| arp_spoof | ARP spoofing | | | |
| dns_spoof | DNS spoofing | | | |
| port_scan | Port scan | | | |

If the **port scan** detector fires on the real baseline, tell Part 1. Its thresholds (`window_seconds`, `port_threshold` in `port_scan.py`) are meant to be tuned on our baseline.

---

## 8. Done when

- [ ] `arp_spoof.py` and `dns_spoof.py` have `implemented = True`; the dashboard shows all three as **Active**
- [ ] `samples/mixed.pcapng` shows **3 alerts**: ARP spoofing (high, ~14.9 s), DNS spoofing (high, ~39.9 s), port scan (medium, ~59.9 s)
- [ ] `samples/baseline.pcap` and `samples/lab/baseline.pcapng` show **0 alerts**
- [ ] All tests pass, including the two new test files
- [ ] Pasting each alert's Wireshark filter into Wireshark shows exactly the evidence frames
- [ ] Lab captures + results table committed in `backend/samples/lab/`

## Talk to Part 1 before changing

`engine/detector.py` (the `Alert` fields), `engine/packet.py` (adding fields is fine, renaming is not), and `frontend/src/types.ts`. The frontend and Phase 2 both read those shapes.
