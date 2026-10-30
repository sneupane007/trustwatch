# Phase 2 · Part 2: Live dashboard, alert explanations, final validation

**Owner:** ______________  **Builds on:** all of Phase 1
**Works in parallel with:** Phase 2 Part 1 (live backend). Its **API contract** (`phase2-part1-live-backend.md`, section 3) is what you build against.

## Your goal

1. Give the dashboard a **Live** mode that updates every second while an attack happens.
2. Make every alert **explain itself** using our presentation, with a one-click Wireshark filter.
3. Add **session history** so past captures can be reopened and downloaded.
4. **Prove the tool works** on a capture it has never seen (proposal week 6), then script the **final demo**.

---

## 1. What Phase 1 already gives you

| Piece | Where | Why it matters to you |
|---|---|---|
| `<Dashboard result={...} />` | `frontend/src/components/Dashboard.tsx` | Renders any `AnalysisResult`. Live snapshots use the **same shape**, so the live view reuses it unchanged. |
| Types | `frontend/src/types.ts` | `Alert`, `DetectorInfo`, `AnalysisResult` |
| API helpers | `frontend/src/api.ts` | Add your new calls here |
| Disabled "Live capture" button | `frontend/src/App.tsx` | Enable it |
| Vite proxy with `ws: true` | `frontend/vite.config.ts` | WebSockets to `/api/live/ws` already go to the backend |
| Colors & dark mode | `frontend/src/styles.css` | Use the CSS variables; never hard-code hex |

**Suggested order:** Task 2 (alert detail) first, because it works with Phase 1 data today. Then Task 1 once Part 1's **replay mode** is up. Replay gives you realistic live data without root or the lab.

---

## 2. Task 1: Live view

New file `frontend/src/components/LiveView.tsx`, plus a simple tab switch in `App.tsx`: **Upload · Live · History**. Plain React state is enough; no router needed.

**Controls**
- Interface picker filled from `GET /api/interfaces`, plus a **"Replay a sample"** option (`mixed.pcapng`) for demos without the lab
- Start / Stop buttons → `POST /api/live/start`, `POST /api/live/stop`
- Status line: `● Recording on en0 · 02:14 elapsed · 312 packets/s` (packets/s = change in `summary.packets` between snapshots)

**WebSocket**
```ts
const scheme = location.protocol === "https:" ? "wss" : "ws";
const socket = new WebSocket(`${scheme}://${location.host}/api/live/ws`);
```
- `snapshot` → `<Dashboard result={message.result} />`, with a **Live** badge
- `alert` → a toast at the top: *"▲ High · ARP spoofing · 02:00:00:00:00:42 → 10.0.0.20"*. Also briefly highlight that alert in the list.
- `stopped` → show "Session saved" with a link to it in History
- `error` → show `message` as-is (it contains the fix, e.g. "run with sudo")
- On close: show "Disconnected, retrying…" and reconnect every 2 s

**When the backend refuses to start** (403 or 409), show the `detail` text from the response. `api.ts` already does this for upload errors; reuse that helper.

---

## 3. Task 2: Alert detail panel

New file `frontend/src/components/AlertDetail.tsx`. Clicking an alert opens a side panel (or a modal on phones) with:

1. **Header:** severity badge, title, attacker → victim, first/last time
2. **Copy Wireshark filter** button: `navigator.clipboard.writeText(alert.wireshark_filter)` and a "Copied" confirmation. Under it: *"In Wireshark, paste into the display filter bar and press Enter. Or jump straight to frame #N with Go → Go to Packet (Cmd/Ctrl + G)."*
3. **Evidence:** the frame numbers in `alert.packets` (first 50) and the total `packet_count`
4. **Details:** `alert.details` as a readable list. Keys per detector:
   - port scan: `ports_probed`, `open_ports`, `window_seconds`, `port_threshold`
   - ARP: `ip`, `original_mac`, `original_first_frame`, `new_mac`, `claims`
   - DNS: `qname`, `query_id`, `client`, `responses[]`, `reason`
5. **"What is this attack?"**: the explanation from our slides, below
6. **"How it's fixed in the real world"**: from the last table of our theory slides

Make it keyboard-friendly: `Esc` closes, focus moves into the panel when it opens and back to the alert when it closes.

### Content from our slides

Create `frontend/src/attackInfo.ts` with this text, copied from `Attacks_Deck_Detailed.pptx` and `Theory_Why_Attacks_Work.pptx`:

```ts
export const ATTACK_INFO: Record<string, {
  layer: string;
  howItWorks: string;
  trustAssumption: string;
  inWireshark: string;
  howWeDetect: string;
  realWorldFix: string;
}> = {
  arp_spoof: {
    layer: "Link / network",
    howItWorks:
      "The attacker sends forged ARP replies claiming the gateway's IP. The victim updates its ARP cache and sends its traffic to the attacker.",
    trustAssumption: "Any reply is believed, even one nobody asked for. Nothing checks who is answering.",
    inWireshark:
      "Filter arp. Look for repeated unsolicited replies (arp.opcode == 2) where one MAC address answers for an IP it should not own.",
    howWeDetect: "Track IP to MAC pairs over time. Flag any IP that suddenly maps to a second MAC address.",
    realWorldFix: "Dynamic ARP Inspection, static ARP entries",
  },
  dns_spoof: {
    layer: "Application, over UDP",
    howItWorks:
      "The attacker answers a DNS query first with a forged reply that reuses the query ID. The victim trusts the first answer it gets.",
    trustAssumption: "The first answer matching the query ID wins. Answers carry no proof of origin.",
    inWireshark:
      "Filter dns. Compare dns.id and the answer records. Two responses to one query with different addresses is the tell.",
    howWeDetect:
      "Group responses by query ID and name. Flag conflicting answers, or an answer that differs from a known-good address.",
    realWorldFix: "DNSSEC, encrypted DNS",
  },
  port_scan: {
    layer: "Transport, TCP",
    howItWorks:
      "The attacker sends SYN packets to many ports and reads the replies: SYN/ACK means open, RST means closed. A SYN scan never finishes the handshake.",
    trustAssumption: "Open and closed ports must answer differently (SYN/ACK vs RST) for TCP to work.",
    inWireshark:
      "Filter tcp.flags.syn == 1 && tcp.flags.ack == 0. Expect a burst of SYNs from one source to many ports within seconds.",
    howWeDetect:
      "Count distinct destination ports per source in a sliding window. Flag any source that crosses a threshold tuned on the baseline.",
    realWorldFix: "Firewall rules, rate limiting, IDS",
  },
};
```

End the panel with the slides' closing idea: *"Each of these attacks works because the protocol trusts by default."*

---

## 4. Task 3: Session history

New file `frontend/src/components/SessionHistory.tsx`:

- List from `GET /api/sessions`: source, start time, duration, packets, alert count (newest first)
- **Open** → `GET /api/sessions/{id}` → `<Dashboard result={...} />`
- **Download .pcap** → plain link to `/api/sessions/{id}/pcap`
- Empty state: *"No live sessions yet. Start one from the Live tab."*

---

## 5. Task 4: Final validation (proposal, week 6)

Our proposal promises to *"run the finished tool against a new capture that mixes normal traffic with one or more of the attacks in an order we have not tuned the tool around."*

1. In the lab, record `backend/samples/lab/unseen_mixed.pcapng` (~5 minutes): normal traffic with all three attacks in a **different order and timing** than `mixed.pcapng`. Write down the exact time each attack started. **Nobody tunes thresholds after seeing this file.**
2. Upload it and also replay it through live mode. Fill in:

| Attack | Started at (your notes) | Detected? | Alert time | Delay | Notes |
|---|---|---|---|---|---|
| ARP spoofing | | | | | |
| DNS spoofing | | | | | |
| Port scan | | | | | |
| False alarms | none expected | | | | |

3. Put the table in the final report and on a slide. A miss or false alarm isn't a failure. Explain why it happened, because that discussion is worth marks.

---

## 6. Task 5: Final demo script (~5 minutes)

| # | Show | Say |
|---|---|---|
| 1 | Lab slide (3 VMs, isolated network) | "Everything runs on our own isolated lab." |
| 2 | Live tab → start capture on the victim | "Same engine as upload mode, now on live packets." |
| 3 | Kali: `nmap -sS <victim>` → port scan alert pops up | "One source, many ports, a few seconds." |
| 4 | Kali: start ARP spoofing → high alert | "One IP, two MAC addresses." |
| 5 | DNS spoof a lab domain → high alert | "Two answers, one query ID: the first answer wins." |
| 6 | Stop → open session in History → download .pcap → open in Wireshark → paste the alert's filter | "Every alert points to the exact packets, so you can verify it yourself." |
| 7 | Upload tab → `unseen_mixed.pcapng` | "And here's the capture we never tuned on." |

**Backup plan (rehearse it):** if the lab fails on the day, use **Replay** with the recorded lab captures. The screens look identical. Also keep screenshots of each step in the slides.

---

## 7. Polish checklist

- [ ] Every screen works in light **and** dark mode (CSS variables only)
- [ ] No horizontal scrolling at phone width (390 px)
- [ ] Loading, empty and error states on Live and History
- [ ] Toasts don't cover the Stop button
- [ ] Severity is never shown by color alone (badge keeps its icon + word)

## 8. Done when

- [ ] Live tab: start, watch alerts arrive within ~1 s, stop. Works with replay **and** a real interface.
- [ ] Clicking any alert opens the detail panel with slide content, details and a working copy-filter button
- [ ] History lists sessions; each opens and downloads its `.pcap`
- [ ] Validation table filled in from `unseen_mixed.pcapng`
- [ ] Demo rehearsed twice, once using the backup plan
- [ ] `npm run build` passes with no type errors

## Talk to Part 1 before changing

Anything in `frontend/src/types.ts` that mirrors the backend, and the WebSocket message shapes.
