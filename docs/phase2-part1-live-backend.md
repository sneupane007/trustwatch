# Phase 2 · Part 1: Live capture backend

**Owner:** ______________  **Builds on:** all of Phase 1 (upload mode + three detectors)
**Works in parallel with:** Phase 2 Part 2 (live dashboard). Agree on the **API contract in section 3** on day one.

## Your goal

Watch a network interface live, run the **same engine** over packets as they arrive, stream results to the browser every second, and save every session as a `.pcap` you can open in Wireshark.

This closes the loop from our proposal: *"a single tool that can take a packet capture file, or a live capture, and report what it finds."*

---

## 1. What Phase 1 already gives you

Phase 1 was built so live mode needs **no detector changes**:

- `Engine.process(pkt)` takes one packet at a time and returns only alerts that are **new** because of it (`backend/app/engine/engine.py`).
- Detectors update an existing alert in place while an attack continues, so one attack stays one alert.
- Detectors use packet timestamps, so live and recorded traffic behave the same.
- `Engine.result()` returns the exact JSON shape the dashboard already renders.
- The test `test_live_style_feed_returns_the_alert_exactly_once` already feeds packets one by one, the way you will.

Your job is the plumbing around the engine. You don't change the engine itself.

---

## 2. Architecture

```
 network interface ──► Scapy AsyncSniffer (its own thread)
                            │  for each packet:
                            ├──► PcapWriter ──► sessions/<id>/capture.pcap
                            └──► with lock: engine.process(to_packet_info(pkt, n))

 asyncio task, every 1 s:  with lock: engine.result()  ──►  WebSocket /api/live/ws  ──►  browser
                           new alert ids since last tick ──► {"type": "alert"} messages

 on stop: close pcap, save result.json next to it
```

Two decisions keep this simple:

1. **One lock, no queues.** The sniffer thread and the 1-second broadcaster both touch the engine. Wrap `engine.process(...)` and `engine.result()` in the same `threading.Lock`. That's the only thread-safety the engine needs.
2. **Detect new alerts by comparing ids on each tick.** Don't push from the sniffer thread into asyncio. Each second the broadcaster compares the alert ids in the snapshot with the ids it already sent. Anything new gets an `alert` message. Worst-case delay is one second, which is fine for a demo.

**Frame numbers must match Wireshark.** Count packets from 1 in the order you write them to `capture.pcap`. Pass that number to `to_packet_info(pkt, n)`. Then "frame #243" on the dashboard is frame #243 when someone opens the saved file in Wireshark.

---

## 3. API contract (share with Part 2)

All routes live in `backend/app/main.py` (or a new `backend/app/live.py` router). One live session at a time.

| Method & path | Body / response |
|---|---|
| `GET /api/interfaces` | `[{"name": "en0", "description": "Wi-Fi", "ip": "192.168.1.5"}]`. Use `scapy.interfaces.get_working_ifaces()`. |
| `POST /api/live/start` | Body `{"interface": "en0"}` or `{"replay": "mixed.pcapng", "speed": 1.0}` → `{"session_id": "2026-11-20_14-03-11"}`. **409** if a session is running. **403** with a helpful `detail` if capture permission is denied. |
| `POST /api/live/stop` | → `{"session_id": ..., "packets": 1234, "alerts": 2}` |
| `GET /api/live/status` | → `{"running": true, "session_id": ..., "source": "en0", "started_at": 1790863200.0}` |
| `WS /api/live/ws` | Server → browser messages, below |
| `GET /api/sessions` | `[{"id", "source", "started_at", "ended_at", "packets", "alerts"}]`, newest first |
| `GET /api/sessions/{id}` | The saved `result.json` (same shape as `/api/analyze`) |
| `GET /api/sessions/{id}/pcap` | Download `capture.pcap` (`FileResponse`) |

### WebSocket messages

```jsonc
// every second while running; "result" has the SAME shape as POST /api/analyze
{"type": "snapshot", "session_id": "2026-11-20_14-03-11", "source": "en0", "result": { /* AnalysisResult */ }}

// once per alert, the first tick it appears (the UI shows a toast)
{"type": "alert", "alert": { /* Alert */ }}

// when the session ends (stop button, error, or replay finished)
{"type": "stopped", "session_id": "2026-11-20_14-03-11"}

// capture failed (e.g. permission denied mid-session)
{"type": "error", "message": "Permission denied opening en0. Run the backend with sudo (see README)."}
```

When a browser connects mid-session, send a `snapshot` straight away so it doesn't wait a second for the first frame.

---

## 4. Replay mode (build this first)

`POST /api/live/start` with `{"replay": "mixed.pcapng", "speed": 1.0}` reads a file from `backend/samples/` and feeds it through **the same pipeline** as live capture. Between packets it sleeps `(this.time - previous.time) / speed`.

Build it **before** real sniffing:

- **No root needed.** You and Part 2 can develop and test everything without permissions or the lab.
- **Tests.** Replay at `speed=1000` makes the whole pipeline testable in CI-style unit tests.
- **Demo backup.** If the lab misbehaves during the final presentation, replay a recorded attack and the dashboard looks identical.

Use the same `handle_packet(pkt)` function for both sources so there's only one code path to test.

---

## 5. Real capture: things that will bite you

### Permissions
Capturing raw packets needs extra rights:

| OS | What works |
|---|---|
| macOS | `sudo .venv/bin/uvicorn app.main:app --port 8000`. Wireshark's macOS installer can also install **ChmodBPF**, which gives some users capture access without sudo. Check whether yours did by running the backend without sudo first. |
| Linux (lab VMs) | `sudo .venv/bin/uvicorn ...`, or give the venv's python `cap_net_raw,cap_net_admin` with `setcap` |
| Windows | Npcap (installed with Wireshark) and an Administrator terminal |

Catch `PermissionError` / `Scapy_Exception` when starting the sniffer and return **403** with the exact fix in `detail`. The UI shows that text.

### What the monitor can actually see
A switch (real or virtual) only delivers traffic **to and from this machine, plus broadcasts** such as ARP. Our slides make the same point. For the lab demo:

- **Recommended:** run TrustWatch **on the victim VM** (Ubuntu). It sees everything aimed at it: the scan, the forged ARP replies, the forged DNS answers.
- Running it on the host and sniffing the host-only adapter (`vboxnet0`) only works if VirtualBox delivers VM-to-VM traffic to the host. I'm not certain it does, even with promiscuous mode set to "Allow All". Test it in the first week: ping between two VMs while sniffing on the host.

### Performance
Scapy is pure Python and can drop packets on a busy network. For a lab with three VMs it's fine. Use `store=False` on the sniffer so memory doesn't grow. An optional BPF filter (`arp or udp port 53 or tcp`) cuts the load, but then the stats only cover filtered traffic. Say so in the UI if you add it.

### Dependencies
- Uvicorn needs a WebSocket library or `/api/live/ws` won't connect. Add `websockets` to `backend/requirements.txt` (pin the version you install).
- `AsyncSniffer`, `PcapWriter(path, sync=True)` and `get_working_ifaces()` all exist in the pinned Scapy 2.8.0.

### Shutdown
Use FastAPI's `lifespan` to stop the sniffer and close the pcap when the server stops, so `Ctrl+C` never leaves a half-written capture.

---

## 6. Session storage

No database. One folder per session:

```
backend/sessions/2026-11-20_14-03-11/
    capture.pcap     # every packet, in order (frame numbers match the dashboard)
    result.json      # final engine.result() + {"source", "started_at", "ended_at"}
```

Add `backend/sessions/` to `.gitignore`.

---

## 7. Tests to write

1. **Replay end to end** (no root): with `TestClient`, `POST /api/live/start` replaying `mixed.pcapng` at `speed=1000`, open `client.websocket_connect("/api/live/ws")`, read messages until `stopped`. Assert you got at least one `snapshot` and one `alert` per attack.
2. **Live matches file mode:** after the replay, run `analyze_file()` on the saved `capture.pcap`. Same alert count, same evidence frame numbers.
3. **One session at a time:** a second `start` returns 409.
4. **Permission error** becomes a 403 with a helpful message (mock the sniffer to raise `PermissionError`).

---

## 8. Done when

- [ ] Replay mode streams `mixed.pcapng` to the browser and all three alerts appear
- [ ] Live capture on the victim VM shows the scan, ARP spoof and DNS spoof as they happen
- [ ] Every session is saved; `capture.pcap` opens in Wireshark and frame numbers match the alerts
- [ ] `GET /api/sessions` lists past sessions; `/pcap` downloads work
- [ ] Permission problems show a clear fix instead of a crash
- [ ] Tests from section 7 pass, along with every Phase 1 test

## Talk to Part 2 before changing

The section 3 contract. If you add a field, tell them. If you rename one, update `frontend/src/types.ts` together.
