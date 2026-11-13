"""Live mode (Phase 2, Part 1): run the engine on packets as they arrive.

One session at a time. A background thread feeds packets to Session.handle_packet(),
from a network interface or from a sample file (replay mode). tshark decodes both.
Each WebSocket client gets a snapshot every second. The feeding thread and the
WebSocket loops share the engine through one lock.

Every session is saved to sessions/<id>/: capture.pcap (frame numbers match the
dashboard) and result.json (the final result).

API contract: docs/phase2-part1-live-backend.md, section 3.
"""

from __future__ import annotations

import asyncio
import json
import shutil
import sys
import threading
import time
from collections.abc import Callable
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path

from fastapi import APIRouter, FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from .engine import tshark
from .engine.engine import Engine
from .engine.packet import PacketInfo

BACKEND_DIR = Path(__file__).resolve().parent.parent
SAMPLES_DIR = BACKEND_DIR / "samples"
SESSIONS_DIR = BACKEND_DIR / "sessions"

router = APIRouter()


class Session:
    def __init__(self, session_id: str, folder: Path, source: str, feed: Callable[[Session], None]) -> None:
        self.id, self.folder, self.source = session_id, folder, source
        self.pcap = folder / "capture.pcap"
        self.started_at = time.time()
        self.engine = Engine()
        self.lock = threading.Lock()  # guards engine and packets
        self.packets = 0
        self.stop_requested = threading.Event()
        self.error: str | None = None
        self.ended_at: float | None = None
        self._thread = threading.Thread(target=self._run, args=(feed,), name=f"live-{self.id}", daemon=True)
        self._thread.start()

    @property
    def running(self) -> bool:
        return self.ended_at is None

    def handle_packet(self, pkt: PacketInfo) -> None:
        with self.lock:
            self.packets += 1
            self.engine.process(pkt)  # pkt.number is tshark's frame number, the same as in capture.pcap

    def snapshot(self) -> dict:
        with self.lock:
            return self.engine.result()

    def stop(self) -> dict:
        self.stop_requested.set()
        self._thread.join()
        return {"session_id": self.id, "packets": self.packets, "alerts": len(self.engine.alerts)}

    def _run(self, feed: Callable[[Session], None]) -> None:
        try:
            feed(self)
        except Exception as exc:  # anything uncaught would leave the session stuck as "running"
            self.error = f"Capture stopped: {exc}"
        self.stop_requested.set()  # also ends _capture's stop watcher when a capture failed by itself
        with self.lock:
            self.engine.finish()
            ended_at = time.time()
            saved = {
                **self.engine.result(),
                "source": self.source,
                "started_at": self.started_at,
                "ended_at": ended_at,
            }
            (self.folder / "result.json").write_text(json.dumps(saved))
            self.ended_at = ended_at  # set last, so "stopped" only goes out once result.json exists


def _replay(session: Session, sample: Path, packets: list[PacketInfo], speed: float) -> None:
    """Feed a decoded capture at its recorded pace, `speed` times faster."""
    try:
        previous: float | None = None
        for pkt in packets:
            delay = 0.0 if previous is None else (pkt.time - previous) / speed
            previous = pkt.time
            if session.stop_requested.wait(max(delay, 0.0)):
                return
            session.handle_packet(pkt)
    finally:
        tshark.copy_frames(sample, session.pcap, session.packets)  # exactly the frames that were replayed


def _capture(session: Session, capture: tshark.LiveCapture) -> None:
    """Feed packets from a running tshark until Stop is pressed or the capture fails."""

    def stop_when_asked() -> None:
        session.stop_requested.wait()
        capture.stop()

    threading.Thread(target=stop_when_asked, daemon=True).start()
    for pkt in capture.packets():
        session.handle_packet(pkt)


def _start_capture(name: str, pcap: Path) -> tshark.LiveCapture:
    """Start tshark here, not in the session thread, so a permission problem becomes a 403."""
    if name not in {iface["name"] for iface in tshark.interfaces()}:
        raise HTTPException(status_code=404, detail=f"No network interface named {name!r}.")
    try:
        return tshark.LiveCapture(name, pcap)
    except tshark.TsharkError as exc:
        if "permission" in str(exc).lower():
            raise HTTPException(status_code=403, detail=_permission_help(name)) from exc
        raise HTTPException(status_code=400, detail=f"Could not start capturing on {name} ({exc}).") from exc


def _permission_help(name: str) -> str:
    sudo = "restart the backend with sudo: sudo .venv/bin/uvicorn app.main:app --port 8000"
    if sys.platform == "win32":
        fix = "Install Npcap (it comes with Wireshark) and start the backend from an Administrator terminal."
    elif sys.platform == "darwin":
        fix = f"Install ChmodBPF from the Wireshark installer, or {sudo}"
    else:
        fix = (
            "Let your user capture with sudo dpkg-reconfigure wireshark-common (answer Yes), then "
            f"sudo usermod -aG wireshark $USER and log in again. Or {sudo}"
        )
    return f"Permission denied capturing on {name}. {fix}"


def _decode_sample(name: str) -> tuple[Path, list[PacketInfo]]:
    path = _file_inside(SAMPLES_DIR, name, f"No sample capture named {name!r} in backend/samples/.")
    try:
        return path, tshark.read_capture(path)
    except tshark.TsharkError as exc:
        raise HTTPException(
            status_code=400,
            detail=f"Could not read {name} as a .pcap or .pcapng capture ({exc}).",
        ) from exc


def _new_session_folder() -> tuple[str, Path]:
    """Name a session by its start time, adding _2, _3... if two start in the same second."""
    base = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    session_id, n = base, 1
    while True:
        try:
            (SESSIONS_DIR / session_id).mkdir(parents=True)
            return session_id, SESSIONS_DIR / session_id
        except FileExistsError:
            n += 1
            session_id = f"{base}_{n}"


def _file_inside(folder: Path, relative: str, missing: str) -> Path:
    """Resolve a path from a request, refusing anything outside `folder` (e.g. "../../etc/passwd")."""
    path = (folder / relative).resolve()
    if not path.is_relative_to(folder.resolve()) or not path.is_file():
        raise HTTPException(status_code=404, detail=missing)
    return path


_current: Session | None = None  # the running session, or the last one
_start_lock = threading.Lock()  # start requests can arrive on parallel threads


@asynccontextmanager
async def lifespan(app: FastAPI):
    yield
    if _current is not None:  # Ctrl+C: finish capture.pcap and result.json instead of leaving them half-written
        _current.stop()


@router.get("/api/interfaces")
def interfaces() -> list[dict]:
    return tshark.interfaces()


class StartRequest(BaseModel):
    interface: str | None = None  # e.g. "en0", from GET /api/interfaces
    replay: str | None = None  # a capture under backend/samples/, e.g. "mixed.pcapng" or "lab/arp_spoof.pcapng"
    speed: float = Field(1.0, gt=0)  # replay only


@router.post("/api/live/start")
def start(request: StartRequest) -> dict:
    global _current
    with _start_lock:
        if _current is not None and _current.running:
            raise HTTPException(
                status_code=409,
                detail=f"A live session is already running ({_current.source}). Stop it first.",
            )
        if (request.interface is None) == (request.replay is None):
            raise HTTPException(
                status_code=400,
                detail='Send either {"interface": "en0"} or {"replay": "mixed.pcapng"}.',
            )
        if request.interface is not None:
            session_id, folder = _new_session_folder()  # tshark writes capture.pcap straight into it
            try:
                capture = _start_capture(request.interface, folder / "capture.pcap")
            except Exception:
                shutil.rmtree(folder)  # nothing was captured
                raise
            session = Session(session_id, folder, request.interface, lambda s: _capture(s, capture))
        else:
            sample, packets = _decode_sample(request.replay)
            session_id, folder = _new_session_folder()
            session = Session(
                session_id, folder, f"{request.replay} (replay)", lambda s: _replay(s, sample, packets, request.speed)
            )
        _current = session
    return {"session_id": session.id}


@router.post("/api/live/stop")
def stop() -> dict:
    if _current is None:
        raise HTTPException(status_code=409, detail="No live session has been started.")
    return _current.stop()  # also fine if a replay already reached the end by itself


@router.get("/api/live/status")
def status() -> dict:
    session = _current
    if session is None or not session.running:
        return {"running": False, "session_id": None, "source": None, "started_at": None}
    return {"running": True, "session_id": session.id, "source": session.source, "started_at": session.started_at}


@router.websocket("/api/live/ws")
async def live_ws(websocket: WebSocket) -> None:
    """Every second: a "snapshot", an "alert" per new alert, then "stopped" when the session ends.

    Follows the running session, or one that started after this client connected
    (a fast replay can start and finish between two ticks).
    """
    await websocket.accept()
    connected_at = time.time()
    following: Session | None = None
    sent: set[str] | None = None  # alert ids this client has been told about
    done = False
    try:
        while True:
            session = _current
            if session is not None and session is not following and (
                session.running or session.started_at >= connected_at
            ):
                following, sent, done = session, None, False

            if following is not None and not done:
                ended = not following.running  # read before the snapshot, so the last snapshot is final
                result = following.snapshot()
                await websocket.send_json(
                    {"type": "snapshot", "session_id": following.id, "source": following.source, "result": result}
                )
                if sent is None:
                    # Alerts raised before this client connected are in the snapshot but get no
                    # "alert" message, so a reconnecting browser isn't flooded with toasts.
                    joined_late = following.started_at < connected_at
                    sent = {a["id"] for a in result["alerts"]} if joined_late else set()
                for alert in result["alerts"]:
                    if alert["id"] not in sent:
                        sent.add(alert["id"])
                        await websocket.send_json({"type": "alert", "alert": alert})
                if ended:
                    if following.error:
                        await websocket.send_json({"type": "error", "message": following.error})
                    await websocket.send_json({"type": "stopped", "session_id": following.id})
                    done = True

            if await _closed_within(websocket, seconds=1.0):
                return
    except WebSocketDisconnect:
        return


async def _closed_within(websocket: WebSocket, seconds: float) -> bool:
    """Wait up to `seconds`. True if the browser closed the connection meanwhile."""
    try:
        message = await asyncio.wait_for(websocket.receive(), timeout=seconds)
    except TimeoutError:
        return False
    return message["type"] == "websocket.disconnect"


@router.get("/api/sessions")
def sessions() -> list[dict]:
    """Finished sessions, newest first."""
    found = []
    for path in SESSIONS_DIR.glob("*/result.json"):
        saved = json.loads(path.read_text())
        found.append({
            "id": path.parent.name,
            "source": saved["source"],
            "started_at": saved["started_at"],
            "ended_at": saved["ended_at"],
            "packets": saved["summary"]["packets"],
            "alerts": len(saved["alerts"]),
        })
    return sorted(found, key=lambda s: s["started_at"], reverse=True)


@router.get("/api/sessions/{session_id}")
def session_result(session_id: str) -> dict:
    path = _file_inside(SESSIONS_DIR, f"{session_id}/result.json", f"No saved session {session_id!r}.")
    return json.loads(path.read_text())


@router.get("/api/sessions/{session_id}/pcap")
def session_pcap(session_id: str) -> FileResponse:
    path = _file_inside(SESSIONS_DIR, f"{session_id}/capture.pcap", f"No saved session {session_id!r}.")
    return FileResponse(path, media_type="application/vnd.tcpdump.pcap", filename=f"trustwatch_{session_id}.pcap")
