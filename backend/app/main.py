"""HTTP API for the dashboard.

Run from the backend/ folder:  .venv/bin/uvicorn app.main:app --reload --port 8000
"""

from __future__ import annotations

import shutil
import tempfile
from pathlib import Path

from fastapi import FastAPI, HTTPException, UploadFile
from scapy.error import Scapy_Exception

from .detectors import ALL_DETECTORS
from .engine.engine import analyze_file

app = FastAPI(title="TrustWatch API")


@app.get("/api/health")
def health() -> dict:
    return {"status": "ok"}


@app.get("/api/detectors")
def detectors() -> list[dict]:
    return [cls().info() for cls in ALL_DETECTORS]


@app.post("/api/analyze")
def analyze(file: UploadFile) -> dict:
    suffix = Path(file.filename or "").suffix
    with tempfile.NamedTemporaryFile(suffix=suffix) as tmp:
        shutil.copyfileobj(file.file, tmp)
        tmp.flush()
        try:
            result = analyze_file(tmp.name)
        except (Scapy_Exception, EOFError) as exc:
            raise HTTPException(
                status_code=400,
                detail=f"Could not read this file as a .pcap or .pcapng capture ({exc}).",
            ) from exc
    return {"filename": file.filename, **result}
