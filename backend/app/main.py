"""HTTP API for the dashboard.

Run from the backend/ folder:  .venv/bin/uvicorn app.main:app --reload --port 8000
"""

from __future__ import annotations

import shutil
import tempfile
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request, UploadFile
from fastapi.responses import JSONResponse

from .detectors import ALL_DETECTORS
from .engine.engine import analyze_file
from .engine.tshark import TsharkError, TsharkNotFound
from .live import lifespan
from .live import router as live_router

app = FastAPI(title="TrustWatch API", lifespan=lifespan)
app.include_router(live_router)


@app.exception_handler(TsharkNotFound)
def tshark_not_found(request: Request, exc: TsharkNotFound) -> JSONResponse:
    return JSONResponse(status_code=503, content={"detail": str(exc)})


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
        except TsharkError as exc:
            reason = str(exc).replace(tmp.name, file.filename or "upload")  # tshark names the temp file
            raise HTTPException(
                status_code=400,
                detail=f"Could not read this file as a .pcap or .pcapng capture ({reason}).",
            ) from exc
    return {"filename": file.filename, **result}
