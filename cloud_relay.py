"""
Chaos Key Cloud Relay  v3.0  —  Long-Poll Edition
===================================================
Works on Render free tier. No WebSocket needed.

How it works:
  1. Local bridge polls GET /poll every few seconds to pick up pending jobs
  2. Bridge does the crypto locally, posts result to POST /result
  3. Customer requests wait (long-poll) until the bridge returns a result

No WebSocket = no Render proxy issues.

Env vars:
    BRIDGE_SECRET   — must match launcher.py / ws_bridge.py
    JOB_TIMEOUT     — seconds customer waits for result (default 20)
"""

import asyncio
import json
import logging
import os
import uuid
from datetime import datetime, timezone
from typing import Optional

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel

# ── Config ─────────────────────────────────────────────────────────────────────

BRIDGE_SECRET = os.getenv("BRIDGE_SECRET", "60214a27a9f1ee39361b70b3fa8c98d6")
JOB_TIMEOUT   = float(os.getenv("JOB_TIMEOUT", "20"))

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s [%(levelname)s] %(message)s",
                    datefmt="%Y-%m-%dT%H:%M:%S")
log = logging.getLogger("Relay")

# ── App ────────────────────────────────────────────────────────────────────────

app = FastAPI(title="Chaos Key Relay", version="3.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"],
                   allow_methods=["*"], allow_headers=["*"])

# ── In-memory job queue ────────────────────────────────────────────────────────
#
#  jobs    = { job_id: {"op": str, "payload": dict} }       pending for bridge
#  results = { job_id: dict }                                completed by bridge
#  events  = { job_id: asyncio.Event }                       signals customer
#
jobs:    dict[str, dict] = {}
results: dict[str, dict] = {}
events:  dict[str, asyncio.Event] = {}

# Bridge heartbeat — updated every time bridge polls
bridge_last_seen: Optional[float] = None

def bridge_online() -> bool:
    if bridge_last_seen is None:
        return False
    import time
    return (time.time() - bridge_last_seen) < 30  # offline if no poll in 30s

def require_bridge_secret(request: Request):
    secret = request.headers.get("X-Bridge-Secret", "")
    if secret != BRIDGE_SECRET:
        raise HTTPException(403, "Invalid bridge secret")

def require_relay_token(request: Request):
    token = request.headers.get("X-Relay-Token", "")
    if token != BRIDGE_SECRET:
        raise HTTPException(403, "Invalid relay token")

# ── Bridge endpoints (called by local ws_bridge.py) ───────────────────────────

@app.get("/poll")
async def poll(request: Request):
    """
    Bridge calls this every 2 seconds.
    Returns all pending jobs, clears them from the queue.
    """
    require_bridge_secret(request)

    global bridge_last_seen
    import time
    bridge_last_seen = time.time()

    pending = dict(jobs)
    jobs.clear()

    return {"jobs": pending, "count": len(pending)}


@app.post("/result")
async def post_result(request: Request):
    """
    Bridge posts completed job results here.
    Wakes up the waiting customer request.
    """
    require_bridge_secret(request)

    body = await request.json()
    job_id = body.get("job_id")
    result = body.get("result")

    if not job_id or result is None:
        raise HTTPException(400, "Missing job_id or result")

    results[job_id] = result

    # Wake up the customer who is waiting for this job
    ev = events.get(job_id)
    if ev:
        ev.set()

    return {"ok": True}


@app.get("/bridge_status")
async def bridge_status_endpoint(request: Request):
    require_bridge_secret(request)
    return {"online": bridge_online(), "last_seen": bridge_last_seen}


# ── Helper: submit job and wait for result ─────────────────────────────────────

async def submit_job(op: str, payload: dict) -> dict:
    if not bridge_online():
        raise HTTPException(503, "Bridge offline — run launcher.py on your local machine")

    job_id = str(uuid.uuid4())
    ev     = asyncio.Event()
    events[job_id]          = ev
    jobs[job_id]            = {"op": op, "payload": payload}

    try:
        await asyncio.wait_for(ev.wait(), timeout=JOB_TIMEOUT)
    except asyncio.TimeoutError:
        jobs.pop(job_id, None)
        events.pop(job_id, None)
        raise HTTPException(504, "Bridge timeout — local machine did not respond in time")

    result = results.pop(job_id, None)
    events.pop(job_id, None)

    if result is None:
        raise HTTPException(502, "Bridge returned no result")

    return result


# ── Customer-facing relay endpoints (called by app.py) ────────────────────────

class EncryptRequest(BaseModel):
    plaintext: str

class DecryptRequest(BaseModel):
    ciphertext: str
    nonce: str


@app.get("/relay/status")
async def relay_status(request: Request):
    require_relay_token(request)
    return await submit_job("status", {})


@app.get("/relay/key_info")
async def relay_key_info(request: Request):
    require_relay_token(request)
    return await submit_job("key_info", {})


@app.post("/relay/encrypt")
async def relay_encrypt(body: EncryptRequest, request: Request):
    require_relay_token(request)
    result = await submit_job("encrypt", {"plaintext": body.plaintext})
    if result.get("status", 200) >= 400:
        raise HTTPException(result["status"], result.get("error"))
    return result


@app.post("/relay/decrypt")
async def relay_decrypt(body: DecryptRequest, request: Request):
    require_relay_token(request)
    result = await submit_job("decrypt", {
        "ciphertext": body.ciphertext,
        "nonce":      body.nonce,
    })
    if result.get("status", 200) >= 400:
        raise HTTPException(result["status"], result.get("error"))
    return result


# ── Health ─────────────────────────────────────────────────────────────────────

@app.get("/health")
async def health():
    return {
        "status":        "ok",
        "bridge_online": bridge_online(),
        "last_seen":     bridge_last_seen,
        "timestamp":     datetime.now(timezone.utc).isoformat(),
    }


@app.get("/")
async def root():
    return JSONResponse({
        "service":  "Chaos Key Relay v3.0",
        "bridge":   "online" if bridge_online() else "offline",
        "endpoints": ["/health", "/poll", "/result",
                      "/relay/encrypt", "/relay/decrypt",
                      "/relay/status", "/relay/key_info"],
    })
