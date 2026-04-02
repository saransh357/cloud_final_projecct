"""
WebSocket Relay Server (CLOUD)
================================
Runs in the cloud (Railway / Render / Fly.io / VPS).
Accepts a persistent WebSocket from your local bridge,
then forwards customer HTTP requests through it.

Architecture:
  [customers] → HTTP → [cloud_relay.py] → WebSocket → [ws_bridge.py (local)] → [key]

Install:
    pip install fastapi uvicorn websockets python-dotenv

Run (dev):
    uvicorn cloud_relay:app --host 0.0.0.0 --port 7000

Run (prod):
    uvicorn cloud_relay:app --host 0.0.0.0 --port 7000 --workers 1

Env vars:
    BRIDGE_SECRET   — must match ws_bridge.py --secret
    REQUEST_TIMEOUT — seconds to wait for bridge response (default: 15)
"""

import asyncio
import json
import logging
import os
import secrets
import time
import uuid
from datetime import datetime, timezone
from typing import Optional

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel

# ── Config ─────────────────────────────────────────────────────────────────────

BRIDGE_SECRET   = os.getenv("BRIDGE_SECRET", "")
REQUEST_TIMEOUT = float(os.getenv("REQUEST_TIMEOUT", "15"))

if not BRIDGE_SECRET:
    BRIDGE_SECRET = secrets.token_urlsafe(32)
    print(f"[WARN] BRIDGE_SECRET not set — using random: {BRIDGE_SECRET}")
    print("       Set the same value in ws_bridge.py --secret\n")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S"
)
log = logging.getLogger("CloudRelay")

# ── App ────────────────────────────────────────────────────────────────────────

app = FastAPI(title="Chaos Key Cloud Relay", version="2.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Bridge connection manager ──────────────────────────────────────────────────

class BridgeManager:
    """
    Manages the single persistent WebSocket from the local bridge.
    Multiplexes many concurrent HTTP requests over it using request_id correlation.
    """

    def __init__(self):
        self.ws:         Optional[WebSocket] = None
        self.pending:    dict[str, asyncio.Future] = {}  # request_id → Future
        self._send_lock  = asyncio.Lock()
        self.connected   = False
        self.connected_at: Optional[str] = None
        self.key_bits:   Optional[int] = None
        self.req_count   = 0

    async def connect(self, ws: WebSocket):
        if self.connected:
            log.warning("New bridge connection replacing existing one")
            await self.disconnect_current()
        self.ws          = ws
        self.connected   = True
        self.connected_at = datetime.now(timezone.utc).isoformat()
        log.info("Bridge connected ✓")

    async def disconnect_current(self):
        if self.ws:
            try:
                await self.ws.close()
            except Exception:
                pass
        self._fail_all_pending("Bridge disconnected")
        self.ws        = None
        self.connected = False
        log.info("Bridge disconnected")

    def _fail_all_pending(self, reason: str):
        for fut in self.pending.values():
            if not fut.done():
                fut.set_exception(RuntimeError(reason))
        self.pending.clear()

    async def send_request(self, op: str, payload: dict) -> dict:
        """Send a request to the local bridge and await its response."""
        if not self.connected or not self.ws:
            raise HTTPException(503, "Bridge offline — local machine not connected")

        request_id          = str(uuid.uuid4())
        payload["request_id"] = request_id
        payload["op"]         = op

        loop = asyncio.get_event_loop()
        fut  = loop.create_future()
        self.pending[request_id] = fut

        msg = json.dumps({"type": "request", "payload": payload})

        try:
            async with self._send_lock:
                await self.ws.send_text(msg)
            self.req_count += 1

            result = await asyncio.wait_for(fut, timeout=REQUEST_TIMEOUT)
            return result

        except asyncio.TimeoutError:
            self.pending.pop(request_id, None)
            raise HTTPException(504, "Bridge timeout — local machine did not respond")
        except Exception as e:
            self.pending.pop(request_id, None)
            raise HTTPException(502, f"Bridge error: {e}")

    def resolve_response(self, request_id: str, payload: dict):
        """Called when a response arrives from the bridge."""
        fut = self.pending.pop(request_id, None)
        if fut and not fut.done():
            fut.set_result(payload)

    async def receive_loop(self, ws: WebSocket):
        """Read messages from the bridge WebSocket continuously."""
        try:
            async for raw in ws.iter_text():
                try:
                    msg = json.loads(raw)
                except json.JSONDecodeError:
                    log.warning(f"Invalid JSON from bridge: {raw[:80]}")
                    continue

                msg_type = msg.get("type", "")

                if msg_type == "bridge_hello":
                    self.key_bits = msg.get("key_bits")
                    log.info(f"Bridge hello — key_bits={self.key_bits}")
                    await ws.send_text(json.dumps({"type": "relay_ack"}))

                elif msg_type == "response":
                    request_id = msg.get("request_id")
                    payload    = msg.get("payload", {})
                    if request_id:
                        self.resolve_response(request_id, payload)

                elif msg_type == "pong":
                    pass  # keepalive

                else:
                    log.debug(f"Unknown bridge message type: {msg_type}")

        except WebSocketDisconnect:
            pass
        except Exception as e:
            log.error(f"Bridge receive error: {e}")
        finally:
            await self.disconnect_current()


bridge = BridgeManager()

# ── WebSocket endpoint (for local bridge) ──────────────────────────────────────

@app.websocket("/bridge")
async def websocket_bridge(ws: WebSocket):
    """
    Persistent WebSocket for the local ws_bridge.py to connect to.
    Authenticated via X-Bridge-Secret header.
    """
    secret = ws.headers.get("X-Bridge-Secret", "")
    if BRIDGE_SECRET and secret != BRIDGE_SECRET:
        await ws.close(code=4003, reason="Invalid bridge secret")
        log.warning("Bridge connection rejected — invalid secret")
        return

    await ws.accept()
    await bridge.connect(ws)

    try:
        await bridge.receive_loop(ws)
    finally:
        if bridge.ws is ws:
            await bridge.disconnect_current()

# ── HTTP endpoints (for customers via app.py) ──────────────────────────────────

class EncryptRequest(BaseModel):
    plaintext: str

class DecryptRequest(BaseModel):
    ciphertext: str
    nonce:      str

def relay_headers(request: Request):
    """Pass-through auth — app.py already validated the customer key."""
    # app.py sets X-Relay-Token when calling us
    token = request.headers.get("X-Relay-Token", "")
    if BRIDGE_SECRET and token != BRIDGE_SECRET:
        raise HTTPException(403, "Invalid relay token")


@app.get("/relay/status")
async def relay_status(request: Request, _=Depends(relay_headers)):
    result = await bridge.send_request("status", {})
    return result


@app.get("/relay/key_info")
async def relay_key_info(request: Request, _=Depends(relay_headers)):
    result = await bridge.send_request("key_info", {})
    return result


@app.post("/relay/encrypt")
async def relay_encrypt(body: EncryptRequest, request: Request, _=Depends(relay_headers)):
    result = await bridge.send_request("encrypt", {"plaintext": body.plaintext})
    if result.get("status", 200) >= 400:
        raise HTTPException(result["status"], result.get("error"))
    return result


@app.post("/relay/decrypt")
async def relay_decrypt(body: DecryptRequest, request: Request, _=Depends(relay_headers)):
    result = await bridge.send_request("decrypt", {
        "ciphertext": body.ciphertext,
        "nonce":      body.nonce,
    })
    if result.get("status", 200) >= 400:
        raise HTTPException(result["status"], result.get("error"))
    return result


# ── Health & metrics ───────────────────────────────────────────────────────────

@app.get("/health")
async def health():
    return {
        "status":       "ok",
        "bridge_online": bridge.connected,
        "key_bits":      bridge.key_bits,
        "requests_proxied": bridge.req_count,
        "connected_at":  bridge.connected_at,
        "timestamp":     datetime.now(timezone.utc).isoformat(),
    }


@app.get("/")
async def root():
    return JSONResponse({
        "service":   "Chaos Key Cloud Relay",
        "version":   "2.0",
        "endpoints": ["/health", "/relay/status", "/relay/key_info",
                      "/relay/encrypt", "/relay/decrypt"],
        "websocket": "/bridge  (local bridge connects here)"
    })