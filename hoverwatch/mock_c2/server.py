"""
Refog Mock C2 Server (Hoverwatch / Snoopza)
===========================================
Simulates the Refog stalkerware C2 backend based on reverse-engineered protocol.

Version 2.0.0 — synced with hoverwatch_analysis.md v3 findings:
  - Multipart/form-data exfil format (NOT protobuf — Apache HttpClient)
  - Multi-brand support: HWA / HWA_TST / SNPA
  - 3-domain rotation in registration response
  - Realistic HTTP error codes (401, 403, 409, 410, 413)
  - Kill switch armed via /admin/kill triggers HTTP 410 on next request
  - Per-brand storage layout

Usage:
    uv sync
    uv run uvicorn server:app --host 0.0.0.0 --port 8443 \\
        --ssl-keyfile key.pem --ssl-certfile cert.pem
    # Or without SSL (the app's TrustManager accepts anything):
    uv run uvicorn server:app --host 0.0.0.0 --port 8443

Research use only — ASTRA / LHS-LORIA stalkerware analysis project.
"""

import json
import logging
import uuid
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

# Mock returns a 3-domain list (the app expects "X;Y;Z" format with rotation).
# In a multi-port setup, replace these with 3 distinct mock instances for
# failover/rotation testing.
MOCK_DOMAINS = (
    "https://127.0.0.1:8443/;"
    "https://127.0.0.1:8443/;"
    "https://127.0.0.1:8443/"
)

MOCK_PIN = "1234"
MOCK_SUBSCRIPTION = "premium"
VALID_THROUGH = (datetime.now() + timedelta(days=365)).strftime("%Y-%m-%d %H:%M:%S")
CLIENT_VERSION = "7.5.369"
SETTINGS_VERSION = 100

# Known brands (cf. C0737a static init: f5124e = SNPA ? : HWA_TST ? : HWA)
KNOWN_BRANDS = {"HWA", "HWA_TST", "SNPA"}

LOG_DIR = Path("logs")
LOG_DIR.mkdir(exist_ok=True)
for sub in ("registrations", "exfil", "exceptions", "raw", "by_brand"):
    (LOG_DIR / sub).mkdir(exist_ok=True)

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
# State — tracks registered devices and exfiltration counters
# ---------------------------------------------------------------------------

devices: dict[str, dict] = {}                 # auth_key -> device info
killed_devices: set[str] = set()              # auth_keys to receive HTTP 410
locked_devices: set[str] = set()              # auth_keys to receive HTTP 401 (license locked)
banned_devices: set[str] = set()              # auth_keys to receive HTTP 403

# Stats per brand
stats: dict[str, dict] = {
    brand: {
        "devices": 0,
        "exfil_requests": 0,
        "exfil_bytes": 0,
        "exception_requests": 0,
        "messages_intercepted": 0,
        "locations_intercepted": 0,
        "screenshots_intercepted": 0,
        "unknown_payloads": 0,
    }
    for brand in (KNOWN_BRANDS | {"UNKNOWN"})
}

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
    title="Refog Mock C2 (Hoverwatch / Snoopza)",
    description="Research mock — simulates Refog Inc. stalkerware C2 backend",
    version="2.0.0",
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def brand_of(auth_key: str) -> str:
    """Return the brand for a given auth_key, or 'UNKNOWN'."""
    info = devices.get(auth_key)
    if info:
        return info.get("brand", "UNKNOWN")
    return "UNKNOWN"


def classify_log_payload(payload: dict) -> str:
    """Heuristic categorization of an exfiltrated log JSON, based on its keys.
    Used to drive per-category counters in the stats dashboard."""
    if not isinstance(payload, dict):
        return "unknown"
    keys = set(payload.keys())
    # IM message (cf. InstantMessage Gson DTO, hoverwatch_analysis.md §9.5.2)
    if {"text", "direct"} <= keys or {"N", "time", "type"} <= keys:
        return "im_message"
    # Location event
    if "loc" in keys or {"crd", "acc"} <= keys:
        return "location"
    # Screenshot
    if "shot" in keys or "screenshot" in keys:
        return "screenshot"
    # Call recording
    if "call" in keys or "audio" in keys:
        return "call"
    # SMS
    if "sms" in keys:
        return "sms"
    # Contact
    if "contact" in keys:
        return "contact"
    # Browser history / bookmarks
    if "url" in keys or "bookmark" in keys:
        return "browser"
    # Keylog
    if "keys" in keys or "key" in keys:
        return "keylog"
    return "unknown"


# ---------------------------------------------------------------------------
# Middleware — log every request (headers + body summary)
# ---------------------------------------------------------------------------

@app.middleware("http")
async def log_requests(request: Request, call_next):
    auth_key = request.headers.get("x-auth-key", "")
    user_agent = request.headers.get("user-agent", "unknown")
    settings_ver = request.headers.get("x-settings-ver", "")
    client_event = request.headers.get("x-client-event", "")
    content_type = request.headers.get("content-type", "")
    content_length = request.headers.get("content-length", "0")
    brand = brand_of(auth_key) if auth_key else "-"

    log.info(
        ">>> %s %s | brand=%s | UA=%s | auth=%s | settings-ver=%s | event=%s | CL=%s | CT=%s",
        request.method,
        request.url.path,
        brand,
        user_agent,
        auth_key[:24] + "…" if len(auth_key) > 24 else auth_key or "-",
        settings_ver or "-",
        client_event or "-",
        content_length,
        content_type[:50],
    )

    # IMPORTANT: do NOT consume the body here — multipart endpoints need the
    # raw stream intact for downstream parsing. Body inspection is done in the
    # specific handlers (registration/activation/logs/exceptions) where needed.
    response = await call_next(request)

    log.info("<<< %s %s → %d", request.method, request.url.path, response.status_code)
    return response


# ---------------------------------------------------------------------------
# POST /api/online/registration/
# Device registration — receives credentials + device fingerprint
# Note: brand is NOT in the registration body — it's only known via the
# /programversion/{brand}/ endpoint that the app calls separately. We tag
# the device as UNKNOWN here and reconcile later.
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
    # user_type is the device profile (CHILD=0, EMPLOYEE=1, OWN=2, UNDEFINED=3)
    # cf. C0867b0$a enum — NOT to be confused with the brand code (HWA/SNPA).
    user_type = body.get("user_type", -1)
    user_type_label = {0: "CHILD", 1: "EMPLOYEE", 2: "OWN", 3: "UNDEFINED"}.get(user_type, "?")

    auth_key = f"{username}:{uuid.uuid4().hex[:16]}"

    device_info = {
        "auth_key": auth_key,
        "brand": "UNKNOWN",  # set when /programversion/{brand}/ is hit
        "username": username,
        "password": password,
        "hid": hid,
        "device_name": device_name,
        "client_ver": client_ver,
        "imei": imei,
        "user_type": user_type,
        "user_type_label": user_type_label,
        "registered_at": datetime.now().isoformat(),
        "raw_registration": body,
    }
    devices[auth_key] = device_info

    # Persist registration to per-brand and global jsonl logs
    with open(LOG_DIR / "registrations" / "all.jsonl", "a") as f:
        f.write(json.dumps(device_info, default=str) + "\n")

    log.info(
        "🎯 DEVICE REGISTERED: user=%s | hid=%s | device=%s | imei=%s | type=%s | → auth_key=%s",
        username, hid, device_name, imei, user_type_label, auth_key,
    )

    return JSONResponse(content={
        "status": "ok",
        "auth_key": auth_key,
        "valid_through": VALID_THROUGH,
        "subscription": MOCK_SUBSCRIPTION,
        "domains": MOCK_DOMAINS,
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

    auth_key = request.headers.get("x-auth-key", "") or f"activated:{uuid.uuid4().hex[:16]}"
    log.info("🔑 ACTIVATION | auth=%s | payload=%s", auth_key, json.dumps(body, default=str)[:300])

    return JSONResponse(content={
        "status": "ok",
        "auth_key": auth_key,
        "valid_through": VALID_THROUGH,
        "subscription": MOCK_SUBSCRIPTION,
        "domains": MOCK_DOMAINS,
        "client_pin": MOCK_PIN,
        "settings": DEFAULT_SETTINGS,
    })


# ---------------------------------------------------------------------------
# POST /api/online/check/
# Heartbeat / ping — app checks if C2 is reachable AND if it should
# uninstall (HTTP 410 = kill switch) or back off (HTTP 401 = license locked).
# ---------------------------------------------------------------------------

@app.post("/api/online/check/")
async def check(request: Request):
    auth_key = request.headers.get("x-auth-key", "")

    # Apply admin-armed states first — these dictate what the app does next
    if auth_key in killed_devices:
        log.warning("☠️  KILL SWITCH delivered to %s (HTTP 410)", auth_key)
        # Don't pop — the app may retry; keep responding 410 until uninstall confirmed
        return Response(status_code=410, content="Remove application")
    if auth_key in banned_devices:
        log.warning("🚫 BANNED auth_key=%s (HTTP 403)", auth_key)
        return Response(status_code=403, content="Wrong login/pass")
    if auth_key in locked_devices:
        log.warning("🔒 LOCKED auth_key=%s (HTTP 401 — app will sync every 720min)", auth_key)
        return Response(status_code=401, content="License locked")

    log.info("💓 HEARTBEAT auth_key=%s brand=%s", auth_key, brand_of(auth_key))
    return Response(status_code=200, content="ok")


# ---------------------------------------------------------------------------
# GET /api/online/programversion/{brand}/
# Update check + brand reconciliation
#   brand ∈ {HWA, HWA_TST, SNPA} — cf. C0737a static init
# This is the ONLY endpoint that reveals which brand the APK was built as.
# ---------------------------------------------------------------------------

@app.get("/api/online/programversion/{brand}/")
async def program_version(brand: str, request: Request):
    auth_key = request.headers.get("x-auth-key", "")
    if brand not in KNOWN_BRANDS:
        log.warning("⚠️  UNKNOWN BRAND in update check: %r (auth_key=%s)", brand, auth_key)
    else:
        log.info("📦 UPDATE CHECK | brand=%s | auth_key=%s", brand, auth_key)

    # Reconcile brand on the device record (if registered)
    if auth_key and auth_key in devices and devices[auth_key].get("brand") in (None, "UNKNOWN"):
        devices[auth_key]["brand"] = brand
        stats.setdefault(brand, stats["UNKNOWN"])["devices"] += 1
        log.info("   → reconciled brand=%s for auth_key=%s", brand, auth_key)

    # "No update available" — keep the current version running
    return Response(status_code=404, content="Update not found")

    # To simulate an update push, return JSON:
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
# Exception/error logs from the stalkerware (multipart with 'exceptionNNNN' parts)
# Format: multipart/form-data, parts named 'exception0001', 'exception0002', …
#         (cf. C0881o.m6334X(true, i) → "exception%04d")
# ---------------------------------------------------------------------------

@app.post("/api/online/exceptionlog/")
async def exception_log(request: Request):
    auth_key = request.headers.get("x-auth-key", "")
    brand = brand_of(auth_key)

    # Try multipart parse first (the actual format used)
    parsed_parts: list[dict] = []
    try:
        form = await request.form()
        for part_name, part_value in form.multi_items():
            content = part_value if isinstance(part_value, str) else (await part_value.read()).decode("utf-8", errors="replace")
            try:
                parsed_parts.append({"name": part_name, "json": json.loads(content)})
            except json.JSONDecodeError:
                parsed_parts.append({"name": part_name, "text": content[:500]})
    except Exception as e:
        # Fallback: dump raw body
        raw = await request.body()
        log.warning("⚠️  Could not parse multipart on /exceptionlog/: %s | %d raw bytes", e, len(raw))
        parsed_parts = [{"name": "_raw", "hex": raw[:512].hex()}]

    log.info("🐛 EXCEPTION LOG | brand=%s | auth=%s | %d parts", brand, auth_key, len(parsed_parts))
    for p in parsed_parts[:5]:
        log.info("   part %s: %s", p["name"], json.dumps(p, ensure_ascii=False, default=str)[:300])

    # Persist
    stats[brand]["exception_requests"] += 1
    safe_key = auth_key[:32].replace("/", "_").replace(":", "_").replace("\\", "_")
    out_path = LOG_DIR / "exceptions" / f"{datetime.now().strftime('%Y%m%d_%H%M%S')}_{brand}_{safe_key or 'noauth'}.json"
    out_path.write_text(
        json.dumps({"auth_key": auth_key, "brand": brand, "parts": parsed_parts}, ensure_ascii=False, indent=2, default=str)
    )

    return Response(status_code=200, content="ok")


# ---------------------------------------------------------------------------
# POST /api/online/logs/
# MAIN EXFILTRATION ENDPOINT — receives all stolen data
# Format: multipart/form-data via Apache HttpClient MultipartEntityBuilder
#         (cf. d.a.a.a.f.d.k = MultipartEntityBuilder)
# Each part is named 'logNNNN' (cf. C0881o.m6334X(false, i) → "log%04d")
# Each part body is a UTF-8 JSON object (an event: IM message, location, screenshot, etc.)
# ---------------------------------------------------------------------------

@app.post("/api/online/logs/")
async def receive_logs(request: Request):
    auth_key = request.headers.get("x-auth-key", "")
    brand = brand_of(auth_key)

    # Honor admin-armed kill before processing any data
    if auth_key in killed_devices:
        log.warning("☠️  KILL SWITCH delivered to %s on /logs/ (HTTP 410)", auth_key)
        return Response(status_code=410, content="Remove application")

    # ---- Multipart parsing
    parsed_parts: list[dict] = []
    raw_body_size = 0
    try:
        form = await request.form()
        for part_name, part_value in form.multi_items():
            if isinstance(part_value, str):
                # Text part (typical for logNNNN with JSON body)
                content = part_value
                raw_body_size += len(content.encode("utf-8"))
                try:
                    payload = json.loads(content)
                    parsed_parts.append({"name": part_name, "kind": "json", "data": payload})
                except json.JSONDecodeError:
                    parsed_parts.append({"name": part_name, "kind": "text", "data": content[:1000]})
            else:
                # UploadFile (binary attachment — photo/audio/video from IM)
                blob = await part_value.read()
                raw_body_size += len(blob)
                # Save the binary attachment for forensic recovery
                safe_part = part_name.replace("/", "_").replace(":", "_").replace("\\", "_")
                safe_filename = (part_value.filename or "noname").replace("/", "_").replace(":", "_").replace("\\", "_")
                bin_path = LOG_DIR / "raw" / f"{datetime.now().strftime('%Y%m%d_%H%M%S')}_{brand}_{safe_part}_{safe_filename}"
                bin_path.write_bytes(blob)
                parsed_parts.append({
                    "name": part_name,
                    "kind": "binary",
                    "filename": part_value.filename,
                    "content_type": part_value.content_type,
                    "size": len(blob),
                    "saved_to": str(bin_path),
                })
    except Exception as e:
        # Fallback if not multipart — some test clients may post plain JSON
        raw = await request.body()
        raw_body_size = len(raw)
        log.warning("⚠️  Could not parse multipart on /logs/: %s | %d raw bytes", e, raw_body_size)
        try:
            parsed_parts = [{"name": "_unparsed", "kind": "json", "data": json.loads(raw)}]
        except json.JSONDecodeError:
            parsed_parts = [{"name": "_unparsed", "kind": "binary", "hex": raw[:512].hex(), "size": raw_body_size}]

    # ---- Update stats per category
    stats[brand]["exfil_requests"] += 1
    stats[brand]["exfil_bytes"] += raw_body_size
    for p in parsed_parts:
        if p.get("kind") == "json":
            cat = classify_log_payload(p.get("data", {}))
            if cat == "im_message":
                stats[brand]["messages_intercepted"] += 1
            elif cat == "location":
                stats[brand]["locations_intercepted"] += 1
            elif cat == "screenshot":
                stats[brand]["screenshots_intercepted"] += 1
            elif cat == "unknown":
                stats[brand]["unknown_payloads"] += 1

    # ---- Log summary
    log.info(
        "📡 EXFIL | brand=%s | auth=%s | %d parts | %d bytes",
        brand, auth_key, len(parsed_parts), raw_body_size,
    )
    for p in parsed_parts[:5]:
        snippet = json.dumps(p, ensure_ascii=False, default=str)
        log.info("   part %s: %s", p["name"], snippet[:300])
    if len(parsed_parts) > 5:
        log.info("   … +%d more parts", len(parsed_parts) - 5)

    # ---- Persist structured exfil dump
    safe_key = auth_key[:32].replace("/", "_").replace(":", "_").replace("\\", "_")
    out_path = LOG_DIR / "exfil" / f"{datetime.now().strftime('%Y%m%d_%H%M%S')}_{brand}_{safe_key or 'noauth'}.json"
    out_path.write_text(
        json.dumps(
            {
                "timestamp": datetime.now().isoformat(),
                "auth_key": auth_key,
                "brand": brand,
                "part_count": len(parsed_parts),
                "raw_body_size": raw_body_size,
                "parts": parsed_parts,
            },
            ensure_ascii=False, indent=2, default=str,
        )
    )

    return Response(status_code=200, content="ok")


# ---------------------------------------------------------------------------
# Dashboard — view registered devices and stats per brand
# ---------------------------------------------------------------------------

@app.get("/")
async def dashboard():
    return JSONResponse(content={
        "server": "Refog Mock C2 (Hoverwatch / Snoopza)",
        "version": "2.0.0",
        "status": "running",
        "registered_devices": len(devices),
        "killed_devices": len(killed_devices),
        "locked_devices": len(locked_devices),
        "banned_devices": len(banned_devices),
        "stats_by_brand": stats,
        "devices": [
            {
                "auth_key": d["auth_key"],
                "brand": d.get("brand", "?"),
                "username": d["username"],
                "device_name": d["device_name"],
                "imei": d.get("imei", "?"),
                "user_type": d.get("user_type_label", "?"),
                "registered_at": d["registered_at"],
            }
            for d in devices.values()
        ],
    })


@app.get("/devices")
async def list_devices():
    return JSONResponse(content={"devices": list(devices.values())})


@app.get("/exfil")
async def list_exfil():
    """List exfiltrated dumps stored on disk (filenames + sizes)."""
    files = sorted((LOG_DIR / "exfil").iterdir(), key=lambda p: p.stat().st_mtime, reverse=True)
    return JSONResponse(content={
        "count": len(files),
        "recent": [
            {"name": f.name, "size": f.stat().st_size, "mtime": f.stat().st_mtime}
            for f in files[:50]
        ],
    })


# ---------------------------------------------------------------------------
# Admin — simulate server-side actions for behavior research
# ---------------------------------------------------------------------------

@app.post("/admin/kill/{auth_key:path}")
async def admin_kill(auth_key: str):
    """Arm kill switch — next /check/ or /logs/ from this device returns HTTP 410.
    The app then sets state APP_STATE_UNINSTALL_ASK and prompts the victim
    via Intent.ACTION_DELETE on next USER_PRESENT (cf. C0744c)."""
    killed_devices.add(auth_key)
    log.warning("☠️  KILL SWITCH armed for %s (HTTP 410 next request)", auth_key)
    return {"status": "kill_switch_armed", "auth_key": auth_key}


@app.post("/admin/lock/{auth_key:path}")
async def admin_lock(auth_key: str):
    """Arm license-lock — next /check/ returns HTTP 401, app then backs off
    sync interval to 720 minutes (12h) per the protocol."""
    locked_devices.add(auth_key)
    log.warning("🔒 LOCK armed for %s (HTTP 401 next request)", auth_key)
    return {"status": "locked", "auth_key": auth_key}


@app.post("/admin/ban/{auth_key:path}")
async def admin_ban(auth_key: str):
    """Arm wrong-credentials response — next request returns HTTP 403."""
    banned_devices.add(auth_key)
    log.warning("🚫 BAN armed for %s (HTTP 403 next request)", auth_key)
    return {"status": "banned", "auth_key": auth_key}


@app.post("/admin/clear/{auth_key:path}")
async def admin_clear(auth_key: str):
    """Clear all admin-armed states for a device."""
    killed_devices.discard(auth_key)
    locked_devices.discard(auth_key)
    banned_devices.discard(auth_key)
    log.info("🧹 Cleared armed states for %s", auth_key)
    return {"status": "cleared", "auth_key": auth_key}


@app.post("/admin/settings")
async def admin_update_settings(request: Request):
    """Push new settings to all devices on next sync.
    The app picks them up on next registration/activation response."""
    global DEFAULT_SETTINGS
    body = await request.json()
    DEFAULT_SETTINGS.update(body)
    DEFAULT_SETTINGS["version"] = DEFAULT_SETTINGS.get("version", SETTINGS_VERSION) + 1
    log.info("⚙️  SETTINGS UPDATED → version=%d", DEFAULT_SETTINGS["version"])
    log.info("   %s", json.dumps(DEFAULT_SETTINGS, indent=2))
    return {"status": "ok", "new_settings": DEFAULT_SETTINGS}
