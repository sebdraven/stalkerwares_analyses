#!/usr/bin/env python3
"""
Mobile Tracker Free — Mock C2 Server (Sinkhole/Honeypot)
Simule le backend MTF pour capturer et analyser les communications
du stalkerware phone.monitor2026.

Référence : mtf_c2_analysis.md

Tous les endpoints renvoient "ok" pour que le stalkerware continue
à exfiltrer. Les données reçues sont loggées dans ./captures/

Usage :
  uv sync
  uv run python mtf_c2_server.py           # HTTPS :8443, auto-gen cert si absent
  uv run python mtf_c2_server.py --http     # HTTP :8080 (debug)
  uv run python mtf_c2_server.py --regen-cert  # force nouveau cert

Le premier lancement génère mock.crt + mock.key (self-signed, SAN=
127.0.0.1/localhost/10.11.1.1/10.0.2.2/mobile-track-data.com, valide 1 an).
Le bypass SSL Frida reste requis côté app (ou MITM proxy sans cert pinning).

Pour rediriger le stalkerware vers ce serveur :
  - DNS spoofing de mobile-track-data.com
  - ou modifier /etc/hosts sur le device (root)
  - ou adb reverse tcp:8443 tcp:8443 (lab Corellium sans VPN)
"""

import argparse
import ipaddress
import json
import logging
import os
import shutil
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, File, Form, Request, UploadFile
from fastapi.responses import JSONResponse, PlainTextResponse
import uvicorn

# ============================================================
# Self-signed TLS cert — auto-généré au premier lancement
# ============================================================

CERT_PATH = Path(__file__).parent / "mock.crt"
KEY_PATH  = Path(__file__).parent / "mock.key"


def ensure_cert(log_fn=print) -> tuple[Path, Path]:
    """Génère mock.crt + mock.key si absents. Self-signed, SAN multi-IP,
    valide 1 an. Utilise `cryptography` (pur Python, pas d'openssl)."""
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
        x509.NameAttribute(NameOID.COMMON_NAME, "mock-mtf-c2"),
    ])

    san = x509.SubjectAlternativeName([
        x509.DNSName("localhost"),
        x509.DNSName("mobile-track-data.com"),
        x509.DNSName("mock-c2"),
        x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
        x509.IPAddress(ipaddress.IPv4Address("10.11.1.1")),
        x509.IPAddress(ipaddress.IPv4Address("10.0.2.2")),
    ])

    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=365))
        .add_extension(san, critical=False)
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

    log_fn(f"   ✅ {CERT_PATH.name} + {KEY_PATH.name} (valid 1y, SAN=127.0.0.1/localhost/10.11.1.1/10.0.2.2/mobile-track-data.com)")
    return CERT_PATH, KEY_PATH

# ============================================================
# Config
# ============================================================

CAPTURE_DIR = Path("captures")
LOG_FILE = CAPTURE_DIR / "c2_server.log"

EXPECTED_UA_STALKERWARE = "ILAHK20DKA8751LD9D729OJD6D7HJDK2AQMFT2019"
EXPECTED_UA_DROPPER = "KABNKNHFFHDHYD58698347556988AD89GH2020"

app = FastAPI(
    title="MTF C2 Sinkhole",
    description="Mock C2 server for Mobile Tracker Free stalkerware analysis",
    version="1.0.0",
)

# ============================================================
# Logging
# ============================================================

CAPTURE_DIR.mkdir(parents=True, exist_ok=True)

logger = logging.getLogger("mtf_c2")
logger.setLevel(logging.DEBUG)

fh = logging.FileHandler(LOG_FILE, encoding="utf-8")
fh.setLevel(logging.DEBUG)

ch = logging.StreamHandler()
ch.setLevel(logging.INFO)

fmt = logging.Formatter("[%(asctime)s] %(levelname)s %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
fh.setFormatter(fmt)
ch.setFormatter(fmt)

logger.addHandler(fh)
logger.addHandler(ch)


# ============================================================
# Helpers
# ============================================================

def _ts() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S_%f")


def _check_ua(request: Request) -> str:
    """Vérifie le User-Agent et retourne le type de client."""
    ua = request.headers.get("user-agent", "")
    if EXPECTED_UA_STALKERWARE in ua:
        return "STALKERWARE"
    elif EXPECTED_UA_DROPPER in ua:
        return "DROPPER"
    else:
        return f"UNKNOWN({ua[:60]})"


async def _capture_form(request: Request, endpoint: str, category: str) -> dict:
    """Capture une requête POST form-data et la log."""
    client_type = _check_ua(request)
    client_ip = request.client.host if request.client else "unknown"

    form = await request.form()
    params = {k: v for k, v in form.items() if not hasattr(v, "read")}

    # Masquer les données trop longues (Base64 screenshots, etc.)
    params_log = {}
    for k, v in params.items():
        if isinstance(v, str) and len(v) > 500:
            params_log[k] = f"<{len(v)} chars — {v[:80]}...>"
        else:
            params_log[k] = v

    id_phone = params.get("idPhone", "?")
    token = params.get("tokenSecurity", "")[:20]

    entry = {
        "timestamp": datetime.now().isoformat(),
        "client_ip": client_ip,
        "client_type": client_type,
        "endpoint": endpoint,
        "category": category,
        "id_phone": id_phone,
        "token_prefix": token,
        "params": params_log,
    }

    logger.info(
        f"[{client_type}] {client_ip} → {endpoint} | "
        f"idPhone={id_phone} | params={list(params_log.keys())}"
    )

    # Sauvegarder en JSON
    cat_dir = CAPTURE_DIR / category
    cat_dir.mkdir(parents=True, exist_ok=True)
    out = cat_dir / f"{_ts()}_{endpoint.replace('/', '_')}.json"
    with open(out, "w", encoding="utf-8") as f:
        json.dump(entry, f, indent=2, ensure_ascii=False)

    return params


async def _capture_multipart(
    request: Request,
    endpoint: str,
    category: str,
    file: Optional[UploadFile] = None,
) -> dict:
    """Capture une requête multipart + fichier."""
    params = await _capture_form(request, endpoint, category)

    if file and file.filename:
        file_dir = CAPTURE_DIR / category / "files"
        file_dir.mkdir(parents=True, exist_ok=True)

        id_phone = params.get("idPhone", "unknown")
        ext = Path(file.filename).suffix or ".bin"
        out_path = file_dir / f"{_ts()}_phone{id_phone}{ext}"

        with open(out_path, "wb") as f:
            shutil.copyfileobj(file.file, f)

        size = out_path.stat().st_size
        logger.info(f"  └─ FILE saved: {out_path.name} ({size:,} bytes)")

    return params


# ============================================================
# Catch-all middleware pour logger TOUT
# ============================================================

@app.middleware("http")
async def log_all_requests(request: Request, call_next):
    """Log toutes les requêtes, même celles non matchées."""
    response = await call_next(request)
    if response.status_code == 404:
        logger.warning(
            f"[UNMAPPED] {request.method} {request.url.path} "
            f"UA={request.headers.get('user-agent', '?')[:40]}"
        )
    return response


# ============================================================
# ENDPOINTS — User / Phone
# ============================================================

@app.post("/user/verifPhone.php")
async def verif_phone(request: Request):
    params = await _capture_form(request, "user/verifPhone.php", "user")
    return JSONResponse({"status": "ok", "nbPhone": 0})


@app.post("/user/savePhone.php")
async def save_phone(request: Request):
    params = await _capture_form(request, "user/savePhone.php", "user")
    # Retourne un faux idPhone pour que le stalkerware s'enregistre
    return JSONResponse({"status": "ok", "idPhone": 99999})


@app.post("/user/updatePhone.php")
async def update_phone(request: Request):
    await _capture_form(request, "user/updatePhone.php", "user")
    return PlainTextResponse("ok")


# ============================================================
# ENDPOINTS — SMS / MMS
# ============================================================

@app.post("/sms/insertSMS.php")
async def insert_sms(request: Request):
    await _capture_form(request, "sms/insertSMS.php", "sms")
    return PlainTextResponse("ok")


@app.post("/sms/insertSMSAlert.php")
async def insert_sms_alert(request: Request):
    await _capture_form(request, "sms/insertSMSAlert.php", "sms")
    return PlainTextResponse("ok")


@app.post("/mms/insertMMS.php")
async def insert_mms(request: Request):
    await _capture_form(request, "mms/insertMMS.php", "mms")
    return PlainTextResponse("ok")


# ============================================================
# ENDPOINTS — Calls
# ============================================================

@app.post("/calls/insertCall.php")
async def insert_call(request: Request):
    await _capture_form(request, "calls/insertCall.php", "calls")
    return PlainTextResponse("ok")


@app.post("/calls/insertCallRecord.php")
async def insert_call_record(request: Request):
    form = await request.form()
    file = form.get("file")
    await _capture_multipart(request, "calls/insertCallRecord.php", "calls", file)
    return PlainTextResponse("ok")


# ============================================================
# ENDPOINTS — Contacts / Calendar / Location / Clipboard
# ============================================================

@app.post("/contacts/insertContactNew.php")
async def insert_contact(request: Request):
    await _capture_form(request, "contacts/insertContactNew.php", "contacts")
    return PlainTextResponse("ok")


@app.post("/calendar/insertCalendar.php")
async def insert_calendar(request: Request):
    await _capture_form(request, "calendar/insertCalendar.php", "calendar")
    return PlainTextResponse("ok")


@app.post("/location/insertLocation.php")
async def insert_location(request: Request):
    await _capture_form(request, "location/insertLocation.php", "location")
    return PlainTextResponse("ok")


@app.post("/clipboard/insertClipboard.php")
async def insert_clipboard(request: Request):
    await _capture_form(request, "clipboard/insertClipboard.php", "clipboard")
    return PlainTextResponse("ok")


# ============================================================
# ENDPOINTS — Applications
# ============================================================

@app.post("/applications/insertApplication.php")
async def insert_app(request: Request):
    await _capture_form(request, "applications/insertApplication.php", "apps")
    return PlainTextResponse("ok")


@app.post("/applications/insertApplicationsUsage.php")
async def insert_app_usage(request: Request):
    await _capture_form(request, "applications/insertApplicationsUsage.php", "apps")
    return PlainTextResponse("ok")


# ============================================================
# ENDPOINTS — Web History / SIM
# ============================================================

@app.post("/site/insertSiteHistory.php")
async def insert_site_history(request: Request):
    await _capture_form(request, "site/insertSiteHistory.php", "web")
    return PlainTextResponse("ok")


@app.post("/sim/setChangeSIM.php")
async def set_change_sim(request: Request):
    await _capture_form(request, "sim/setChangeSIM.php", "sim")
    return PlainTextResponse("ok")


# ============================================================
# ENDPOINTS — Pictures
# ============================================================

@app.post("/pictures/insertPicture.php")
async def insert_picture(request: Request):
    form = await request.form()
    file = form.get("file")
    await _capture_multipart(request, "pictures/insertPicture.php", "pictures", file)
    return PlainTextResponse("ok")


@app.post("/pictures/setPicturePasswordFailed.php")
async def set_picture_pw_fail(request: Request):
    await _capture_form(request, "pictures/setPicturePasswordFailed.php", "pictures")
    return PlainTextResponse("ok")


# ============================================================
# ENDPOINTS — Audio Recording
# ============================================================

@app.post("/recordAudio/setRecordAudio.php")
async def set_record_audio(request: Request):
    form = await request.form()
    file = form.get("file")
    await _capture_multipart(request, "recordAudio/setRecordAudio.php", "audio", file)
    return PlainTextResponse("ok")


# ============================================================
# ENDPOINTS — Screenshots
# ============================================================

@app.post("/screenshot/insertScreen.php")
async def insert_screen(request: Request):
    form = await request.form()
    file = form.get("file")
    await _capture_multipart(request, "screenshot/insertScreen.php", "screenshots", file)
    return PlainTextResponse("ok")


# ============================================================
# ENDPOINTS — File Explorer
# ============================================================

@app.post("/fileExplorer/insertNewFileFirst.php")
async def insert_file_first(request: Request):
    await _capture_form(request, "fileExplorer/insertNewFileFirst.php", "file_explorer")
    return PlainTextResponse("ok")


@app.post("/fileExplorer/insertNewFile.php")
async def insert_file(request: Request):
    form = await request.form()
    file = form.get("file")
    await _capture_multipart(request, "fileExplorer/insertNewFile.php", "file_explorer", file)
    return PlainTextResponse("ok")


# ============================================================
# ENDPOINTS — Remote Control
# ============================================================

@app.post("/remoteControl/setLog.php")
async def set_log(request: Request):
    params = await _capture_form(request, "remoteControl/setLog.php", "remote_control")
    # Log spécial : c'est l'accusé de réception des commandes FCM
    cmd_type = params.get("type", "?")
    cmd_data = params.get("data", "?")
    if isinstance(cmd_data, str) and len(cmd_data) > 100:
        cmd_data = f"<{len(cmd_data)} chars>"
    logger.info(f"  └─ CMD ACK: type={cmd_type} data={cmd_data}")
    return PlainTextResponse("ok")


# ============================================================
# ENDPOINTS — Live Streaming
# ============================================================

@app.post("/live/sendToken.php")
async def send_live_token(request: Request):
    params = await _capture_form(request, "live/sendToken.php", "live")
    token = params.get("token", "?")
    logger.info(f"  └─ LIVE TOKEN: {token[:50]}")
    return PlainTextResponse("ok")


# ============================================================
# ENDPOINTS — IM No-Root (19 apps)
# ============================================================

IM_NOROOT_APPS = [
    "Facebook", "WhatsAppMessagesNew", "Viber", "Skype", "Line",
    "Kik", "Tango", "Hangouts", "Telegram", "Wechat",
    "Snapchat", "Tinder", "Hike", "Instagram", "Twitter",
    "Gmail", "IMO", "YoutubeHistory", "Signal",
]

for _app_name in IM_NOROOT_APPS:
    _endpoint = f"socialNetwork/noRoot/insert{_app_name}Messages.php"
    if _app_name == "YoutubeHistory":
        _endpoint = "socialNetwork/noRoot/insertYoutubeHistory.php"

    # Closure pour capturer _endpoint et _app_name
    def _make_im_handler(ep=_endpoint, an=_app_name):
        async def handler(request: Request):
            params = await _capture_form(request, ep, "im_noroot")
            name = params.get("fullName", "?")
            logger.info(f"  └─ IM [{an}] from: {name}")
            return PlainTextResponse("ok")
        handler.__name__ = f"im_noroot_{an.lower()}"
        return handler

    app.post(f"/{_endpoint}")(_make_im_handler())


# ============================================================
# ENDPOINTS — IM Root (9 apps)
# ============================================================

IM_ROOT_APPS = [
    "Facebook", "Hangouts", "Kik", "WhatsApp",
    "Instagram", "Line", "Viber", "Gmail", "Skype",
    "Telegram",
]

for _app_name in IM_ROOT_APPS:
    _endpoint = f"socialNetwork/root/insert{_app_name}.php"

    def _make_root_handler(ep=_endpoint, an=_app_name):
        async def handler(request: Request):
            params = await _capture_form(request, ep, "im_root")
            name = params.get("fullName", "?")
            logger.info(f"  └─ ROOT IM [{an}] from: {name}")
            return PlainTextResponse("ok")
        handler.__name__ = f"im_root_{an.lower()}"
        return handler

    app.post(f"/{_endpoint}")(_make_root_handler())


# ============================================================
# DROPPER ENDPOINTS (bonus — pour capturer aussi le dropper)
# ============================================================

@app.post("/getVersionApp.php")
async def get_version_app(request: Request):
    """Dropper v3.9 — version check."""
    await _capture_form(request, "getVersionApp.php", "dropper")
    return PlainTextResponse("3.9")


@app.post("/downloadAPK.php")
async def download_apk(request: Request):
    """Dropper v3.9 — download APK (retourne une erreur contrôlée)."""
    await _capture_form(request, "downloadAPK.php", "dropper")
    return PlainTextResponse("", status_code=404)


@app.post("/getURLFTP.php")
async def get_url_ftp(request: Request):
    """Dropper v2.7 — legacy endpoint."""
    await _capture_form(request, "getURLFTP.php", "dropper")
    return JSONResponse({"status": "no"})


# ============================================================
# CATCH-ALL — Endpoints inconnus
# ============================================================

@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE"])
async def catch_all(request: Request, path: str):
    """Capture tout endpoint non mappé."""
    client_type = _check_ua(request)
    client_ip = request.client.host if request.client else "unknown"

    body = ""
    try:
        body = (await request.body()).decode("utf-8", errors="replace")[:2000]
    except Exception:
        pass

    entry = {
        "timestamp": datetime.now().isoformat(),
        "client_ip": client_ip,
        "client_type": client_type,
        "method": request.method,
        "path": path,
        "headers": dict(request.headers),
        "body_preview": body,
    }

    logger.warning(f"[CATCH-ALL] [{client_type}] {request.method} /{path}")

    unknown_dir = CAPTURE_DIR / "unknown"
    unknown_dir.mkdir(parents=True, exist_ok=True)
    out = unknown_dir / f"{_ts()}_{path.replace('/', '_')[:80]}.json"
    with open(out, "w", encoding="utf-8") as f:
        json.dump(entry, f, indent=2, ensure_ascii=False)

    # Répondre "ok" par défaut pour ne pas casser le stalkerware
    return PlainTextResponse("ok")


# ============================================================
# Stats endpoint (pour le chercheur)
# ============================================================

@app.get("/_stats")
async def stats():
    """Statistiques du sinkhole."""
    counts = {}
    for cat_dir in CAPTURE_DIR.iterdir():
        if cat_dir.is_dir() and cat_dir.name != "unknown":
            n = sum(1 for f in cat_dir.glob("*.json"))
            if n > 0:
                counts[cat_dir.name] = n

    files_captured = sum(
        1
        for cat_dir in CAPTURE_DIR.rglob("files/*")
        if cat_dir.is_file()
    )

    return {
        "status": "running",
        "captures_by_category": counts,
        "total_captures": sum(counts.values()),
        "files_captured": files_captured,
        "log_file": str(LOG_FILE),
    }


# ============================================================
# Main
# ============================================================

def main():
    parser = argparse.ArgumentParser(description="MTF C2 Mock Server")
    parser.add_argument("--host", default="0.0.0.0", help="Bind address")
    parser.add_argument("--port", type=int, default=8443, help="Port (default: 8443 HTTPS, 8080 HTTP)")
    parser.add_argument("--http", action="store_true",
                        help="Serve plain HTTP (no TLS). Bascule aussi le port par défaut à 8080.")
    parser.add_argument("--regen-cert", action="store_true",
                        help="Force regeneration of mock.crt/mock.key even if they exist.")
    args = parser.parse_args()

    # Ajuste le port si HTTP et port par défaut 8443 pas override
    if args.http and args.port == 8443:
        args.port = 8080

    print("=" * 60)
    print("Mobile Tracker Free — C2 Mock Server (Sinkhole)")
    print(f"Captures → {CAPTURE_DIR.absolute()}")
    print(f"Stats    → http://{args.host}:{args.port}/_stats")
    print("=" * 60)
    print()
    print("Redirect stalkerware traffic here via:")
    print("  - DNS spoofing (mobile-track-data.com)")
    print("  - /etc/hosts on rooted device")
    print("  - adb reverse tcp:8443 tcp:8443 (Corellium)")
    print("  - MITM proxy (no cert pinning!)")
    print()

    if args.http:
        print(f"⚠️  HTTP MODE (no TLS) — http://{args.host}:{args.port}/")
        uvicorn.run(app, host=args.host, port=args.port, log_level="warning")
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
        log_level="warning",
    )


if __name__ == "__main__":
    main()
