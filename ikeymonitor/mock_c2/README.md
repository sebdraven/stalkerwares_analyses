# iKeyMonitor v17.4 — Mock C2 Server

Mock C2 pour l'analyse en lab de l'APK iKeyMonitor Android.
Dual-canal : REST API + WebSocket + support RTMP.

> **Research use only** — ASTRA / stalkerware analysis project.

## Quickstart

```bash
# 1. Installer les dépendances
uv sync

# 2. Générer le certificat TLS (SAN pour *.awsapi.io)
uv run python gen_cert.py

# 3. Lancer le serveur
uv run uvicorn server:app --host 0.0.0.0 --port 8443 \
    --ssl-keyfile key.pem --ssl-certfile cert.pem

# 4. (Optionnel) Serveur RTMP pour le screen streaming
# docker run -d -p 1935:1935 tiangolo/nginx-rtmp
```

## Setup device de test

### DNS redirect

Sur le device (ou dans le routeur/DNS du lab) :

```
# /etc/hosts ou équivalent
192.168.X.X  ikmws.awsapi.io
192.168.X.X  ikmws-mirror.awsapi.io
192.168.X.X  ikm-sv2.awsapi.io
192.168.X.X  ikm-sv3.awsapi.io
192.168.X.X  ikm-sv4.awsapi.io
```

### Certificat

Installer `cert.pem` comme certificat utilisateur sur le device Android.
L'APK trust les certificats user (pas de pinning).

### Frida

```bash
frida -U -f com.sec.android.internet.im.service.im20210815 \
    -l ikeymonitor_hook.js --no-pause
```

## Architecture

```
┌──────────────┐     REST (HTTPS)      ┌─────────────────┐
│              │  ──────────────────▶   │                 │
│  APK iKM     │     /index.php?       │  Mock C2 Server │
│  v17.4       │     m=api&a={action}  │  (FastAPI)      │
│              │  ◀──────────────────  │                 │
│              │     XML response      │  :8443          │
│              │                       │                 │
│              │     WebSocket (WSS)   │  /ws            │
│              │  ◀────────────────▶   │                 │
│              │     XML commands      │                 │
│              │                       ├─────────────────┤
│              │     RTMP stream       │  Admin API      │
│              │  ──────────────────▶  │  /admin/*       │
└──────────────┘     :1935             └─────────────────┘
```

## Endpoints REST

Tous sous `/index.php?m=api&a={action}`.

### Contrôle
| Action | Description |
|---|---|
| `register` | Enregistrement device |
| `account` | Validation licence |
| `cycle` | Heartbeat (toutes les ~5 min) |
| `get_settings` / `set_settings` | Config distante |
| `get_websocket_address` | URL du WebSocket |
| `check_update` / `download_update` | MAJ APK |

### Exfiltration (25 endpoints)
`uoload_keystrokes`, `uoload_chat_logs`, `uoload_website_history`,
`uoload_call_history`, `uoload_gps_history`, `upload_chat_img`,
`upload_call_img`, `upload_Wifi`, `upload_clipboard`, `upload_photo`,
`upload_video`, `upload_screenvideo`, `contact`, `calendar`,
`surrounding`, `get_screenshot`, etc.

Note : les typos `uoload` sont dans l'APK originale (IOC fingerprint).

## Commandes WebSocket (via Admin API)

```bash
# Capture photo (front/back)
curl -X POST "https://localhost:8443/admin/cmd/camera?camera_type=front" -k

# Capture d'écran
curl -X POST "https://localhost:8443/admin/cmd/screenshot" -k

# Stream écran RTMP (start/stop)
curl -X POST "https://localhost:8443/admin/cmd/screenstream?enable=1" -k

# Enregistrement ambiant (60 secondes)
curl -X POST "https://localhost:8443/admin/cmd/surrounding?enable=1&duration=60" -k

# Commande XML arbitraire
curl -X POST "https://localhost:8443/admin/cmd/raw" -k \
    -d '<IKMService><RequestType>test</RequestType><Camera><Enable>1</Enable><Type>back</Type></Camera></IKMService>'
```

## Inspection

```bash
# Status : devices connectés, nombre de WS, données exfiltrées
curl https://localhost:8443/admin/status -k

# Dernières données exfiltrées
curl "https://localhost:8443/admin/exfiltrated?limit=20" -k

# Crypto : chiffrer/déchiffrer 3DES
curl "https://localhost:8443/admin/crypto/encrypt?plaintext=test" -k
curl "https://localhost:8443/admin/crypto/decrypt?ciphertext=..." -k

# Générer signature RTMP
curl "https://localhost:8443/admin/crypto/rtmp_sign?device_id=DEADBEEF" -k
```

## Fichiers

| Fichier | Description |
|---|---|
| `server.py` | Serveur FastAPI (REST + WebSocket + admin) |
| `ikeymonitor_hook.js` | Hooks Frida (13 hooks : crypto, WS, REST, keylogger, RTMP) |
| `gen_cert.py` | Générateur de certificat TLS avec SAN |
| `pyproject.toml` | Dépendances (fastapi, uvicorn, websockets, pycryptodome) |

## Données exfiltrées

Les uploads binaires sont sauvegardés dans `uploads/` :
```
uploads/
├── photos/
├── screenshots/
├── audio/
├── video/
├── chat_img/
└── call_img/
```

Les logs textuels sont dans `logs/c2.log`.

## Crypto

- **3DES/ECB** : clé `ccc707d2924768f2cc12bc8b` — signature des requêtes
- **RTMP sign** : `MD5("/live/" + device_id + "-" + timestamp + "-" + secret)` avec secret `C4hgdA%Qc5UHfqEho&Ke`
- **Pas de SSL pinning** — MITM trivial
