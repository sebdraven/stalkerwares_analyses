# iKeyMonitor v17.4 + v19.1 — Mock C2 Server

Mock C2 pour l'analyse en lab de l'APK iKeyMonitor Android, **cross-version** :
un seul serveur gère à la fois la **v17.4** (endpoints avec typos `uoload`) et la
**v19.1** (endpoints corrigés/renommés), en normalisant les anciens noms vers la
forme canonique v19.1.

Dual-canal : REST API + WebSocket, avec support RTMP pour le screen streaming.

> **Research use only** — ASTRA / LHS-LORIA.

Analyse delta des deux versions : `../ikeymonitor_v19.1_delta.md`.

---

## Ce qui change entre v17.4 et v19.1 (et ce qui ne change pas)

| Aspect | v17.4 | v19.1 | Côté mock |
|---|---|---|---|
| Endpoints REST | 25 (5 typos `uoload`) | 28 (typos corrigées + renommages) | **normalisés par alias** |
| Cibles chat | 9 apps | 15 (+WhatsApp Business, Gmail, Instagram, Skype, TikTok, X) | app-side, transparent |
| GPP bypass | présent | étendu à 15 langues | app-side, transparent |
| Package name | `com.sec.android.internet.im.service.im20210815` | `com.android.internet.a20251031` | hook Frida distinct |
| Crypto 3DES | clé `ccc707d2924768f2cc12bc8b` | **identique** | — |
| Secret RTMP | `C4hgdA%Qc5UHfqEho&Ke` | **identique** | — |
| WebSocket XML | `<IKMService>` | **identique** | — |
| C2 infra | `ikmws.awsapi.io` + 4 mirrors | **identique** | — |

Les « +6 cibles chat » et le « GPP bypass 15 langues » sont des comportements
**app-side** (interception locale / anti-détection) : ils ne se traduisent pas par
des endpoints serveur, donc rien à faire côté mock. Ce qui touche le serveur, c'est
uniquement le **jeu d'endpoints**, géré par normalisation.

---

## Quickstart

```bash
uv sync

# HTTPS :8443 — génère cert.pem + key.pem au premier lancement
uv run python server.py

# Variantes
uv run python server.py --http          # HTTP :8080 (debug, sans TLS)
uv run python server.py --regen-cert    # force un nouveau certificat

# (Optionnel) serveur RTMP pour le screen streaming
# docker run -d -p 1935:1935 tiangolo/nginx-rtmp
```

Le cert self-signé couvre `localhost`, `127.0.0.1`, `10.11.1.1`, `10.0.2.2`
et les 5 domaines C2 iKM dans le SAN. **Pas de SSL pinning** côté app (trust
user + system certs) → MITM trivial, mais le cert doit être installé comme
certificat utilisateur sur le device.

---

## Setup device de test

### DNS redirect (5 domaines, identiques aux deux versions)

```
# /etc/hosts ou DNS du lab
192.168.X.X  ikmws.awsapi.io
192.168.X.X  ikmws-mirror.awsapi.io
192.168.X.X  ikm-sv2.awsapi.io
192.168.X.X  ikm-sv3.awsapi.io
192.168.X.X  ikm-sv4.awsapi.io
```

### Certificat

Installer `cert.pem` comme certificat **utilisateur** (pas besoin du system store :
iKM trust les user certs).

### Frida — hook selon la version

```bash
# v17.4
frida -U -f com.sec.android.internet.im.service.im20210815 \
    -l ikeymonitor_hook.js --no-pause

# v19.1 (package + classes obfusquées différents)
frida -U -f com.android.internet.a20251031 \
    -l ikeymonitor_v19.1_hook.js --no-pause
```

---

## Architecture

```
┌──────────────┐     REST (HTTPS)      ┌─────────────────┐
│  APK iKM     │  ──────────────────▶   │  Mock C2 Server │
│  v17.4 /     │   /index.php?         │  (FastAPI)      │
│  v19.1       │   m=api&a={action}    │  :8443          │
│              │  ◀──────────────────  │                 │
│              │     XML response      │  normalisation  │
│              │                       │  alias → v19.1  │
│              │     WebSocket (WSS)   │                 │
│              │  ◀────────────────▶   │  /ws            │
│              │     XML commands      │                 │
│              │     RTMP stream       ├─────────────────┤
│              │  ──────────────────▶  │  Admin API      │
└──────────────┘     :1935             │  /admin/*       │
                                       └─────────────────┘
```

Le serveur détecte la version (`detect_version()`) à partir du package/namespace
présent dans les requêtes, la mémorise par device, et **route toujours vers le
handler canonique v19.1** après passage par la table d'alias.

---

## Endpoints REST

Tous sous `/index.php?m=api&a={action}`.

### Contrôle & auth (10)

| Action | Description | Version |
|---|---|---|
| `register` | Enregistrement device | v17.4+ |
| `account` | Validation licence | v17.4+ |
| `cycle` | Heartbeat (~5 min) — peut porter des commandes embarquées | v17.4+ |
| `get_settings` / `set_settings` | Config distante | v17.4+ |
| `get_websocket_address` | URL du WebSocket | v17.4+ |
| `check_update` / `download_update` | MAJ APK | v17.4+ |
| `reset_password` | Reset credentials | **v19.1** |
| `schedule_surround` | Planification enregistrement ambiant | **v19.1** |

### Exfiltration (18 canoniques v19.1)

`upload_keystrokes`, `upload_chat_logs`, `upload_website_history`,
`upload_call_history`, `upload_gps_history`, `upload_chat_img`, `upload_call_img`,
`upload_wifi`, `upload_clipboard`, `upload_photo`, `upload_video`,
`upload_screenvideo`, `upload_surrounding`, `upload_contact`, `upload_calendar`,
`upload_screenshot`, `upload_debug_logs` *(v19.1)*, `upload_weekly_crash_logs` *(v19.1)*.

### Table de normalisation v17.4 → v19.1

| Reçu (v17.4) | Normalisé (canonique v19.1) |
|---|---|
| `uoload_keystrokes` | `upload_keystrokes` |
| `uoload_chat_logs` | `upload_chat_logs` |
| `uoload_website_history` | `upload_website_history` |
| `uoload_call_history` | `upload_call_history` |
| `uoload_gps_history` | `upload_gps_history` |
| `surrounding` | `upload_surrounding` |
| `contact` | `upload_contact` |
| `calendar` | `upload_calendar` |
| `get_screenshot` | `upload_screenshot` |
| `upload_Wifi` | `upload_wifi` |

Les deux formes sont acceptées : une trace réseau v17.4 comme v19.1 aboutit au
même handler. `GET /admin/endpoints` renvoie cette table + la liste canonique.

---

## Commandes WebSocket (via Admin API)

Protocole XML `<IKMService>` **inchangé** entre les deux versions.

```bash
# Photo (front/back)
curl -X POST "https://localhost:8443/admin/cmd/camera?camera_type=front" -k

# Screenshot
curl -X POST "https://localhost:8443/admin/cmd/screenshot" -k

# Stream écran RTMP (start/stop)
curl -X POST "https://localhost:8443/admin/cmd/screenstream?enable=1" -k

# Enregistrement ambiant (60 s)
curl -X POST "https://localhost:8443/admin/cmd/surrounding?enable=1&duration=60" -k

# Commande XML arbitraire
curl -X POST "https://localhost:8443/admin/cmd/raw" -k \
    -d '<IKMService><RequestType>test</RequestType><Camera><Enable>1</Enable><Type>back</Type></Camera></IKMService>'
```

---

## Inspection

```bash
# Status : devices (avec version détectée), WS, exfil, versions supportées
curl https://localhost:8443/admin/status -k

# Exfil — toutes, ou filtrées par action canonique
curl "https://localhost:8443/admin/exfiltrated?limit=20" -k
curl "https://localhost:8443/admin/exfiltrated/by_type/upload_keystrokes?limit=20" -k

# Mapping des endpoints (aliases + canoniques + dossiers)
curl https://localhost:8443/admin/endpoints -k

# Crypto : 3DES + signature RTMP
curl "https://localhost:8443/admin/crypto/encrypt?plaintext=test" -k
curl "https://localhost:8443/admin/crypto/decrypt?ciphertext=..." -k
curl "https://localhost:8443/admin/crypto/rtmp_sign?device_id=DEADBEEF" -k
```

`/admin/status` renseigne `version` par device et `supported_versions:
["v17.4","v19.1"]`.

---

## Données exfiltrées

Uploads binaires sauvés dans `uploads/`, JSON/texte des requêtes dans `logs/c2.log` :

```
uploads/
├── photos/        screenshots/     video/       surrounding/
├── chat_img/      call_img/        audio/
├── keystrokes/    chats/           web_history/
├── gps/           calls/           clipboard/
├── contacts/      calendar/        wifi/
├── debug/         crash_logs/      (debug + weekly crash — v19.1)
└── misc/          (fallback)
```

---

## Crypto (identique v17.4 / v19.1)

- **3DES/ECB** : clé `ccc707d2924768f2cc12bc8b` — chiffre/signe les requêtes
  (hex → base64), classe `p128r.C3443z` (v17.4) / `p185u.AbstractC4687z` (v19.1)
- **RTMP sign** : `MD5("/live/" + device_id + "-" + timestamp + "-" + secret)`,
  secret `C4hgdA%Qc5UHfqEho&Ke`
- **Pas de SSL pinning** — MITM trivial

---

## IOC réseau utiles

| IOC | Portée |
|---|---|
| URL pattern `index.php?m=api&a=` | cross-version |
| WebSocket `<IKMService>` | cross-version |
| HealthCheck `<ThreerdPartySecurityapps>` (typo « Threerd ») | cross-version, fiable |
| User-Agent WS `com.ab.ikm.portal.request` | cross-version |
| `a=uoload_keystrokes` | **v17.4 uniquement** |
| `a=upload_keystrokes` | **v19.1+** |
| Package `...im20210815` / `...a20251031` | discrimine la version |

---

## Fichiers

| Fichier | Description |
|---|---|
| `server.py` | Serveur FastAPI cross-version (REST + WebSocket + admin + crypto) |
| `ikeymonitor_hook.js` | Hooks Frida v17.4 |
| `ikeymonitor_v19.1_hook.js` | Hooks Frida v19.1 (package + classes obfusquées) |
| `gen_cert.py` | Générateur de certificat TLS avec SAN (aussi auto-généré par `server.py`) |
| `test_client.py` | Client de test du protocole (sans device) |
| `pyproject.toml` | Dépendances (fastapi, uvicorn, websockets, pycryptodome, cryptography) |
