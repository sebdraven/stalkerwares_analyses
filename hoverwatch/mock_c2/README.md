# Refog Mock C2 Server (Hoverwatch / Snoopza)

Mock C2 qui simule le backend Refog Inc. pour analyse dynamique des stalkerwares
**Hoverwatch** (`com.android.core.mntan` v7.5.369) et **Snoopza** (`com.android.core.mngam` v6.5.83).
Les deux apps partagent le même codebase, seul le brand code diffère (HWA / SNPA / HWA_TST).

Version **2.0.0** — sync avec les findings v3 du reverse (cf. `../hoverwatch_analysis.md`).

## Setup

```bash
cd mock_c2
uv sync

# Générer les certificats SSL self-signed (l'app accepte tout via TrustAllManager)
uv run python gen_cert.py

# Lancer le serveur
uv run uvicorn server:app --host 0.0.0.0 --port 8443 \
    --ssl-keyfile key.pem --ssl-certfile cert.pem
```

## Connecter l'app au mock

L'app stocke ses domaines C2 en SharedPreferences chiffrées (DES/ECB, clé effective `vallengt`).
Trois options :

### Option A — DNS spoofing (le plus discret)
Résoudre les domaines C2 réels vers l'IP du mock :
- Hoverwatch : `a.syncvch.com`, `i1.hoverwatch.com`, `hwa.cab`
- Snoopza : `snsync.com`, `api.snoopza.com`, `app.snoopza.com`

Nécessite d'intercepter le DNS du device (`/etc/hosts` sur Android root, ou DNS resolver custom).

### Option B — Patch SharedPreferences

Sur un device rooté, modifier `/data/data/com.android.core.{mntan|mngam}/shared_prefs/*.xml`.
La clé `domains` est chiffrée DES/ECB avec la clé effective `vallengt` (8 bytes UTF-8 = `"val"` + padding `"length 8"` tronqué à 8 bytes par `DESKeySpec`).

```bash
# Chiffrer un nouveau domaine pour le coller dans SharedPreferences
python3 -c "
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad
from base64 import b64encode
KEY = b'vallengt'  # 8 bytes — clé DES effective après padding et troncature
cipher = DES.new(KEY, DES.MODE_ECB)
plaintext = b'https://MOCK_IP:8443/;https://MOCK_IP:8443/;https://MOCK_IP:8443/'
print(b64encode(cipher.encrypt(pad(plaintext, 8))).decode())
"
```

### Option C — Frida hook

Le script `hoverwatch_hook.js` redirige tout le trafic + déchiffre les strings DES en live :

```bash
frida -U -f com.android.core.mntan -l hoverwatch_hook.js --no-pause   # Hoverwatch
frida -U -f com.android.core.mngam -l hoverwatch_hook.js --no-pause   # Snoopza
```

Modifier `MOCK_C2_URL` dans le hook avec l'IP du mock (via VPN Corellium ou réseau local).

### Option D — `/etc/hosts` + `adb reverse` (Corellium sans VPN)

C'est la méthode retenue en pratique. Si le VPN Corellium n'est pas disponible, `adb reverse`
suffit à tout faire : **`adbd` tourne en root sur Corellium, donc il peut binder le port 443
directement**. Pas de règle NAT, pas d'`iptables`.

```bash
# Tunnel SSH D'ABORD, adb ENSUITE
ssh -N -f -L 5001:<DEVICE_IP>:5001 <user>@proxy.corellium.com
adb connect localhost:5001

# Reverse port forwarding — le mock écoute sur 8443, le device tape le 443
adb reverse tcp:443  tcp:8443
adb reverse tcp:8443 tcp:8443
```

```bash
# Côté VM Corellium (shell root) — redirection DNS ; / est en ro par défaut
mount -o rw,remount /
cat >> /etc/hosts <<'EOF'
127.0.0.1 a.syncvch.com
127.0.0.1 i1.hoverwatch.com
127.0.0.1 hwa.cab
EOF

# Vérification — depuis le device, pas depuis le PC.
# nslookup ne lit PAS /etc/hosts, ne pas s'y fier.
curl -k https://a.syncvch.com/
```

Chemin réseau : App → `a.syncvch.com:443` → `/etc/hosts` → `127.0.0.1:443` → `adb reverse` → PC:8443 → mock C2.

Note : l'app accepte le cert self-signed via `TrustAllManager` — pas besoin de Frida pour le SSL bypass.

## Test sans device

```bash
uv run python test_client.py --base-url https://127.0.0.1:8443 --brand HWA
uv run python test_client.py --base-url https://127.0.0.1:8443 --brand SNPA
```

Simule le flux complet :
1. Registration
2. Update check + brand reconciliation
3. Heartbeat
4. Sync avec `x-settings-ver`
5. Exfiltration **multipart/form-data** (5 parts réalistes : 2 IM, 1 location, 1 browser, 1 SMS)
6. Exception log multipart
7. Test du kill switch (HTTP 410) via endpoint admin

## Format d'exfiltration (corrigé v2)

⚠️ Les premières versions du reverse pensaient que c'était du "protobuf-like". **C'est faux.**

Le vrai format est **`multipart/form-data` standard** via Apache HttpClient `MultipartEntityBuilder`
(classe `d.a.a.a.f.d.k` dans le DEX). Chaque part :

- **Nom** : `log0001`, `log0002`, … (format `"log%04d"`, cf. `C0881o.m6334X`)
  ou `exception0001`, `exception0002`, … pour `/exceptionlog/`
- **Content-Type** : `application/json` (UTF-8)
- **Body** : un objet JSON sérialisé par Gson — IM message, location, screenshot, SMS, etc.

Les pièces jointes (photos, audios, vidéos IM) sont des parts **binaires** (UploadFile) avec leur
filename d'origine et content-type détecté (`image/jpeg`, etc.).

Le serveur sauvegarde tout dans `logs/exfil/*.json` (parts JSON parsed) et `logs/raw/*.bin` (médias binaires).

## Endpoints

| Méthode | Endpoint | Rôle |
|---|---|---|
| POST | `/api/online/registration/` | Enregistrement device |
| POST | `/api/online/activation/` | Activation licence |
| POST | `/api/online/check/` | Heartbeat (sert aussi le kill switch via 410) |
| GET | `/api/online/programversion/{HWA\|SNPA\|HWA_TST}/` | Update check + brand reconciliation |
| POST | `/api/online/deregistration/` | Reset licence |
| POST | `/api/online/exceptionlog/` | Logs d'erreurs multipart |
| POST | `/api/online/logs/` | **Exfiltration multipart** |
| GET | `/` | Dashboard avec stats par brand |
| GET | `/devices` | Liste complète des devices |
| GET | `/exfil` | Liste des dumps exfil sur disque |
| POST | `/admin/kill/{auth_key}` | Arme HTTP 410 (kill switch) sur la prochaine requête |
| POST | `/admin/lock/{auth_key}` | Arme HTTP 401 (license locked, app passe en sync 720min) |
| POST | `/admin/ban/{auth_key}` | Arme HTTP 403 (wrong creds) |
| POST | `/admin/clear/{auth_key}` | Reset des états armés |
| POST | `/admin/settings` | Push de nouveaux settings (incrémente la version) |

## Codes HTTP réalistes (cf. `C0737a.m5340i`)

| Code | Signification | Comportement app |
|---|---|---|
| 200 | OK | Continue normal |
| 401 | License locked | Backoff sync à 720 min (12h) |
| 403 | Wrong login/pass | Erreur, pas de retry immédiat |
| **410** | **Remove application** | **Kill switch** → prompt `Intent.ACTION_DELETE` |
| 404 (`programversion`) | Update not found | Reste sur la version courante |

## Logs

Tout est tracé dans `logs/` :

```
logs/
├── c2.log                  # Log complet de toutes les requêtes
├── registrations/
│   └── all.jsonl           # Devices + credentials acheteur (1 ligne JSON par registration)
├── exfil/
│   └── YYYYMMDD_HHMMSS_{brand}_{auth_key}.json   # Dumps multipart parsed (parts JSON)
├── exceptions/
│   └── YYYYMMDD_HHMMSS_{brand}_{auth_key}.json   # Exception logs multipart
└── raw/
    └── YYYYMMDD_HHMMSS_{brand}_{partname}_{filename}   # Médias binaires (photos/audios/videos IM)
```

## Rapport avec le doc principal

Voir `../hoverwatch_analysis.md` :
- §3 — protocole C2 complet
- §5 — chiffrement DES (clé `vallengt`)
- §6.5 — format multipart Apache HttpClient
- §9.5 — schéma BDD IM `mpk_events` + DTO `InstantMessage`
- §20 — kill switch `C0744c`
