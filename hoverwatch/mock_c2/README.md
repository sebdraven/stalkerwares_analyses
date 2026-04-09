# Hoverwatch Mock C2 Server

Mock C2 qui simule le backend Hoverwatch pour analyse dynamique du stalkerware.
Basé sur le reverse engineering du protocole v7.5.369 (package `com.android.core.mntan`).

## Setup

```bash
cd mock_c2

# Générer les certificats SSL self-signed (l'app accepte tout de toute façon)
uv run python gen_cert.py

# Lancer le serveur
uv run uvicorn server:app --host 0.0.0.0 --port 8443 --ssl-keyfile key.pem --ssl-certfile cert.pem
```

## Connecter l'app Hoverwatch au mock

L'app stocke ses domaines C2 en SharedPreferences chiffrées (DES/ECB, clé `"val"`).
Deux options :

### Option A — DNS spoofing (plus simple)
Résoudre le domaine C2 réel vers l'IP du mock. Nécessite d'intercepter le DNS du device.

### Option B — Patch SharedPreferences
Sur un device rooté, modifier le fichier `shared_prefs` de l'app :
```bash
# Chiffrer le nouveau domaine avec la clé DES
python3 -c "
from Crypto.Cipher import DES
import base64
key = b'vallenge'  # 8 premiers octets de 'vallength 8'
cipher = DES.new(key, DES.MODE_ECB)
domain = b'https://MOCK_IP:8443/'
# Pad to 8 bytes
padded = domain + b'\x00' * (8 - len(domain) % 8)
print(base64.b64encode(cipher.encrypt(padded)).decode())
"
```

### Option C — Frida hook
Hooker `C0888z.m6611x()` pour retourner l'URL du mock :
```javascript
Java.perform(function() {
    var Settings = Java.use("p094hw.utils.C0888z");
    Settings.m6611x.implementation = function() {
        return "https://MOCK_IP:8443/";
    };
});
```

## Test sans device

```bash
uv run python test_client.py --base-url https://127.0.0.1:8443
```

Simule le flux complet : registration → heartbeat → update check → sync → exfiltration → exceptions.

## Endpoints

| Endpoint | Rôle |
|----------|------|
| `POST /api/online/registration/` | Enregistrement device |
| `POST /api/online/activation/` | Activation licence |
| `POST /api/online/check/` | Heartbeat |
| `GET /api/online/programversion/HWA/` | Check update |
| `POST /api/online/deregistration/` | Reset licence |
| `POST /api/online/exceptionlog/` | Logs d'erreurs |
| `POST /api/online/logs/` | **Exfiltration** |
| `GET /` | Dashboard |
| `GET /devices` | Liste des devices enregistrés |
| `GET /exfiltrated` | Données exfiltrées |
| `POST /admin/kill/{auth_key}` | Simuler le kill switch (HTTP 410) |
| `POST /admin/settings` | Pousser de nouveaux settings |

## Logs

Tout est loggé dans `logs/` :
- `c2.log` — log complet de toutes les requêtes
- `registrations.jsonl` — devices enregistrés avec credentials acheteur
- `exfiltrated.jsonl` — metadata des données exfiltrées
- `dump_*.bin` — dumps binaires bruts des payloads exfiltrés
