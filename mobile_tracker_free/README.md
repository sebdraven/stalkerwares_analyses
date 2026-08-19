# Mobile Tracker Free — Mock C2 Server

Mock C2 qui simule le backend de **Mobile Tracker Free** (MTF) pour l'analyse
dynamique en lab du payload `phone.monitor2026` (v161/v162).

Reversé depuis `mtf_c2_analysis.md` + `mtf_payload_analysis.md`.
Lab setup complet dans `mtf_corellium_lab_setup.md`.

> **Research use only** — ASTRA / LHS-LORIA.

---

## Architecture C2 réelle (3 canaux)

MTF n'a pas un seul canal comme Hoverwatch : il en fait tourner **trois** en parallèle.

```
                          ┌──────────────────────────┐
                          │   Dashboard abuseur       │
                          │ mobile-tracker-free.com   │
                          └────────────┬─────────────┘
                                       │
        ┌──────────────────┬───────────┴───────────┬──────────────────┐
        ▼                  ▼                       ▼                  
┌───────────────┐  ┌───────────────┐      ┌───────────────┐
│ Firebase FCM  │  │ HTTPS Retrofit│      │  Socket.IO    │
│ DOWNLINK      │  │ UPLINK        │      │  LIVE (WebRTC)│
│ commandes     │  │ exfiltration  │      │  file explorer│
└───────┬───────┘  └───────┬───────┘      └───────┬───────┘
        │                  │                      │
        └──────────────────┼──────────────────────┘
                           ▼
                  ┌──────────────────┐
                  │ phone.monitor2026│  ← victime
                  └──────────────────┘
```

| Canal | Sens | Rôle | Couvert par le mock ? |
|---|---|---|---|
| **HTTPS Retrofit** | montant | exfiltration (37 endpoints `.php`) | ✅ intégralement |
| **Firebase FCM** | descendant | commandes (`action` FCM) | ⚠️ par procuration (voir plus bas) |
| **Socket.IO** | bidir | live streaming / file explorer | ❌ hors périmètre |

### Le downlink FCM — pourquoi « par procuration »

Le mock **ne peut pas** pousser un vrai message FCM : il faudrait la *server key*
du projet Firebase `myappmobile-537f7` (sender `38496474107`), qu'on n'a pas —
seule l'**API key cliente** est présente dans l'APK. Donc le downlink passe par
`adb am broadcast` vers le `FirebaseInstanceIdReceiver` **exporté** (même technique
que `mtf_cmd_trigger.py`), piloté depuis l'admin API du serveur. Les accusés de
réception reviennent naturellement sur le canal montant via `remoteControl/setLog.php`
et sont **corrélés par `idLog`**.

---

## Ports

| Port | Proto | Rôle |
|---|---|---|
| `8443` | HTTPS | sink d'exfiltration (TLS, cert mock). Redirigé depuis 443 par iptables sur la VM + `adb reverse tcp:8443` |
| `8080` | HTTP | admin/stats en clair (dashboard, pilotage des commandes, `/docs`) |

---

## Quickstart

```bash
# 1. Dépendances (déjà déclarées dans pyproject.toml)
uv sync

# 2. Lancer le serveur — génère mock.crt / mock.key au premier lancement
uv run python mtf_c2_server.py

# options : --https-port 8443 --admin-port 8080 --host 0.0.0.0
```

Au démarrage le serveur crée `captures/` et, si absents, `mock.crt` + `mock.key`
(self-signed, SAN large).

---

## ⚠️ Certificat obligatoire dans le system trust store

**Contrairement à Hoverwatch** (qui a un `TrustManager` trust-all), MTF utilise le
**vrai** `X509TrustManagerExtensions.checkServerTrusted()`. Le cert mock **doit**
être installé dans le *system* trust store Android, sinon le handshake TLS échoue
silencieusement et **aucune** requête n'atteint le mock.

Le SAN du cert couvre : `mobile-track-data.com`, `mobile-tracker-free.com`,
`tracker-free.com`, `localhost`, `127.0.0.1`, `10.11.1.1`, `10.0.2.2`.

Installation sur la VM (shell root) :

```bash
adb push mock.crt /sdcard/mock.crt
```
```bash
# sur le device
HASH=$(openssl x509 -inform PEM -subject_hash_old -in /sdcard/mock.crt | head -1)
mount -o rw,remount /
cp /sdcard/mock.crt /system/etc/security/cacerts/${HASH}.0
chmod 644 /system/etc/security/cacerts/${HASH}.0
mount -o ro,remount /
```

Détails réseau (DNS sinkhole `/etc/hosts`, blocage FCM, iptables 443→8443,
`adb reverse`) : voir `mtf_corellium_lab_setup.md` §3-4.

---

## Endpoints d'exfiltration (uplink :8443)

Le serveur encaisse **tout** `POST /{path}.php` (route fourre-tout), sur le chemin
principal **et** le fallback `/scriptsV5/`, et répond selon la famille reversée.

### Familles de réponse

| Famille | Attendu par l'APK | Endpoints |
|---|---|---|
| `m3129l` (JSON) | JSONObject | `user/verifPhone.php`, `user/savePhone.php`, `remoteControl/setLog.php` |
| `m3136t` (multipart) | texte `ok` | audio, photos, screenshots, call records, file explorer |
| `m3135s` (form-data) | texte `ok` | tout le reste (SMS, calls, contacts, location, IM…) |

### Traitements spéciaux

- `user/savePhone.php` → mint d'un `idPhone` (99999+) renvoyé dans `{"status":"ok","idPhone":N}`
- `user/verifPhone.php` → `{"status":"ok","nbPhone":1}`
- `pictures/setPicturePasswordFailed.php` → décode le Base64 du champ `data` en `.jpg`
- `remoteControl/setLog.php` → corrèle l'ACK de commande FCM par `idLog`
- parts multipart binaires → sauvées dans `captures/<cat>/files/`

Les 37 endpoints (dont les 19 IM no-root et 9+ IM root, y compris ceux avec
`urlScript` dynamique) sont tous absorbés sans énumération explicite.

---

## Admin API (:8080)

### Inspection

```bash
curl http://localhost:8080/_stats      | python3 -m json.tool   # compteurs globaux
curl http://localhost:8080/_devices                            # devices enregistrés
curl http://localhost:8080/_recent                             # 50 dernières requêtes
curl http://localhost:8080/_commands                           # commandes poussées + ACK
curl http://localhost:8080/_cmd_list                           # commandes disponibles
```

### Pilotage des commandes (downlink via adb)

```bash
# Commande nommée
curl -X POST "http://localhost:8080/admin/cmd/location"
curl -X POST "http://localhost:8080/admin/cmd/audio?arg=60"
curl -X POST "http://localhost:8080/admin/cmd/photo_front"
curl -X POST "http://localhost:8080/admin/cmd/screenshot"

# Cible un device précis si plusieurs adb connectés
curl -X POST "http://localhost:8080/admin/cmd/get_whatsapp?serial=emulator-5554"

# Commande FCM brute (le dernier --{idLog} sert de clé de corrélation)
curl -X POST "http://localhost:8080/admin/raw?action=GetLocation----42"
```

Chaque `POST /admin/cmd/*` fabrique l'`action` FCM, la pousse par `am broadcast`,
enregistre l'`idLog`, et se ferme quand le device confirme sur `setLog.php`.

### Vocabulaire de commandes (aligné sur `mtf_cmd_trigger.py`)

`location`, `loc_live_on/off`, `gps_on/off` · `photo_front[_flash]`, `photo_rear[_flash]` ·
`audio` · `screenshot`, `screenshot_mp` · `hide`, `show` · `lock`, `unlock`, `vibrate`,
`ring`, `tts`, `reboot` · `wifi_on/off`, `data_on/off` · `get_sms`, `get_calls`,
`get_contacts`, `get_history` · `get_facebook/whatsapp/telegram/instagram/viber/gmail` ·
`live_start/stop`, `file_explorer` · `sim_info`.

---

## Structure des captures

```
captures/
├── c2_server.log                    # log horodaté de toutes les requêtes
├── user/          *.json            # register / verif
├── sms/           *.json
├── calls/         *.json + files/   # + enregistrements d'appels
├── location/      *.json
├── recordAudio/   *.json + files/   # enregistrements micro
├── pictures/      *.json + files/   # photos + photo échec unlock
├── screenshot/    *.json + files/
├── fileExplorer/  *.json + files/
├── im_noroot/     *.json            # messageries via Accessibility/Notification
├── im_root/       *.json            # DB SQLite volées (root)
└── remoteControl/ *.json            # ACK des commandes FCM
```

---

## IOC réseau (rappel)

| Élément | Valeur |
|---|---|
| UA payload | `ILAHK20DKA8751LD9D729OJD6D7HJDK2AQMFT2019` |
| UA dropper | `KABNKNHFFHDHYD58698347556988AD89GH2020` |
| C2 principal | `mobile-track-data.com` |
| C2 fallback | `mobile-tracker-free.com/scriptsV5/` |
| Firebase | projet `myappmobile-537f7`, sender `38496474107` |
| Bascule fallback | locale `ru` ou `SocketException`/`UnknownHostException` |

---

## Fichiers

| Fichier | Rôle |
|---|---|
| `mtf_c2_server.py` | serveur mock (uplink sink + admin/downlink) |
| `mtf_cmd_trigger.py` | trigger FCM standalone via adb (alternative CLI à l'admin API) |
| `mtf_firebase_scanner.py` | scanner de config Firebase |
| `download_mtf_payload.py` | récupération du payload via le dropper |
| `mtf_c2_analysis.md` | protocole C2 complet |
| `mtf_payload_analysis.md` | capacités de collecte + liste des commandes FCM |
| `mtf_dropper_analysis.md`, `mtf_dropper_v3.9_analysis.md` | chaîne de dropper |
| `mtf_corellium_lab_setup.md` | procédure lab de bout en bout |

---

## Rapport avec les autres mocks du talk

Même finalité que `../hoverwatch/mock_c2/` et `../ikeymonitor/mock_c2/`, mais archi
distincte : là où Hoverwatch/iKeyMonitor pilotent le device par **WebSocket**, MTF
sépare exfiltration (HTTPS/PHP) et commandes (**FCM**), d'où le downlink par `adb`.
C'est le troisième cas d'étude du talk *Inside the Stalkerware Factory* (hack.lu 2026).
