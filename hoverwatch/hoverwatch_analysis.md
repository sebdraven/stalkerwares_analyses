# Hoverwatch v7.5.369 — Analyse complète

> **Package** : `com.android.core.mntan`
> **Version** : 7.5.369 (versionCode 369)
> **Target SDK** : 33 (Android 13)
> **Min SDK** : 19 (Android 4.4)
> **Obfuscation** : ProGuard — package renommé `p094hw` (hw = Hoverwatch)
> **Application** : `com.utils.core.CoreApplication`
> **Outil** : JADX MCP

---

## 1. Manifest — Permissions

### 1.1 Permissions de surveillance (19)

| Permission | Usage |
|------------|-------|
| `RECEIVE_SMS` / `READ_SMS` | Interception SMS |
| `READ_CALL_LOG` / `WRITE_CALL_LOG` / `PROCESS_OUTGOING_CALLS` | Journal d'appels |
| `READ_CONTACTS` | Contacts |
| `READ_CALENDAR` | Calendrier |
| `ACCESS_FINE_LOCATION` / `ACCESS_COARSE_LOCATION` / `ACCESS_BACKGROUND_LOCATION` | Géolocalisation (y compris background) |
| `READ_PHONE_STATE` / `READ_PHONE_NUMBERS` / `READ_PRIVILEGED_PHONE_STATE` | Identifiants téléphone (IMEI, numéro) |
| `RECORD_AUDIO` / `MODIFY_AUDIO_SETTINGS` | Enregistrement micro |
| `CAMERA` | Photos |
| `READ_EXTERNAL_STORAGE` / `WRITE_EXTERNAL_STORAGE` / `MANAGE_EXTERNAL_STORAGE` | Fichiers |
| `READ_LOGS` | Logs système |
| `GET_ACCOUNTS` | Comptes utilisateur |
| `READ_HISTORY_BOOKMARKS` | Historique navigateur |
| `PACKAGE_USAGE_STATS` | Apps utilisées |

### 1.2 Permissions de furtivité (stealth)

| Permission | Usage |
|------------|-------|
| `SYSTEM_ALERT_WINDOW` | Overlay (masquer l'app) |
| `REQUEST_IGNORE_BATTERY_OPTIMIZATIONS` | Empêcher l'arrêt par le système |
| `FOREGROUND_SERVICE` | Service persistant |
| `RECEIVE_BOOT_COMPLETED` | Survie au redémarrage |
| `WAKE_LOCK` | Maintien du processeur actif |
| `REQUEST_INSTALL_PACKAGES` / `REQUEST_DELETE_PACKAGES` | Auto-update / auto-suppression |
| `QUERY_ALL_PACKAGES` | Lister toutes les apps installées |
| `INTERACT_ACROSS_USERS` / `INTERACT_ACROSS_USERS_FULL` | Multi-profil (nécessite signature) |

---

## 2. Architecture — Composants

### 2.1 Services

| Classe | Rôle | Détails |
|--------|------|---------|
| `p094hw.utils.ServiceCore` | Orchestration | foregroundServiceType=location |
| `p094hw.recorder.ServiceRecording` | Enregistrement audio | process `:r` séparé |
| `p094hw.utils.ServiceScr` | Capture écran | foregroundServiceType=mediaProjection |
| `p094hw.imreader.ReaderAccessibilityService` | Interception IM | AccessibilityService |
| `p094hw.imreader.ReaderNotificationService` | Lecture notifications | NotificationListenerService |

### 2.2 Receivers

| Classe | Trigger | Rôle |
|--------|---------|------|
| `ReceiverBoot` | `BOOT_COMPLETED` (priority=100) | Redémarrage auto |
| `ReceiverOutgoingCall` | `NEW_OUTGOING_CALL` / `PHONE_STATE` | Interception appels |
| `ReceiverChangeConnection` | `CONNECTIVITY_CHANGE` / `WIFI_STATE_CHANGED` | Trigger sync réseau |
| `ReceiverUserPresent` | `USER_PRESENT` + lockscreen tiers | Détection déverrouillage |
| `ReceiverPowerEvents` | Événements batterie | Monitoring batterie |
| `ReceiverAirplaneMode` | `AIRPLANE_MODE` | Détection mode avion |
| `ReceiverAlarm` | Alarmes périodiques | Tâches planifiées |
| `ReceiverMsg` | Messages internes | Communication inter-services |

### 2.3 Activities

| Classe | Rôle |
|--------|------|
| `ActivityMainStarter` | Launcher principal (excludeFromRecents=true) |
| `ActivityDblStarter` | Double launcher (icône alternative) |
| `ActivityMain` | Interface de contrôle |
| `ActivityTrScr` | Activité transparente (overlay furtif, singleInstance, noHistory) |
| `ActivityInstaller` | Assistant installation/configuration |
| `ActivityWidget` | Widget anodin (point d'accès caché) |

**Notes** :
- `excludeFromRecents="true"` sur toutes les activités → invisible dans les apps récentes
- Process séparé `:r` pour l'enregistrement audio → survie indépendante

---

## 3. Protocole C2 — Classe `p092e.p093a.C0736a`

### 3.1 Identification client

| Champ | Valeur |
|-------|--------|
| User-Agent | `Android Monitor 7.5.369` |
| Client ID | `HWA` (prod), `HWA_TST` (test), `SNPA` (variante) |
| Auth header | `x-auth-key: {ActivationID}` |
| Settings header | `x-settings-ver: {version}` |
| Event header | `x-client-event: {event_data}` |

### 3.2 Endpoints API

| Endpoint | Méthode | Auth | Usage |
|----------|---------|------|-------|
| `api/online/registration/` | POST (JSON) | Non | Enregistrement device |
| `api/online/activation/` | POST (JSON) | Non | Activation licence |
| `api/online/check/` | POST | Non | Ping / vérification domaine |
| `api/online/programversion/HWA/` | GET | Non | Vérification mise à jour |
| `api/online/deregistration/` | POST | Oui | Reset licence |
| `api/online/exceptionlog/` | POST (protobuf) | Oui | Envoi logs d'erreurs |
| `api/online/logs/` | POST (protobuf) | Oui | **Exfiltration données collectées** |

### 3.3 Registration — Données envoyées

```json
{
  "username": "<email_acheteur>",
  "password": "<password_acheteur>",
  "hid": "and:<device_hardware_id>",
  "device_name": "<modele_telephone>",
  "client_ver": "7.5.369",
  "os_ver": "<android_version>",
  "user_type": 0,
  "device.dev_mac_adr_str": "<mac_wifi>",
  "device.dev_mac2_adr_str": "<mac_secondaire>",
  "device.dev_serial_num_str": "<serial>",
  "device.dev_imei_str": "<imei>",
  "device.dev_accounts_str": "<comptes_google>",
  "device.perm_118": "<état_permission>",
  "device.perm_121": "<état_permission>",
  "device.perm_116": "<état_permission>",
  "device.perm_101": "<état_permission>",
  "device.perm_102": "<état_permission>",
  "device.perm_103": "<état_permission>",
  "device.perm_129": "<état_permission>",
  "device.perm_130": "<état_permission>",
  "device.perm_128": "<état_permission>"
}
```

### 3.4 Registration — Réponse serveur

```json
{
  "status": "ok",
  "auth_key": "<activation_id>",
  "valid_through": "2026-12-31 23:59:59",
  "subscription": "<type_abonnement>",
  "domains": "https://domain1.com:443/;https://domain2.com:443/",
  "client_pin": "<code_pin>"
}
```

### 3.5 Codes de réponse HTTP

| Code | Signification | Action client |
|------|---------------|---------------|
| 200 | OK | Continue |
| 400 | Request unrecognized | Erreur |
| 401 | License locked | Augmente période sync à 720 min |
| 403 | Wrong login/pass | Erreur |
| 404 | Update not found | Ignoré |
| 409 | License limit | Erreur |
| **410** | **Remove application** | **Auto-désinstallation (kill switch)** |
| 413 | Request entity too large | Erreur |
| 422 | Unprocessable Entity | Erreur |
| 500 | Server error | Erreur |
| 502 | Bad Gateway | Erreur |

### 3.6 Gestion des domaines C2

- Format : `https://domain1.com:443/;https://domain2.com:443/`
- **Rotation automatique** : en cas d'échec, domaine déplacé en fin de liste
- **Mise à jour dynamique** : le serveur envoie de nouveaux domaines via registration/activation
- Normalisation forcée : ajout `https://` et `:443/` si absents
- Fallback : si domaine échoue pendant >3h, rotation vers le suivant

---

## 4. Sécurité SSL — Classe `p092e.p093a.C0739d`

**AUCUNE** vérification SSL :

```java
// TrustManager — accepte TOUT
public void checkClientTrusted(X509Certificate[] chain, String type) { }
public void checkServerTrusted(X509Certificate[] chain, String type) { }
public X509Certificate[] getAcceptedIssuers() { return null; }

// HostnameVerifier — accepte TOUT
public boolean verify(String hostname, SSLSession session) { return true; }
```

→ Vulnérable au MITM, tout proxy peut intercepter le trafic C2

---

## 5. Chiffrement — Classe `p094hw.utils.C0870h`

### 5.1 Algorithme

**DES en mode ECB** — pas de IV, pas de chaînage.

```java
SecretKey key = SecretKeyFactory.getInstance("DES")
    .generateSecret(new DESKeySpec(keyStr.getBytes(UTF_8)));
Cipher cipher = Cipher.getInstance("DES");  // = DES/ECB/PKCS5Padding
cipher.init(DECRYPT_MODE, key);
return new String(cipher.doFinal(Base64.decode(input)));
```

### 5.2 Clé par défaut

| Usage | Clé brute | DESKeySpec (8 octets) |
|-------|-----------|----------------------|
| SharedPreferences (ActivationID, Password, domains, Subscription) | `"val"` → padded `"vallength 8"` | `vallength` (8 premiers octets) |
| Strings obfusquées dans le code | idem | idem |

### 5.3 Déchiffrement forensique

```python
from Crypto.Cipher import DES
import base64
key = b"vallenge"  # 8 premiers octets de "val" + "length 8"
# Note: DESKeySpec prend les 8 premiers octets de "vallength 8" = "valleng" + padding
cipher = DES.new(key, DES.MODE_ECB)
plaintext = cipher.decrypt(base64.b64decode(ciphertext))
```

### 5.4 Vulnérabilités cryptographiques

1. **DES** — cassé depuis 1998 (56 bits)
2. **ECB** — patterns visibles dans le chiffré
3. **Clé `"val"` hardcodée** → tout est déchiffrable
4. **Pas de IV** → même plaintext = même ciphertext
5. **Pas de MAC/HMAC** → modification silencieuse possible

---

## 6. Collecteurs de données

### 6.1 Architecture d'exfiltration

```
Collecteurs (Services/Receivers/ContentObservers)
    ↓ écriture
Base de données SQLite locale (AbstractC0746c / AbstractC0748e)
    ↓ lecture batch
Sérialiseur protobuf-like (p082d.p083a.p084a.p085a)
    ↓ POST HTTPS
C2 server (api/online/logs/)
```

### 6.2 Liste des collecteurs

| ID | Nom | Classe | Données |
|----|-----|--------|---------|
| 302 | Screenshots | `p053c.p077c.p079b.C0611d` | Captures d'écran périodiques (JPEG qualité 40%) |
| 304 | IM Reader | `p053c.p077c.p081d.C0626d` | Messages IM via AccessibilityService (100+ apps) |
| 305 | Browser | `p053c.p077c.p081d.C0626d` | URLs visitées (44+ navigateurs) |
| 312 | Call Recording | `p094hw.recorder.ServiceRecording` / `C0856j` | Enregistrements audio/appels |
| 313 | SMS | `p053c.p077c.p081d.C0626d` | SMS via Google Messages + apps dynamiques |
| 314 | Location | `p053c.p077c.p080c.C0616e` | GPS + WiFi BSSID + Cell ID |
| 319 | Front Camera | config `frcam` | **Photos silencieuses caméra frontale** |
| — | Keylogger | config `keys` | **Frappes clavier via AccessibilityService** |
| — | Contacts | `C0747d` (ContentObserver) / config `contact` | Contacts via ContentProvider |
| — | Call Log | `C0747d` (ContentObserver) | Journal d'appels via ContentProvider |
| — | Calendar | `C0747d` (ContentObserver) / config `calendar` | Événements calendrier |
| — | SIM Monitor | config `sim` | Monitoring changement de carte SIM |
| — | Files Monitor | config `files` | Monitoring fichiers (photos, documents) |
| — | App Usage | config `app` | Applications installées/lancées |

### 6.3 Flux de synchronisation (`m5329C`)

1. Vérification : licence valide + réseau dispo + délai respecté
2. Si WiFi : acquisition `WifiLock` pour maintenir la connexion
3. Ping serveur (`api/online/check/`)
4. Parse settings serveur (header `x-settings-ver`)
5. Envoi exception logs (`api/online/exceptionlog/`)
6. Envoi event logs (`api/online/logs/`)
7. Envoi données de chaque collecteur (`AbstractC0746c.m5458p()`)
8. Update timestamp `SyncServerLastTime`

### 6.4 Configuration distante — Classe `p094hw.utils.C0887y`

Le serveur C2 contrôle chaque module à distance via un objet `settings` envoyé dans la réponse registration/activation. Config par défaut hardcodée dans `m6527x()` :

```json
{
  "settings": {
    "version": 1,
    "on": true,
    "debug": false,
    "onlyWiFi": false,
    "period": 10,
    "autoupdate": { "on": false },
    "location": { "on": true, "period": 10, "acc": 1000 },
    "contact": { "on": true },
    "call": { "on": true, "rec": true, "source": 4, "quality": 1, "codec": 2, "gain": false },
    "sms": { "on": true, "shot": false },
    "chat": { "on": true, "shot": false, "rec": true },
    "url": { "on": true, "shot": false },
    "sim": { "on": false },
    "calendar": { "on": true },
    "frcam": { "on": true, "photo": true },
    "shot": { "on": false, "period": 5 },
    "files": { "on": true, "shot": false },
    "app": { "on": true, "shot": false },
    "keys": { "on": true, "shot": false }
  }
}
```

Chaque module supporte :
- `on` — activer/désactiver le module
- `shot` — déclencher un screenshot sur événement
- `rec` — déclencher un enregistrement audio sur événement (chat, appels VoIP)

Paramètres audio (`call`) :
- `source` — AudioSource Android : 1=MIC, 4=VOICE_COMMUNICATION (défaut), 6=VOICE_RECOGNITION, 7=VOICE_CALL. Adaptation par fabricant : Samsung→7, Huawei→6
- `quality` — 0=basse, 1=moyenne (défaut), 2=haute
- `codec` — codec d'encodage (défaut=2)
- `gain` — amplification du gain audio (activé par défaut sur Android ≥ 28)

Paramètres localisation :
- `period` — intervalle de collecte en minutes (défaut=10)
- `acc` — précision minimum en mètres (défaut=1500)

Paramètres screenshots :
- `period` — intervalle en minutes (défaut=5)

**Implication critique** : l'acheteur/abuseur peut activer à distance le keylogger, la caméra frontale, les screenshots, et l'enregistrement audio depuis le portail web Hoverwatch.

---

## 7. Enregistrement audio — `p094hw.recorder.ServiceRecording`

- **Process séparé** (`:r`) → survit à l'arrêt du service principal
- Deux slots : `C0846c(10)` (10 min max) et `C0846c(300)` (5h max)
- Trois modes : `OFFHOOK` (détection appel), `RECORD` (enregistrement), `STOP`
- **Views invisibles** (`LinearLayout` ajoutées au `WindowManager`) pour empêcher Android de tuer le service
- Notification foreground avec ID `110111` → invisible
- Détection auto des appels VoIP via AccessibilityService (WhatsApp, etc.)

---

## 8. Capture d'écran — `p053c.p077c.p079b.C0611d`

- **MediaProjection** + `VirtualDisplay` + `ImageReader`
- Compression JPEG **qualité 40%** (faible poids → exfiltration rapide)
- Max **5 captures par session**
- Relancé toutes les **24h** via `ReceiverAlarm`
- **Android < 30 uniquement** (restrictions Google depuis Android 11)
- VirtualDisplay nommé `"Second-screen"` (tente de passer inaperçu)
- Permission obtenue une fois via `ScreenshotCheckerActivity` puis réutilisée via `PendingIntent`

---

## 9. Interception IM — `p094hw.imreader.ReaderAccessibilityService`

### 9.1 Mécanisme

Utilise l'**AccessibilityService** pour parser l'arbre d'accessibilité des apps cibles. Pour chaque app, un parser dédié (ex: `C0776p` pour WhatsApp) navigue dans les `AccessibilityNodeInfo` en utilisant les **resource IDs** des éléments UI :

```
com.whatsapp:id/conversations_row_contact_name → nom du contact
com.whatsapp:id/conversation_contact_name → nom dans la conv
com.whatsapp:id/conversation_root_layout → layout racine
com.whatsapp:id/date → horodatage
com.whatsapp:id/thumb → média thumbnail
com.whatsapp:id/sticker_image → stickers
com.whatsapp:id/call_screen → détection appel
com.whatsapp:id/ringing_dots → appel sortant
com.whatsapp:id/toggle_video_btn → appel vidéo
```

### 9.2 Données interceptées

Structure `InstantMessage` :
- `_time_stamp` — horodatage du message
- `_seen_time` — quand le message a été vu
- `_from` — expéditeur
- `_msg_text` — contenu textuel
- `_msg_type` — type (texte=0, image=1, sticker=5, vidéo=6)
- `_direction` — `INBOUND` / `OUTBOUND`
- `_index` — index dans la conversation

### 9.3 Parsers IM identifiés

| Classe | App | Package |
|--------|-----|---------|
| `C0776p` | WhatsApp | `com.whatsapp` |
| `C0764d` | Facebook Messenger | `com.facebook.orca` |
| `C0769i` | Instagram | `com.instagram.android` |
| `C0765e` | Viber | `com.viber.voip` |
| `C0766f` | Telegram | `org.telegram.messenger` |
| `C0771k` | Skype | `com.skype.raider` |
| `C0773m` | Snapchat | `com.snapchat.android` |
| `C0774n` | LINE | `jp.naver.line.android` |
| `C0775o` | KakaoTalk | `com.kakao.talk` |
| `C0762b` | Générique | Autres apps |

### 9.4 Interception des appels VoIP

Le parser WhatsApp détecte aussi les appels VoIP :
- `accept_incoming_call_view` → appel entrant accepté
- `ringing_dots` → appel sortant en cours
- `toggle_video_btn` → bascule audio/vidéo
- `participant_list` → participants (appels de groupe)
- `surface_view` → flux vidéo détecté

---

## 10. Applications ciblées — Classe `p053c.p077c.p081d.C0626d`

### 10.1 Messageries (54 apps, flag 304)

**Messaging** : WhatsApp, Facebook Messenger, Viber, Telegram, Telegram Plus, Google Hangouts, Google Chat, Google Meet, Snapchat, imo, LINE, LINE Lite, TextMe, Kik, WeChat, Signal, Discord, Microsoft Teams, KakaoTalk, Threema Work, Threema OnPrem, Vidogram, Zalo, Slack, Slack Intune, BBM Enterprise

**Social** : Instagram, VK Messenger, VKontakte, Odnoklassniki, TikTok, TikTok Lite, Tumblr, Weico (Weibo), Reddit, Twitter/X, Skype

**Dating (10 apps — IPV)** : Tinder, Tinder RU, Mamba, Pure, Fitil, Wamba, Muzmatch, Skylove, Boo, Waplog, Galaxy (RU)

**Email** : Gmail, Yandex Mail, Mail.ru, BlueMail, Outlook, Outlook Lite, Samsung Email

### 10.2 Navigateurs (44+ apps, flag 305)

Chrome, Firefox, Opera, Opera Mini, UC Browser, Yandex Browser, **Tor Browser**, DuckDuckGo, Edge, Samsung Internet, Brave, Kiwi, Cromite, Huawei Browser, MIUI Browser, Vivo Browser, OPPO/Heytap Browser, ASUS Browser, Sony Browser, HTC Browser, Quark, TCL, Adblock Plus, et ~20 autres

### 10.3 SMS (flag 313)

Google Messages + apps ajoutables dynamiquement via config serveur

### 10.4 Observations

- **100+ apps** ciblées au total
- **Fort biais russophone** : VK, OK, Yandex, Mail.ru, Mamba, Tinder RU, Galaxy
- **10 apps de dating** → surveillance relationnelle / IPV
- **Signal et Threema** ciblées via Accessibility → **contourne le chiffrement E2E**
- **Tor Browser** ciblé → tentative de surveiller la navigation anonyme
- **Config dynamique** : le serveur peut ajouter des apps à surveiller à distance
- **Strings chiffrées** : certains packages obfusqués via `C0870h.m6219c()` (DES)

---

## 11. Géolocalisation — Classe `p053c.p077c.p080c.C0616e`

### 11.1 Données collectées

```json
{
  "loc": {
    "cat": 1,
    "crd": [48.8566, 2.3522],
    "acc": 15.0,
    "spd": 25.2,
    "ssid": "MonWifi",
    "bssid": "AA:BB:CC:DD:EE:FF",
    "cellid": "208-01-1234-5678"
  }
}
```

### 11.2 Base de données locale

```sql
-- Événements GPS
CREATE TABLE mpk_events (
    _id INTEGER PRIMARY KEY AUTOINCREMENT,
    uuid VARCHAR NOT NULL,
    status INTEGER DEFAULT 0 NOT NULL,
    latitude FLOAT,
    longitude FLOAT,
    category INTEGER NOT NULL,
    speed INTEGER,
    accuracy FLOAT,
    cellid VARCHAR,
    bssid VARCHAR,
    ssid VARCHAR
);

-- Cache WiFi (BSSID → coordonnées)
CREATE TABLE mpk_wifi_location (
    bssid VARCHAR PRIMARY KEY,
    ssid VARCHAR,
    mnc INTEGER DEFAULT -1,
    lac INTEGER DEFAULT -1,
    date INTEGER,
    moveable INTEGER DEFAULT 0,
    latitude FLOAT,
    longitude FLOAT,
    category INTEGER NOT NULL,
    accuracy FLOAT
);

-- Cache cellulaire
CREATE TABLE mpk_cell_location (
    cellid VARCHAR PRIMARY KEY,
    mnc INTEGER DEFAULT -1,
    mcc INTEGER DEFAULT -1,
    lac INTEGER DEFAULT -1,
    cid INTEGER DEFAULT -1,
    date INTEGER,
    latitude FLOAT,
    longitude FLOAT,
    category INTEGER NOT NULL,
    accuracy FLOAT
);
```

---

## 12. Settings / État — Classe `p094hw.utils.C0888z`

| Clé SharedPreferences | Type | Usage |
|-----------------------|------|-------|
| `ActivationID` | String (DES) | Clé d'authentification C2 |
| `Password` | String (DES) | PIN de l'acheteur |
| `domains` | String (DES) | Liste des domaines C2 |
| `EnableMonitor` | Boolean | Activation surveillance |
| `HideIcon` | Boolean | Masquer l'icône launcher |
| `PinProtect` | Boolean | Protection par PIN |
| `ValidThrough` | Long | Timestamp expiration licence |
| `Subscription` | String (DES) | Type abonnement |
| `AppInstState` | Int (enum) | NOT_INSTALLED / INSTALLED / UNINSTALL_ASK |
| `SyncServerLastTime` | Long | Dernier sync réussi |
| `SynchServerLastTime` | Long | Dernier sync (variante) |
| `SettingsVersion` | Long | Version settings serveur |
| `Version` | String | Version app |
| `DebugMode` | Boolean | Mode debug |
| `MemoryLimit` | Boolean | Limite mémoire atteinte |
| `UserPermState-{id}` | Int | État de chaque permission |
| `UserPermSent-{id}` | Boolean | Permission reportée au serveur |

### 12.1 Gestion de licence

- **Validité** : `ValidThrough` + 7 jours de grâce (604800000 ms)
- **Verrouillage** : `ValidThrough` + 42 jours (3628800000 ms)
- **Période sync normale** : 5 min
- **Période sync erreur licence** : 720 min (12h)
- **Kill switch** : code 410 → `C0743c.m5397a()` (auto-désinstallation)

---

## 13. Vulnérabilités identifiées

| # | Vulnérabilité | Sévérité | Impact |
|---|---------------|----------|--------|
| 1 | Pas de vérification SSL (TrustAll + HostnameVerifier=true) | **CRITIQUE** | MITM trivial |
| 2 | DES/ECB avec clé hardcodée `"val"` | **CRITIQUE** | Déchiffrement de toutes les données locales |
| 3 | Services/Receivers exportés (`exported="true"`) | **HAUTE** | Contrôle local par app tierce |
| 4 | Kill switch distant (HTTP 410) | **HAUTE** | Suppression preuves à distance |
| 5 | Pas de certificate pinning | **HAUTE** | Proxy interception sans modification APK |
| 6 | Credentials acheteur récupérables | **HAUTE** | Identification de l'abuseur via forensics |
| 7 | Domaines C2 en clair après déchiffrement DES | MOYENNE | IOC extraction facilitée |
| 8 | Screenshots JPEG qualité 40% | FAIBLE | Qualité faible mais suffisante pour lire du texte |
| 9 | Notifications foreground vides | FAIBLE | Détectable (Android 13+) |
| 10 | Keylogger via AccessibilityService | **HAUTE** | Capture de tous les mots de passe saisis |
| 11 | Caméra frontale silencieuse (module 319) | **HAUTE** | Photos de la victime à son insu |
| 12 | Configuration modules à distance | **HAUTE** | L'abuseur active/désactive la surveillance sans accès physique |

---

## 14. Mapping des classes obfusquées

| Classe obfusquée | Nom réel | Rôle |
|------------------|----------|------|
| `p094hw` | `hw` | Package principal Hoverwatch |
| `p092e.p093a.C0736a` | `HttpClient` | Client HTTP C2 |
| `p092e.p093a.C0737b` | `NetworkUtils` | Vérification réseau |
| `p092e.p093a.C0739d` | `TrustAllManager` | TrustManager permissif |
| `p094hw.utils.C0888z` | `Settings` | SharedPreferences / état |
| `p094hw.utils.C0870h` | `CryptoHelper` | Chiffrement DES |
| `p094hw.utils.C0874l` | `Logger` | Logging interne |
| `p094hw.utils.C0877o` | `Utils` | Utilitaires divers |
| `p094hw.utils.C0887y` | `ModuleConfig` | Configuration des modules |
| `p094hw.utils.C0873k` | `EventTracker` | Tracking événements |
| `p094hw.utils.C0863b0` | `AppConstants` | Constantes globales |
| `p053c.p077c.p081d.C0626d` | `TaskSendEvents` | Collecteur IM/Browser/SMS |
| `p053c.p077c.p080c.C0616e` | `ObserverLocation` | Collecteur GPS |
| `p053c.p077c.p079b.C0611d` | `ScreenCapture` | Capture d'écran |
| `p094hw.imreader.C0776p` | `WhatsAppParser` | Parser WhatsApp |
| `p094hw.imreader.C0764d` | `MessengerParser` | Parser Facebook Messenger |
| `p094hw.imreader.C0769i` | `InstagramParser` | Parser Instagram |
| `p094hw.recorder.C0856j` | `AudioRecorder` | Enregistrement audio |
| `p094hw.database.C0751h` | `IMDatabase` | Base messages IM |
| `p094hw.database.C0747d` | `ContentObserverCollector` | Collecteur ContentProvider |
| `p094hw.core.C0743c` | `UninstallManager` | Auto-désinstallation |

---

## 15. TODO

- [x] Analyser le protocole C2 complet (endpoints, auth, codes HTTP)
- [x] Documenter le chiffrement DES et la clé hardcodée
- [x] Identifier les 100+ apps ciblées (IM, navigateurs, dating)
- [x] Analyser le service d'enregistrement audio
- [x] Analyser la capture d'écran (MediaProjection)
- [x] Analyser l'interception IM (AccessibilityService + parsers WhatsApp, etc.)
- [x] Documenter la géolocalisation (GPS + WiFi + Cell + schéma SQL)
- [x] Extraire la configuration distante (settings JSON, modules)
- [x] Identifier les modules keylogger (keys) et caméra frontale (frcam/319)
- [x] Générer la spec JSON complète du protocole C2 (`hoverwatch_c2_protocol.json`)
- [ ] Déchiffrer les strings obfusquées (`C0870h.m6219c()`) pour extraire les packages cachés
- [ ] Extraire les domaines C2 par défaut (hardcodés ou dans les ressources)
- [ ] Analyser `C0743c` — mécanisme d'auto-désinstallation (kill switch)
- [ ] Analyser le format protobuf des logs exfiltrés (`p082d.p083a.p084a.p085a`)
- [ ] Documenter le schéma complet de la BDD des messages IM (`C0751h`)
- [ ] Analyser `ActivityInstaller` — procédure de setup (permissions, accessibility)
- [ ] Vérifier s'il y a du code natif (`.so`) → Kharon
- [ ] Coder un mock C2 server pour tester les signatures Suricata
- [ ] Tester le déchiffrement DES avec la clé `"val"` sur des SharedPreferences réelles
