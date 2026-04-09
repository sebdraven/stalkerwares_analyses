# Mobile Tracker Free — Payload Stalkerware — Analyse complète

> **Package** : `phone.monitor2026`
> **Version** : 161 (versionCode 524)
> **Target SDK** : 34 (Android 14) | **Min SDK** : 23 (Android 6.0)
> **Obfuscation** : R8 (map-id `3e94806707266205...`)
> **Application** : `com.app.activity.MyApp`
> **Outil** : JADX MCP
> **Date d'analyse** : 2026-04-09

---

## 1. Identification

`phone.monitor2026` est le **payload stalkerware** de Mobile Tracker Free, distribué via les droppers `com.mtf.download` (v2.7) et `com.mtf.protect` (v3.9). L'app se camoufle sous le nom **"Wi-Fi Service"** (`name_hide_app`) et son AccessibilityService se nomme **"Security Service"**.

Après installation, l'icône peut être masquée. L'accès caché se fait via un **code dialer secret** : composer `*1234*` (configurable via SharedPreferences `codeSecret`) ouvre `MainActivity` même avec l'icône cachée.

---

## 2. Permissions (45+)

### 2.1 Surveillance

| Permission | Capacité |
|------------|----------|
| `CAMERA` + features (front, autofocus, camera2) | Capture photo à distance |
| `RECORD_AUDIO` + `MODIFY_AUDIO_SETTINGS` | Enregistrement micro ambiant + appels |
| `ACCESS_FINE/COARSE/BACKGROUND_LOCATION` | Géolocalisation permanente |
| `READ_SMS` / `RECEIVE_SMS` / `SEND_SMS` / `RECEIVE_MMS` | Interception + envoi SMS/MMS |
| `READ_CALL_LOG` / `PROCESS_OUTGOING_CALLS` / `READ_PHONE_STATE` | Interception appels |
| `READ_CONTACTS` / `GET_ACCOUNTS` | Extraction contacts |
| `READ_CALENDAR` | Extraction calendrier |
| `READ_MEDIA_IMAGES` / `READ_MEDIA_VIDEO` / `MANAGE_EXTERNAL_STORAGE` | Accès fichiers |
| `QUERY_ALL_PACKAGES` | Inventaire applications |
| `PACKAGE_USAGE_STATS` | Statistiques d'usage apps |

### 2.2 Persistance et contrôle

| Permission | Capacité |
|------------|----------|
| `RECEIVE_BOOT_COMPLETED` | Démarrage au boot (priority 999) |
| `REQUEST_IGNORE_BATTERY_OPTIMIZATIONS` | Anti-kill batterie |
| `FOREGROUND_SERVICE` (5 types) | location, camera, microphone, mediaProjection, dataSync |
| `SYSTEM_ALERT_WINDOW` | Overlay sur autres apps |
| `SCHEDULE_EXACT_ALARM` | Alarmes exactes pour tâches planifiées |
| `WAKE_LOCK` / `DISABLE_KEYGUARD` | Maintien actif |
| `BIND_DEVICE_ADMIN` (via manifest) | **Device Admin** — anti-uninstall |
| `BIND_NOTIFICATION_LISTENER_SERVICE` | Interception notifications |
| `BIND_ACCESSIBILITY_SERVICE` | **AccessibilityService** — IM + keylogging |

### 2.3 Root et réseau

| Permission | Capacité |
|------------|----------|
| `ACCESS_SUPERUSER` | **Accès ROOT** — extraction DB IM |
| `REBOOT` | Redémarrage du téléphone (`su -c reboot now`) |
| `CHANGE_WIFI_STATE` / `CHANGE_NETWORK_STATE` | Contrôle WiFi/Data mobile |
| `CALL_PHONE` | Émission d'appels |
| `VIBRATE` | Vibration à distance |

---

## 3. Infrastructure C2

### 3.1 URLs et domaines

| Ressource | URL | Rôle |
|-----------|-----|------|
| `my_url` | `https://mobile-track-data.com/` | **C2 principal** — exfiltration données |
| `my_url_other` | `https://mobile-tracker-free.com/scriptsV5/` | **C2 fallback** — activé via SharedPrefs `urlOther` |
| Endpoint API | `remoteControl/setLog.php` | Logging des commandes distantes |
| Site web | `https://mobile-tracker-free.com/` | Dashboard abuseur |
| Aide | `https://mobile-tracker-free.com/help/` | |
| Inscription | `https://mobile-tracker-free.com/register/` | |

**Sélection de l'URL** (classe `kw1`) :
```java
sharedPrefs.getBoolean("urlOther", false) 
  ? getString(R.string.my_url_other)   // fallback
  : getString(R.string.my_url)          // principal
```

### 3.2 Firebase

| Paramètre | Valeur |
|-----------|--------|
| Project ID | `myappmobile-537f7` |
| Sender ID | `38496474107` |
| API Key | `AIzaSyDbUBsZ11AUjeuOW9e8g1azhCV3wmDKhQ0` |
| App ID | `1:38496474107:android:1437f8b679b84fe53ab15e` |
| Database | `https://myappmobile-537f7.firebaseio.com` |
| Storage | `myappmobile-537f7.firebasestorage.app` |
| Crashlytics git rev | `e3acc81c538dbe70c765e9c0eef0980bb1bbdbdf` |

Firebase est utilisé comme **canal C2 push** via FCM (Firebase Cloud Messaging). Analytics et Crashlytics sont désactivés (`false` dans le manifest).

### 3.3 Client HTTP (Retrofit)

**User-Agent stalkerware** (DIFFÉRENT du dropper) :
```
ILAHK20DKA8751LD9D729OJD6D7HJDK2AQMFT2019
```

Interface Retrofit `InterfaceC0091c` — 3 méthodes :
- `m833a` — POST form data → String (envoi de données texte)
- `m834b` — POST **multipart + file upload** → String (envoi enregistrements, captures, photos)
- `m835c` — POST form data → ResponseBody streaming

Timeouts : 15s connect / 30s read / 30s write.

### 3.4 Socket.IO

Socket.IO est utilisé pour les **communications temps réel** : live streaming vidéo/audio/écran, localisation live, et explorateur de fichiers distant.

---

## 4. Stealth (Camouflage)

| Technique | Détails |
|-----------|---------|
| **Nom affiché** | `"Wi-Fi Service"` (`name_hide_app`) |
| **Nom AccessibilityService** | `"Security Service"` (`app_name_accessibility`) |
| **Icon hide** | `FirstActivityAlias` activé par `@bool/app_icon_value` — toggle via FCM `hideIcon`/`showIcon` |
| **Code dialer secret** | `*1234*` (défaut, configurable) — ouvre l'app quand l'icône est cachée |
| **excludeFromRecents** | `true` sur toutes les activités |
| **noHistory** | `true` sur `FirstActivity`, `CheckingWarningActivity`, `BugAllActivity`, `ActivityRestriction` |
| **singleInstance** | Sur la majorité des activités |
| **Thème transparent** | `Theme.Transparent` sur 8 activités (capture caméra, TTS, live, audio) |
| **BOOT_COMPLETED** | Priority **999** — démarre avant la plupart des apps |
| **Device Admin** | `PolicyActivate$PolicyAdmin` — empêche la désinstallation, détecte les échecs de mot de passe |
| **Password SMS** | `"MobileTrackerFreeSMS"` (défaut) — mot de passe pour commandes SMS |
| **Dropper reference** | `name_package_download_app` = `com.mtf.protect` — détection/désinstallation du dropper |
| **OPPO fix** | `SettingsFixOppoAppActivity` — corrections spécifiques pour OPPO/Xiaomi |

---

## 5. Services de surveillance (25+)

### 5.1 Localisation (5 services)

| Service | Type foreground | Rôle |
|---------|----------------|------|
| `Localization` | location | Localisation principale |
| `ServiceLoc` | location | Localisation secondaire |
| `ServiceLocDashboard` | location | MAJ dashboard |
| `ServiceLocalization` | location | Géolocalisation continue |
| `LocLive` | location | **Tracking live temps réel** (Socket.IO) |

### 5.2 Audio (2 services)

| Service | Type | Rôle |
|---------|------|------|
| `AudioRecordService` | microphone | **Enregistrement micro ambiant** (3 types, durée configurable) |
| `RecordCallService` | microphone | **Enregistrement d'appels** (configurable : source, format, haut-parleur) |

### 5.3 Caméra (3 services)

| Service | Type | Rôle |
|---------|------|------|
| `ServiceTakePictureRemoteVersion1` | camera | Capture photo à distance v1 |
| `ServiceTakePictureRemoteVersion2` | camera | Capture photo à distance v2 (front/rear + flash) |
| `ServiceTakePicturePasswordFailed` | camera | **Photo automatique sur échec de mot de passe** |

### 5.4 Capture d'écran (4 services)

| Service | Type | Rôle |
|---------|------|------|
| `ServiceScreenshotRoot` | dataSync | Screenshot via root (`su`) |
| `ServiceScreenshotRemoteRoot` | dataSync | Screenshot remote via root |
| `ServiceScreenshotAuto` | dataSync | Screenshots automatiques (intervalle configurable, défaut 2h) |
| `ScreenRemoteService` | mediaProjection | Capture écran via MediaProjection |

### 5.5 LIVE Streaming (2 services)

| Service | Type | Rôle |
|---------|------|------|
| `LiveRTCVideoAudioService` | **microphone + camera** | **LIVE streaming vidéo+audio via WebRTC** |
| `LiveRTCScreenService` | **mediaProjection** | **LIVE streaming écran via WebRTC** |

### 5.6 Upload/Exfiltration (6 services)

| Service | Type | Process |
|---------|------|---------|
| `UploadCallService` | dataSync | main |
| `UploadDataService` | dataSync | main |
| `UploadRecordAudioService` | dataSync | main |
| `UploadScreenService` | dataSync | main |
| `UploadScreenRemoteService` | dataSync | main |
| `UploadPictureRemoteService` | dataSync | **`:uploaddpicture`** (process séparé) |

### 5.7 Fichiers et données (3 services)

| Service | Type | Process |
|---------|------|---------|
| `FileExplorerRemote` | dataSync | **`:fileexplorer`** (process séparé) |
| `UploadDataFileExplorer` | dataSync | **`:fileexplorerupload`** (process séparé) |
| `GetDataRootService` | dataSync | main — **extraction données ROOT** (DB IM) |

### 5.8 C2 et surveillance passive (6 services)

| Service | Rôle |
|---------|------|
| `MyFirebaseMTFMessagingService` | **Réception commandes FCM** (60+ commandes) |
| `NotificationListener` | **Interception notifications** (IM no-root) |
| `AccessService` | **AccessibilityService** — IM, web history, app blocking (30+ méthodes) |
| `ServiceObserver` | **ContentObserver** — SMS, MMS, photos, contacts, calendrier |
| `ServiceCheckSettings` | Vérification config |
| `ServiceUpdateInfoDashboard` | MAJ info dashboard |

---

## 6. Commandes FCM distantes (60+)

Le service `MyFirebaseMTFMessagingService` reçoit des commandes via Firebase Cloud Messaging. Le format est : `action--param1--param2--...` (split par `--`).

### 6.1 Contrôle du device

| Commande | Effet |
|----------|-------|
| `LockPhone--code--...--idLog` | Verrouille le téléphone avec un code |
| `UnLockPhone--...--idLog` | Déverrouille |
| `wipeData--...--idLog` | **Efface toutes les données** (via Device Admin) |
| `restartPhone--...--idLog` | **Redémarre** (`su -c reboot now`) |
| `Vibrate--durée--action--idLog` | Vibration |
| `Ring--durée--action--idLog` | Sonnerie |
| `Message--idLog--titre--message` | Affiche un message à l'écran |
| `TextSpeaker--texte--voix--idLog` | **Text-to-Speech** — fait parler le téléphone |

### 6.2 Caméra

| Commande | Effet |
|----------|-------|
| `TakePictureFront--type##flash--idLog` | Photo front(1)/rear(2), flash on/off |
| `disableCamera--...--idLog` | Désactive la caméra (Device Admin) |
| `enableCamera--...--idLog` | Réactive la caméra |

### 6.3 Audio

| Commande | Effet |
|----------|-------|
| `RecordAudio--durée--type--idLog` | Enregistrement micro (type 1/2/3, durée configurable) |

### 6.4 Capture d'écran

| Commande | Effet |
|----------|-------|
| `screenShot--...--idLog` | Screenshot via **root** |
| `takeScreenShot--...--idLog` | Screenshot via **MediaProjection** |

### 6.5 Localisation

| Commande | Effet |
|----------|-------|
| `GetLocation--...--idLog` | Récupère la position courante |
| `startLocLive--1/0--...--idLog` | Active/désactive le tracking live |
| `isActiveGPS` | Vérifie si le GPS est activé |
| `activateLocGPS` / `disabledLocGPS` | Active/désactive le GPS (root) |

### 6.6 Extraction IM (ROOT — lecture directe des DB SQLite)

| Commande | App | ID |
|----------|-----|-----|
| `getListFacebook` | Facebook Messenger | 20 |
| `getListCallsFacebook` | Facebook calls | 21 |
| `getListWhatsApp` / `getListCallsWhatsApp` | WhatsApp messages/calls | 3 / 2 |
| `getListInstagram` | Instagram | 4 |
| `getListTelegram` | Telegram | 5 |
| `getListKik` | Kik | 6 |
| `getListLine` | LINE | 7 |
| `getListHangouts` | Hangouts | 8 |
| `getListViber` / `getListCallsViber` | Viber messages/calls | 9 / 0 |
| `getListSkype` / `getListCallsSkype` | Skype messages/calls | 10 / 1 |
| `getListGmail` | Gmail | 11 |

### 6.7 Tracking IM (no-root — via Accessibility + Notifications)

20 apps ciblées : Facebook, WhatsApp, Viber, Skype, LINE, KIK, Tango, Hangouts, Telegram, WeChat, Snapchat, Tinder, Hike, Instagram, IMO, Twitter, Gmail, YouTube (history), Signal.

### 6.8 Extraction de données

`getListMessage` (SMS), `getListCall` (journal d'appels), `getListContacts`, `getListHistory` (historique web), `getListHistoryChrome`, `getListBookmarksChrome`, `getListBookmarks`.

### 6.9 Toggles de surveillance

`trackSMS`, `trackMMS`, `trackCalls`, `trackLoc`, `trackCalendar`, `trackContact`, `trackApps`, `trackPictures`, `trackScreenshot`, `trackClipboard`, `trackHistorique`, `trackPicLock`, `recordingCalls`, `trackBlockApps`, `trackBlockSite`.

### 6.10 Configuration à distance

`timeLoc` (intervalle localisation, min 15s), `timeMessagerie` (intervalle IM, min 15s), `timeVerifAll`, `screenshotSendTime` (intervalle screenshots), `sizeCallsLimit`, `sizeCallsLimitWIFI`, `sourceRecordCalls`, `typeAudioRecordCalls`, `configRecordCalls`, `handsFreeSpeakerCalls`, `increaseSoundCalls`, `passwordSMS`, `passwordLaunchApp`, `namePhone`.

### 6.11 Réseau

`activateWIFI` / `disabledWIFI`, `enabledDataMobile` / `disabledDataMobile`.

### 6.12 Blocage apps/sites

`addBlockApp`, `updateBlockApp`, `deleteBlockApp`, `blockSiteWeb`, `blockCalls`, `smsAlert`, `addRestriction`, `updateRestriction`, `deleteRestriction`.

### 6.13 Stealth / Admin

`hideIcon`, `showIcon`, `dashboardUpdate`, `settingsCheck`, `getAccessibility`, `getNotifications`, `getOptimizeBattery`, `getPlayP`, `refreshApps`, `refreshContacts`, `startLive`, `startFileExplorer`, `restartApp`, `deletePhone`, `sendSMS`, `getInfoSIM`.

---

## 7. ServiceObserver — ContentObservers

L'orchestrateur `ServiceObserver` surveille en temps réel via des `ContentObserver` :

| Provider surveillé | Données |
|-------------------|---------|
| `Telephony.Sms.CONTENT_URI` | SMS entrants/sortants |
| `Telephony.MmsSms.CONTENT_URI` | MMS |
| `MediaStore.Images.Media` (ext+int) | Nouvelles photos |
| `ContactsContract.Contacts` | Modifications contacts |
| `CalendarContract.Events` | Événements calendrier |

Chaque changement déclenche l'exfiltration automatique vers le C2.

---

## 8. CallReceived — Interception d'appels et code secret

### 8.1 Code dialer secret

```java
if (str.equals(getSharedPreferences("user", 0).getString("codeSecret", "*1234*"))) {
    m1022c(context);  // Ouvre MainActivity
}
```

Composer `*1234*` depuis le dialer ouvre l'UI cachée du stalkerware. Sur Xiaomi/OPPO, un délai de 2.5s est ajouté pour compatibilité.

### 8.2 Enregistrement d'appels

Le `CallReceived` gère jusqu'à **3 appels simultanés** (`phonenumber1/2/3`), avec :
- Détection entrant (RINGING) / sortant (NEW_OUTGOING_CALL) / actif (OFFHOOK)
- Démarrage automatique de `RecordCallService` si le tracking est activé
- Upload via `UploadCallService` à la fin de l'appel

### 8.3 Blocage d'appels

Via reflection sur `ITelephony.endCall()` — peut bloquer silencieusement des appels entrants de numéros spécifiques.

---

## 9. AccessService — 30+ méthodes

L'AccessibilityService est le **cœur de l'interception IM sans root**. Avec 30+ méthodes, il :
- Intercepte les messages envoyés/reçus dans les apps de messagerie ciblées
- Extrait l'historique de navigation web
- Bloque l'accès à certaines applications
- Surveille le contenu affiché à l'écran
- Facilite l'enregistrement d'appels (via Accessibility)
- Surveille l'historique YouTube

Strings d'identification des champs de saisie IM :
- Facebook : `"Write a message"` / `"Type a message"`
- WhatsApp : `"Message"`
- Instagram : `"message…"`
- Snapchat : `"Send a chat"`

---

## 10. MyApp — Initialisation

L'Application class enregistre dynamiquement 5 receivers :
- `ConnectionChangeReceived` — `CONNECTIVITY_CHANGE`
- `ScreenOFFReceived` — `SCREEN_OFF`
- `SMSReceived` — `SMS_RECEIVED`
- `AppsReceived` — `PACKAGE_ADDED/REPLACED/REMOVED`
- `BootReceived` — `USER_PRESENT`

Un `UncaughtExceptionHandler` custom est défini pour la résilience.

---

## 11. Indicateurs de compromission (IoC)

### 11.1 Réseau

| Indicateur | Type | Détails |
|------------|------|---------|
| `mobile-track-data.com` | Domaine C2 | Exfiltration principale |
| `mobile-tracker-free.com` | Domaine | Site web + C2 fallback (`/scriptsV5/`) |
| `remoteControl/setLog.php` | Endpoint | Logging commandes distantes |
| `ILAHK20DKA8751LD9D729OJD6D7HJDK2AQMFT2019` | User-Agent | **Stalkerware** (≠ dropper) |
| `KABNKNHFFHDHYD58698347556988AD89GH2020` | User-Agent | Dropper |

### 11.2 Firebase

| Indicateur | Valeur |
|------------|--------|
| Project ID | `myappmobile-537f7` |
| Sender ID | `38496474107` |
| API Key | `AIzaSyDbUBsZ11AUjeuOW9e8g1azhCV3wmDKhQ0` |

### 11.3 Hôte

| Indicateur | Type |
|------------|------|
| `phone.monitor2026` | Package actuel |
| `mobile.parental2025` / `com.protect2025` | Packages 2025 |
| `phone.child2024` / `phone.child2020` / `mobile.monitor.child2022` | Packages historiques |
| `com.app.activity.FirstActivity` | Activité principale |
| `com.app.activity.MyApp` | Application class |
| `com.app.service.MyFirebaseMTFMessagingService` | Service FCM |
| `com.app.service.AccessService` | AccessibilityService |
| `com.app.received.PolicyActivate$PolicyAdmin` | Device Admin |

### 11.4 Signatures Suricata

```suricata
# UA Stalkerware (DIFFÉRENT du dropper)
alert http $HOME_NET any -> $EXTERNAL_NET any (
    msg:"STALKERWARE MTF Payload - User-Agent";
    flow:established,to_server;
    http.user_agent;
    content:"ILAHK20DKA8751LD9D729OJD6D7HJDK2AQMFT2019";
    classtype:trojan-activity;
    sid:20260007; rev:1;
)

# C2 principal
alert http $HOME_NET any -> $EXTERNAL_NET any (
    msg:"STALKERWARE MTF Payload - C2 Domain";
    flow:established,to_server;
    http.host;
    content:"mobile-track-data.com";
    classtype:trojan-activity;
    sid:20260008; rev:1;
)

# C2 fallback
alert http $HOME_NET any -> $EXTERNAL_NET any (
    msg:"STALKERWARE MTF Payload - Fallback C2";
    flow:established,to_server;
    http.host;
    content:"mobile-tracker-free.com";
    http.uri;
    content:"scriptsV5";
    classtype:trojan-activity;
    sid:20260009; rev:1;
)

# Remote control endpoint
alert http $HOME_NET any -> $EXTERNAL_NET any (
    msg:"STALKERWARE MTF Payload - Remote Control";
    flow:established,to_server;
    http.uri;
    content:"remoteControl/setLog.php";
    classtype:trojan-activity;
    sid:20260010; rev:1;
)
```

---

## 12. Comparaison avec Hoverwatch

| Aspect | MTF (`phone.monitor2026`) | Hoverwatch |
|--------|--------------------------|------------|
| Services | 25+ | ~15 |
| Commandes FCM | 60+ | ~30 |
| IM ciblées (no-root) | 20 apps | ~10 |
| IM ciblées (root) | 11 apps | ~8 |
| Live streaming | WebRTC vidéo+audio+écran | Non |
| Explorateur fichiers distant | Oui (process séparé) | Non |
| Code dialer secret | `*1234*` | `*#900#` |
| Photo sur échec mdp | Oui | Non |
| TTS distant | Oui | Non |
| Blocage apps/sites | Oui (avec restrictions horaires) | Non |
| SMS commands | Oui | Non |
| Socket.IO live | Oui | Non |
| Envoi SMS depuis victime | Oui | Non |
| YouTube history | Oui | Non |
| Signal interception | Oui | Non |
| 3 appels simultanés | Oui | 1 seul |
| Processus séparés | 3 (photo, file explorer, upload) | 0 |

MTF est significativement plus sophistiqué que Hoverwatch, avec une surface d'attaque plus large et des capacités de contrôle à distance nettement supérieures.

---

## 13. MITRE ATT&CK Mobile — Mapping

| Technique | ID | Implementation MTF |
|-----------|----|--------------------|
| Boot Persistence | T1398 | `BOOT_COMPLETED` priority 999 |
| Input Capture | T1417 | AccessibilityService |
| Location Tracking | T1430 | 5 services de localisation |
| Capture Audio | T1429 | `AudioRecordService`, `RecordCallService` |
| Capture Camera | T1512 | 3 services caméra + photo sur échec mdp |
| Screen Capture | T1513 | 4 services screenshot + live MediaProjection |
| SMS/MMS Collection | T1636.004 | ContentObserver + receiver |
| Call Log Collection | T1636.002 | `CallReceived` + `UploadCallService` |
| Contact List | T1636.003 | ContentObserver |
| Notification Access | T1517 | `NotificationListener` |
| Device Admin | T1401 | `PolicyActivate$PolicyAdmin` |
| Masquerading | T1655 | "Wi-Fi Service", icon hide, transparent themes |
| Foreground Persistence | T1541 | 5 types de foreground service |
| C2 Channel | T1437 | Firebase FCM + HTTPS Retrofit + Socket.IO |
| Data Exfiltration | T1646 | Upload services (6+) vers `mobile-track-data.com` |
| Remote File Browsing | — | `FileExplorerRemote` (non-standard) |
| Remote Device Wipe | T1447 | `wipeData` via Device Admin |

---

## 14. TODO

- [ ] Analyser `AccessService.onAccessibilityEvent()` — dispatch par package name
- [ ] Extraire la logique `FileExplorerRemote` (explorateur de fichiers)
- [ ] Analyser `LiveRTCVideoAudioService` — protocole WebRTC/signaling
- [ ] Investiguer `GetDataRootService` — commandes `su` et extraction DB
- [ ] Mapper la base SQLite locale (SharedPreferences + DB)
- [ ] Analyser le module SMS commands (`SMSReceived` + `passwordSMS`)
- [ ] Extraire les endpoints PHP complets appelés côté serveur
- [ ] Résoudre DNS des domaines C2
- [ ] Corréler avec le dataset ASTRA
- [ ] Produire un case study LaTeX pour Kharon/FM 2026
