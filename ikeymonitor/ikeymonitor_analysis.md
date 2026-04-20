# Rapport d'Analyse Forensique — iKeyMonitor Android v17.4

**Analyste :** Sébastien Larinier — ASTRA/LHS-LORIA  
**Date :** 2026-04-20  
**Sample :** `Ikeymonitor-Android_from_Panel.apk`  
**Package :** `com.sec.android.internet.im.service.im20210815`  
**Version :** 17.4 (versionCode 322)  
**Target SDK :** 29 (Android 10) — **compileSdk 33 (Android 13)**  
**Min SDK :** 21 (Android 5.0)  
**Package applicatif réel :** `com.p025as.monitoringapp`  
**sharedUserId :** `android.uid.system` — revendique les privilèges système  
**Application class :** `com.p025as.monitoringapp.logging.MyApplication`

---

## 1. Dissimulation & Identité

L'APK se fait passer pour une application Samsung légitime via son package name (`com.sec.android.internet.im.service.im20210815`) qui imite la nomenclature Samsung (`com.sec.android.*`). Le code applicatif réel réside dans `com.p025as.monitoringapp`. Toutes les activités sont configurées avec `excludeFromRecents="true"` pour ne pas apparaître dans le task switcher. L'activité `TrialPage` expose un deep link `smartkey://` pour l'activation depuis le navigateur. L'application utilise `ProcessPhoenix` (librairie de Jake Wharton) pour se relancer en cas de crash de l'AccessibilityService.

---

## 2. Permissions (53 permissions demandées)

### Surveillance active
| Catégorie | Permissions |
|---|---|
| **Localisation** | `ACCESS_FINE_LOCATION`, `ACCESS_COARSE_LOCATION`, `ACCESS_BACKGROUND_LOCATION` |
| **Communications** | `READ_SMS`, `RECEIVE_SMS`, `READ_CALL_LOG`, `WRITE_CALL_LOG`, `CALL_PHONE`, `PROCESS_OUTGOING_CALLS`, `READ_CONTACTS`, `WRITE_CONTACTS` |
| **Caméra/Micro** | `CAMERA`, `RECORD_AUDIO`, `CAPTURE_AUDIO_OUTPUT` |
| **Écran** | `FOREGROUND_SERVICE_MEDIA_PROJECTION` |
| **Navigateur** | `READ_HISTORY_BOOKMARKS`, `WRITE_HISTORY_BOOKMARKS` |
| **Calendrier** | `READ_CALENDAR` |
| **Comptes** | `GET_ACCOUNTS`, `READ_PROFILE` |
| **Téléphone** | `READ_PHONE_STATE`, `READ_PRIVILEGED_PHONE_STATE` |

### Persistance & furtivité
| Catégorie | Permissions |
|---|---|
| **Boot** | `RECEIVE_BOOT_COMPLETED` |
| **Overlay** | `SYSTEM_ALERT_WINDOW` |
| **Batterie** | `REQUEST_IGNORE_BATTERY_OPTIMIZATIONS` |
| **Icône** | `INSTALL_SHORTCUT`, `UNINSTALL_SHORTCUT` |
| **Settings** | `WRITE_SETTINGS`, `READ_SETTINGS` |
| **Accessibilité** | `BIND_ACCESSIBILITY_SERVICE` |
| **Notifications** | `BIND_NOTIFICATION_LISTENER_SERVICE` |
| **Auto-update** | `REQUEST_INSTALL_PACKAGES`, `REQUEST_DELETE_PACKAGES` |

---

## 3. Infrastructure C2

### Serveurs HTTP (REST API)

Domaine principal : `https://ikmws.awsapi.io` (configurable dynamiquement)

Serveurs miroirs WebSocket (fallback, hardcodés dans `MyApplication.f1909r`) :

- `https://ikmws-mirror.awsapi.io`
- `https://ikm-sv2.awsapi.io`
- `https://ikm-sv3.awsapi.io`
- `https://ikm-sv4.awsapi.io`

Domaines dans `network_security_config.xml` : `awsapi.io`, `emcpanel.com`

### Endpoints REST (25 endpoints PHP identifiés)

Classe source : `p070j.C2089e` — compilée depuis `Constants.java`

| Endpoint | Fonction |
|---|---|
| `/index.php?m=api&a=register` | Enregistrement du device |
| `/index.php?m=api&a=reset_password` | Reset mot de passe |
| `/index.php?m=api&a=cycle` | Cycle d'upload périodique |
| `/index.php?m=api&a=account` | Informations compte |
| `/index.php?m=api&a=get_settings` | Récupération config distante |
| `/index.php?m=api&a=set_settings` | Modification config distante |
| `/index.php?m=api&a=get_websocket_address` | Adresse WebSocket dynamique |
| `/index.php?m=api&a=uoload_keystrokes` | Exfiltration keylogger (typo d'origine) |
| `/index.php?m=api&a=uoload_chat_logs` | Exfiltration chats (typo d'origine) |
| `/index.php?m=api&a=uoload_website_history` | Exfiltration historique web |
| `/index.php?m=api&a=uoload_call_history` | Exfiltration journal d'appels |
| `/index.php?m=api&a=uoload_gps_history` | Exfiltration historique GPS |
| `/index.php?m=api&a=upload_chat_img` | Exfiltration images de chats |
| `/index.php?m=api&a=upload_call_img` | Exfiltration images d'appels |
| `/index.php?m=api&a=upload_Wifi` | Exfiltration info WiFi |
| `/index.php?m=api&a=upload_clipboard` | Exfiltration presse-papiers |
| `/index.php?m=api&a=upload_photo` | Exfiltration photos |
| `/index.php?m=api&a=surrounding` | Exfiltration enregistrement ambiant |
| `/index.php?m=api&a=upload_screenvideo` | Exfiltration vidéo d'écran |
| `/index.php?m=api&a=upload_video` | Exfiltration vidéo caméra |
| `/index.php?m=api&a=contact` | Exfiltration contacts |
| `/index.php?m=api&a=calendar` | Exfiltration calendrier |
| `/index.php?m=api&a=get_screenshot` | Commande screenshot à la demande |
| `/index.php?m=api&a=check_update` | Vérification MAJ |
| `/index.php?m=api&a=download_update` | Téléchargement MAJ |
| `/index.php?m=api&a=upload_debug_logs` | Upload logs debug |
| `/index.php?m=api&a=upload_weekly_crash_logs` | Upload crash logs hebdo |
| `/index.php?m=api&a=schedule_surround` | Planification enregistrement ambiant |

**Note :** Les typos `uoload` (au lieu de `upload`) dans 4 endpoints sont présentes dans le code source original — IOC fingerprint exploitable pour des rules de détection réseau.

### Canal WebSocket (temps réel)

Classe source : `p027d.C1800c` — compilée depuis `MyWebSocketOper.java`

Protocole : **XML custom encapsulé** dans des messages WebSocket texte.

Format de réponse APK → serveur :
```xml
<IKMService>
  <RequestType>{type}</RequestType>
  <RequestId>{id}</RequestId>
  <Ret>{code}</Ret>
  <Logstype>5</Logstype>
  <Client>{device_id}</Client>
  <License>{license_key}</License>
  <WSTimeStamp>{unix_timestamp}</WSTimeStamp>
</IKMService>
```

Commandes WebSocket identifiées (serveur → APK) :

| Commande | Effet |
|---|---|
| `Camera` (Enable=1, Type=front/back) | Capture photo à distance |
| `Screenshots` (Enable=1) | Capture d'écran à la demande |
| `ScreenshotVideo` (Enable=1, SignTimeStamp) | Stream vidéo écran via RTMP |
| `Surrounding` (Enable=1) | Enregistrement audio ambiant en temps réel |

Codes de retour (`<Ret>`) :
- `1` = succès / exécution en cours
- `6` = écran éteint / fonctionnalité indisponible
- `7` = erreur RTMP
- `8` = arrêt enregistrement

### Streaming RTMP (screen mirroring)

L'APK supporte le **streaming vidéo en temps réel** de l'écran via RTMP :

```
rtmp://{server}/{device_id}?sign={signature}-{md5}
```

Signature construite : `MD5("/live/" + device_id + "-" + sign_timestamp + "-" + secret)`

Secret RTMP hardcodé : `C4hgdA%Qc5UHfqEho&Ke` (champ `f4849b` dans `C2089e`)

---

## 4. Chiffrement

### C2 payload signing

Algorithme : **DESede/ECB/PKCS5Padding** (Triple DES en mode ECB)

Classe : `p128r.C3443z.m7234b()` — compilée depuis `Utility_ContentInfo.java`

Clé hardcodée : `ccc707d2924768f2cc12bc8b` (24 bytes = 3DES)

Utilisation : signature des requêtes C2 pour authentification. Le plaintext (license key) est chiffré avec 3DES-ECB puis encodé en hex + Base64.

**Analyse critique :**
- ECB mode = pas d'IV, patterns reproductibles → trivial à casser
- Clé hardcodée dans l'APK = extraction immédiate
- Pas de PFS (Perfect Forward Secrecy)
- Pas de rotation de clé

### TLS

Config réseau : **aucun certificate pinning**. L'APK trust les certificats user ET system, et autorise le cleartext traffic. Interception MITM triviale avec Burp/mitmproxy + certificat user installé.

Custom TrustManager dans `MyApplication` : `C3559e.m8026c()` — implémente un TrustManager custom (probable bypass de validation).

---

## 5. Abus de l'Accessibility Service

Classe : `com.android.internet.Stenographer_Service`

Configuration (`stenographer_config.xml`) :
- `accessibilityEventTypes="typeAllMask"` — intercepte **tous** les événements
- `accessibilityFeedbackType="feedbackAllMask"`
- `canRetrieveWindowContent="true"` — lit le contenu de toutes les fenêtres
- Flags : `flagRetrieveInteractiveWindows`, `flagReportViewIds`, `flagIncludeNotImportantViews`

### Fonctionnalités via AccessibilityService

**Keylogging** : `Acc_InputText.onNewText()` — capture tous les `TYPE_VIEW_TEXT_CHANGED` events, y compris dans les champs de texte de toutes les applications. Exclut les champs `isPassword()`. Stocke en DB locale puis exfiltre via l'endpoint `uoload_keystrokes`.

**Interception de chats** : `Sts_chats.Deal_Chat_Info()` — intercepte les messages affichés dans les apps de messagerie via scraping de l'arbre d'accessibilité.

Apps de messagerie ciblées (classes `GetChatInfo_*` identifiées) :

- WhatsApp (`com.whatsapp`)
- Telegram
- Facebook Messenger
- WeChat (`com.tencent.mm`)
- Line
- Viber
- Signal
- Snapchat
- Zalo

**Interception web** : `Sts_web.getWebHisr()` — capture les URLs visitées via l'AccessibilityService.

**Anti-désinstallation** : `handleAccessibilityEvent()` effectue un `goBack()` (via `performGlobalAction(1)`) quand l'utilisateur accède aux paramètres d'accessibilité de l'app (Samsung et Android stock) pour empêcher la désactivation du service.

**Clipboard** : `sendBroadcastToGetClip()` — exfiltration du presse-papiers via `Get10ClpInfoReceiver` (Android 10+ via broadcast).

---

## 6. Persistance

| Mécanisme | Implémentation |
|---|---|
| **Boot receiver** | `StartupReceiver` + `BOOT_COMPLETED` (priority MAX_INT) |
| **Foreground service** | `BackService` avec notification permanente |
| **AlarmManager** | GPS polling + screenshot polling périodique |
| **ContentObserver** | Observateurs sur SMS, contacts, calendrier, call log |
| **NetworkChangeReceiver** | Redémarrage sur changement réseau / WiFi |
| **ProcessPhoenix** | Restart complet de l'app si AccessibilityService crash |
| **onLowMemory** | Relance `BackService` en cas de pression mémoire |
| **LicenseReceiver** | Vérification périodique de la licence |
| **Multi-receiver** | 8 BroadcastReceivers enregistrés dynamiquement |

---

## 7. Exfiltration de données

Cycle d'upload périodique (`RunnableC1556b`) : toutes les **5 minutes** (300 000 ms), l'APK exécute une collecte complète :
- Photos
- Chats (via DB root OU AccessibilityService)
- Browser history
- Contacts, calendrier, SMS, call log
- Keystrokes
- Clipboard
- GPS
- WiFi info
- Screenshots (via AlarmManager, intervalle configurable à distance)

L'upload passe par les endpoints REST listés en §3. Les fichiers média (photos, screenshots, vidéos) sont uploadés via des endpoints dédiés multipart.

### Health Check XML

L'APK envoie un rapport d'état au C2 (XML) incluant :
- État de l'AccessibilityService
- État de l'UsageAccess
- Permission root
- Statut Google Play Protect
- Battery optimization
- Présence d'apps de sécurité tierces

---

## 8. Auto-update

L'APK vérifie les MAJ via `check_update` et peut télécharger et installer silencieusement une nouvelle version via `download_update` + `REQUEST_INSTALL_PACKAGES`.

---

## 9. ACRA (crash reporting)

L'APK utilise **ACRA** (Application Crash Reports for Android) pour collecter les crash dumps, envoyés au C2 via `upload_weekly_crash_logs`. Processus dédié `:acra`.

---

## 10. Indicateurs de Compromission (IOCs)

### Domaines
- `ikmws.awsapi.io` (C2 principal)
- `ikmws-mirror.awsapi.io` (miroir WS)
- `ikm-sv2.awsapi.io`
- `ikm-sv3.awsapi.io`
- `ikm-sv4.awsapi.io`
- `emcpanel.com` (panel d'administration)

### Signatures réseau
- User-Agent : OkHttp 3.x
- Endpoints avec typo `uoload` (au lieu de `upload`) dans les URL paths
- Payloads XML contenant `<IKMService>` dans les WebSocket frames
- RTMP streams avec paramètre `?sign=` + MD5

### Artefacts filesystem
- Répertoire de logs : `/ikm_logs/`
- Fichiers debug : `bkservices_1.txt`, `Accessib.txt`, `AccUpload.txt`, `scre1en_test.txt`, `ScreenVideo.txt`, `photo_l_o_g.txt`, `LocalSurrRecord.txt`, `exception_file.txt`
- Package name : `com.sec.android.internet.im.service.im20210815`
- Deep link scheme : `smartkey://`
- SharedPreferences : `AccessibilityPreference`

### Crypto
- Clé 3DES hardcodée : `ccc707d2924768f2cc12bc8b`
- Secret RTMP hardcodé : `C4hgdA%Qc5UHfqEho&Ke`

### Actions broadcast internes
- `B.k_BackgWork`, `B.k.BackClipAc`, `Screen.Ac.ATION`, `RecLic.Ac.licRecATION`, `ACTION_.CHECK._WEBSOCKET`, `ACTION_.CHECK._ALIVE`, `S.Start.SS`, `S.End.SS`

---

## 11. Comparaison avec Hoverwatch & MTF

| Critère | iKeyMonitor v17.4 | Hoverwatch v7.5 | MTF |
|---|---|---|---|
| **Canal C2** | REST + WebSocket XML | REST PHP | REST + dual C2 |
| **Chiffrement** | 3DES/ECB (clé 24B hardcodée) | DES/ECB (clé hardcodée) | — |
| **SSL Pinning** | Aucun | Aucun | — |
| **Endpoints** | ~25 PHP | ~37 PHP | 60+ FCM cmds |
| **Streaming** | RTMP (écran + audio) | — | WebRTC |
| **Keylogger** | AccessibilityService | AccessibilityService | AccessibilityService |
| **Chat interception** | 9 apps ciblées (Accessibility) | — | — |
| **Persistance** | 8 receivers, ProcessPhoenix | — | — |
| **Auto-update** | Oui (silent install) | — | — |
| **Typos IOCs** | `uoload` dans 4 endpoints | — | — |
| **Crash reporting** | ACRA | — | — |

---

## 12. Pistes pour le mock C2

Pour construire un mock C2 fonctionnel en lab :

1. **Serveur REST** : FastAPI avec les 25 endpoints PHP mappés. L'APK utilise des form-data standard.

2. **Serveur WebSocket** : écoute sur l'adresse retournée par `get_websocket_address`. Envoyer des commandes XML avec les tags `Camera`, `Screenshots`, `ScreenshotVideo`, `Surrounding` encapsulés dans un envelope XML custom.

3. **Serveur RTMP** : nginx-rtmp ou un simple serveur RTMP pour recevoir les streams écran. L'URL est construite côté client, il faut juste servir le bon endpoint.

4. **DNS redirect** : pointer `ikmws.awsapi.io` et les miroirs vers le lab via `/etc/hosts` ou DNS local.

5. **Certificat** : pas besoin de bypass SSL pinning — l'APK trust les certificats user. Un cert mitmproxy standard suffit.

6. **Frida hooks potentiels** : hooker `C3443z.m7234b()` pour logger les payloads avant chiffrement 3DES, et `C1803f.m3421q()` pour intercepter les messages WebSocket sortants.
