# Hoverwatch — Reverse Engineering du protocole C2

> **Package** : `com.android.core.mntan` (7.5.369) / `com.android.core.mntau` (7.5.385)
> **Versions analysées** : 7.5.369 (versionCode 369), 7.5.385 (versionCode 385)
> **Target SDK** : 33 (Android 13)
> **Obfuscation** : ProGuard — package renommé `p094hw` (hw = Hoverwatch)
> **Outil** : JADX MCP

---

## 1. Manifest — Permissions & Composants

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
| `GET_ACCOUNTS` | Comptes utilisateur (**utilisé aussi pour l'exfil SMTP, cf. §5**) |
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
| `INTERACT_ACROSS_USERS` / `INTERACT_ACROSS_USERS_FULL` | Multi-profil (tentative, nécessite signature) |

### 1.3 Composants clés

| Type | Classe | Rôle |
|------|--------|------|
| Service | `p094hw.utils.ServiceCore` | Orchestration (foregroundServiceType=location) |
| Service | `p094hw.recorder.ServiceRecording` | Enregistrement audio (process `:r` séparé) |
| Service | `p094hw.utils.ServiceScr` | Capture écran (foregroundServiceType=mediaProjection) |
| Service | `p094hw.imreader.ReaderAccessibilityService` | Interception notifications/IM via AccessibilityService |
| Service | `p094hw.imreader.ReaderNotificationService` | Listener de notifications |
| Receiver | `com.utils.receivers.ReceiverBoot` | Persistance au boot (priority=100) |
| Receiver | `com.utils.receivers.ReceiverOutgoingCall` | Interception appels sortants |
| Receiver | `com.utils.receivers.ReceiverChangeConnection` | Détection changement réseau → trigger sync |
| Receiver | `com.utils.receivers.ReceiverUserPresent` | Détection déverrouillage écran |
| Receiver | `com.utils.receivers.ReceiverPowerEvents` | Événements batterie |
| Receiver | `com.utils.receivers.ReceiverAirplaneMode` | Détection mode avion |
| Receiver | `p094hw.core.ReceiverAlarm` | Alarmes périodiques |
| Activity | `com.activities.ActivityMainStarter` | Launcher (excludeFromRecents=true) |
| Activity | `com.activities.ActivityDblStarter` | Double launcher (icône alternative) |
| Activity | `p094hw.installer.ActivityInstaller` | Assistant d'installation/configuration |
| Activity | `com.activities.ActivityTrScr` | Activité transparente (overlay furtif) |

**Notes** :
- `excludeFromRecents="true"` sur toutes les activités → invisible dans les apps récentes
- Double launcher (`ActivityMainStarter` + `ActivityDblStarter`) → deux icônes possibles pour le déguisement
- Process séparé `:r` pour l'enregistrement audio → survie indépendante du service principal
- Widget (`WidgetProvider`) → possibilité de masquer l'accès derrière un widget anodin

---

## 2. Protocole C2 — Classe `p092e.p093a.C0736a` (369) / `C0737a` (385)

### 2.1 Identification client

| Champ | Valeur |
|-------|--------|
| User-Agent | `Android Monitor <versionName>` (ex. `Android Monitor 7.5.385`) |
| Client ID | `HWA` (prod), `HWA_TST` (test), `SNPA` (variante Snoopza) |
| Auth header | `x-auth-key: {ActivationID}` |
| Settings header | `x-settings-ver: {version}` |
| Event header | `x-client-event: {event_data}` |

### 2.2 Endpoints API

| Endpoint | Méthode | Auth | Usage |
|----------|---------|------|-------|
| `api/online/registration/` | POST (JSON) | Non | Enregistrement device |
| `api/online/activation/` | POST (JSON) | Non | Activation licence |
| `api/online/check/` | POST | Non | Ping / vérification domaine |
| `api/online/programversion/HWA/` | GET | Non | Vérification mise à jour |
| `api/online/deregistration/` | POST | Oui | Reset licence |
| `api/online/exceptionlog/` | POST (protobuf) | Oui | Envoi logs d'erreurs |
| `api/online/logs/` | POST (protobuf) | Oui | **Exfiltration des données collectées** |

### 2.3 Registration — Données envoyées

```json
{
  "username": "<email_acheteur>",
  "password": "<password_acheteur>",
  "hid": "and:<device_hardware_id>",
  "device_name": "<modele_telephone>",
  "client_ver": "7.5.385",
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

### 2.4 Registration — Réponse serveur

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

### 2.5 Codes de réponse HTTP

| Code | Signification | Action client |
|------|---------------|---------------|
| 200 | OK | Continue |
| 400 | Request unrecognized | Erreur |
| 401 | License locked | Erreur, augmente période sync à 720 min |
| 403 | Wrong login/pass | Erreur |
| 404 | Update not found | Ignoré |
| 409 | License limit | Erreur |
| **410** | **Remove application** | **Auto-désinstallation (kill switch)** |
| 413 | Request entity too large | Erreur |
| 422 | Unprocessable Entity | Erreur |
| 500 | Server error, try later | Erreur |
| 502 | Bad Gateway | Erreur |

### 2.6 Gestion des domaines C2

- Stockés en SharedPreferences sous la clé `domains`
- Format : `https://domain1.com:443/;https://domain2.com:443/`
- **Rotation automatique** : en cas d'échec, le domaine est déplacé en fin de liste
- **Mise à jour dynamique** : le serveur peut envoyer de nouveaux domaines via la réponse registration/activation
- Normalisation forcée : ajout `https://` et `:443/` si absents
- Fallback : si le domaine courant échoue pendant >3h, rotation vers le suivant

### 2.7 Domaines C2 par défaut (bootstrap)

Hardcodés DES-chiffrés dans `p053c.p077c.p081d.C0624b` (classe d'initialisation `ServiceCore.INITIALIZE`), rejoués à chaque mise à jour de l'app :

| Variante | Domaines (ordre = priorité) |
|----------|------------------------------|
| **HWA** (Hoverwatch, `f6028x=false`) | `a.syncvch.com`, `i1.hoverwatch.com`, `hwa.cab` |
| **SNPA** (Snoopza, `f6028x=true`) | `snsync.com`, `api.snoopza.com`, `app.snoopza.com` |

Tous en HTTPS sur port 443 explicite (`https://<host>:443/`).

### 2.8 Sécurité SSL

**AUCUNE** vérification SSL :
- `TrustManager` custom (`C0739d` / `C0740d`) → accepte tous les certificats
- `HostnameVerifier` → `return true` systématique
- Implication : vulnérable au MITM, n'importe quel proxy peut intercepter le trafic

---

## 3. Settings / État — Classe `p094hw.utils.C0888z` (369) / `C0895z` (385)

### 3.1 Clés de configuration

| Clé SharedPreferences | Type | Usage |
|-----------------------|------|-------|
| `ActivationID` | String (chiffré) | Clé d'authentification C2 |
| `Password` | String (chiffré) | PIN de l'acheteur |
| `domains` | String (chiffré) | Liste des domaines C2 |
| `EnableMonitor` | Boolean | Activation/désactivation surveillance |
| `HideIcon` | Boolean | Masquer l'icône du launcher |
| `PinProtect` | Boolean | Protection par PIN |
| `ValidThrough` | Long | Timestamp d'expiration licence |
| `Subscription` | String (chiffré) | Type d'abonnement |
| `AppInstState` | Int (enum) | NOT_INSTALLED / INSTALLED / UNINSTALL_ASK |
| `UserType` | Int | Type de device |
| `SyncServerLastTime` | Long | Dernier sync réussi |
| `SettingsVersion` | Long | Version des settings serveur |
| `Version` | String | Version app |
| `DebugMode` | Boolean | Mode debug |
| `MemoryLimit` | Boolean | Limite mémoire atteinte |
| `UserPermState-{id}` | Int | État de chaque permission |
| `UserPermSent-{id}` | Boolean | Permission reportée au serveur |
| `SysSettings_{id}` | Int/Long/String | Paramètres système |

### 3.2 Gestion de licence

- **Validité** : `ValidThrough` + 7 jours de grâce (`604800000` ms)
- **Verrouillage** : `ValidThrough` + 42 jours (`3628800000` ms) → app verrouillée
- **Période de sync en cas d'erreur** : 5 min (normal) → 720 min (si erreur licence)
- **Kill switch** : code 410 → déclenche `C0743c.m5397a()` / `C0744c.m5393a()` (désinstallation)

---

## 4. Exfiltration par C2 HTTPS (chemin primaire)

### 4.1 Architecture

```
Collecteurs (Services/Receivers)
    ↓ écriture
Base de données locale (AbstractC0746c / AbstractC0747c)
    ↓ lecture batch
Sérialiseur protobuf-like (p082d.p083a.p084a.p085a)
    ↓ POST
C2 server (api/online/logs/)
```

### 4.2 Flux d'exfiltration (`m5329C` → `m5356u` / `m5325C` → `m5352u`)

1. Vérification : licence valide + réseau disponible + délai respecté
2. Si WiFi : acquisition d'un `WifiLock` pour maintenir la connexion
3. Ping serveur (`api/online/check/`) → vérifie que le domaine répond
4. Parse settings serveur (header `x-settings-ver`)
5. Envoi logs d'erreurs (`api/online/exceptionlog/`)
6. Envoi logs d'événements (`api/online/logs/`)
7. Envoi des données collectées par chaque collecteur (`AbstractC0746c`)
8. Mise à jour du timestamp de dernière sync

### 4.3 Format d'envoi

- Sérialisation via `C0718k` (protobuf-like builder)
- Chaque événement est un JSON wrappé dans un conteneur binaire
- Header `Content-Type` non spécifié pour les logs (raw body)
- `Content-Length` explicite

---

## 5. Exfiltration par SMTP (chemin secondaire) — `assets/providers.json`

> **Analysé sur la 7.5.385.** Présence probable sur la 7.5.369 (à re-vérifier ; la
> permission `GET_ACCOUNTS` et la string obfusquée `refog` sont présentes sur les
> deux versions, cohérent avec une réutilisation du même codepath).

### 5.1 Fichier de config `assets/providers.json`

Base JSON de **22 fournisseurs d'email** avec configs SMTP complètes (hostname, port, flags TLS/SSL/STARTTLS). Format unitaire :

```json
{
  "domain-match": ["gmail\\.com", "googlemail\\.com"],
  "smtp": [
    {"starttls": true, "port": 587, "hostname": "smtp.gmail.com"},
    {"port": 465, "hostname": "smtp.gmail.com", "ssl": true},
    {"starttls": true, "port": 25, "hostname": "smtp.gmail.com"}
  ]
}
```

Les `domain-match` sont des regex (escape de `\.`) testées contre le domaine de l'adresse email à matcher. Plusieurs candidats SMTP par provider en mode fallback (587 STARTTLS → 465 SSL → 25 STARTTLS).

### 5.2 Providers ciblés (22 entrées)

| Catégorie | Providers |
|-----------|-----------|
| Généralistes US/EU | Gmail, Outlook/Hotmail/Live (~40 TLDs), Yahoo (+ymail, rocketmail, xtra.co.nz), Yahoo Japan, AOL/AIM/Juno, Mail.com, GMX/Caramail, Zoho, FastMail (~100 alias) |
| Secure / privacy | Hushmail, OpenMailbox |
| Apple | iCloud/Me/Mac (`smtp.mail.me.com`) **+ Apple corporate** (`apple.com`, `euro.apple.com`, `asia.apple.com` → `phonehome[.asia].apple.com`) |
| Russophones / CIS | **Mail.ru** (+inbox/list/bk.ru, mail.ua), **Yandex** (6 TLDs : .ru/.ua/.kz/.by/.com/.com.tr), **Rambler** (lenta/autorambler/myrambler/ro.ru/r0.ru), **Ukr.net** |
| Chinois | **QQ/Tencent** (`smtp.exmail.qq.com`) |

### 5.3 Mécanique d'exfiltration présumée

Pipeline déductif (à valider par identification du code consommateur) :

1. Permission `GET_ACCOUNTS` (déjà requise au manifest) → `AccountManager.getAccounts()` liste les comptes configurés sur l'appareil
2. Pour chaque compte, extraction du domaine (`user@<domaine>`)
3. Match du domaine contre les regex `domain-match` de `providers.json`
4. Récupération de la config SMTP correspondante (avec fallbacks port/TLS)
5. Authentification SMTP (creds fournies par l'opérateur à la config de l'app, ou potentiellement récupérées via OAuth/AccountManager selon la version Android et les permissions accordées)
6. Envoi des logs de surveillance en tant que **mail sortant depuis le compte de la cible**

**Intérêt pour l'opérateur du stalkerware** :
- Contourne le blocage des domaines C2 (le mail sortant ressemble à du trafic utilisateur légitime)
- Contourne les outils d'analyse de trafic HTTPS d'entreprise qui whitelisteraient les domaines SMTP grand public
- En cas de compromission du C2 principal (takedown, DNS sinkhole), le canal SMTP reste opérationnel
- Le compte mail de la victime devient un proxy d'exfiltration — en cas d'investigation, la trace revient à la victime

### 5.4 Indicateur de lineage Refog

Deux indices convergents suggèrent une filiation codebase **Refog → Brainstack/Hoverwatch** :

1. String `refog` (plaintext `uHpzgHJIA7s=\n`) parmi les 20 strings DES-chiffrées du DEX (cf. `hoverwatch_20260420_strings.md`) — apparaît dans le static initializer de `C0737a` (`C0877h.m6278c("uHpzgHJIA7s=\n")`)
2. **L'exfiltration par email SMTP est la signature historique de Refog** (keylogger Windows depuis 2003), caractéristique rarissime dans les stalkerwares Android modernes qui privilégient HTTPS C2
3. La structure de `providers.json` (`domain-match` regex + array de `smtp` candidates) ressemble aux tables d'autoconfig de clients mail open source (Thunderbird ISPDB, K-9 Mail) ou à une adaptation d'une config Refog Windows historique

Lien à documenter précisément dans le SoK pour établir le **graphe de filiation de la famille Brainstack** (mSpy, Struktura, Ersten Group, Refog, Hoverwatch, Snoopza).

### 5.5 TODO d'analyse

- [ ] Localiser la classe qui parse `providers.json` (candidats : chercher dans les DEX les strings `providers.json`, `domain-match`, `starttls`, `MimeMessage`, `javax.mail` via `apk_peek find --bytes`)
- [ ] Identifier l'API SMTP utilisée (JavaMail bundled ? implémentation maison socket-level ?)
- [ ] Tracer l'origine des credentials SMTP (prompt à l'installeur, `AccountManager.getAuthToken`, config serveur ?)
- [ ] Comparer avec la version 7.5.369 : `providers.json` identique ? modifié ?
- [ ] Comparer avec la variante SNPA (Snoopza) : même fichier bundlé ?
- [ ] Identifier quelles données partent par SMTP vs HTTPS (tout ? fallback ? subset ?)
- [ ] Capturer le format du mail d'exfil (subject, body template, attachments)

---

## 6. Collecteurs identifiés

> **TODO** : analyser chaque collecteur en détail via JADX

| Classe | Données collectées |
|--------|-------------------|
| `p094hw.utils.ServiceCore` | Orchestration, GPS, état device |
| `p094hw.recorder.ServiceRecording` | Enregistrement audio/appels |
| `p094hw.utils.ServiceScr` | Captures d'écran (MediaProjection) |
| `p094hw.imreader.ReaderAccessibilityService` | Messages IM (WhatsApp, Telegram, etc.) via Accessibility |
| `p094hw.imreader.ReaderNotificationService` | Notifications |
| `com.utils.receivers.ReceiverOutgoingCall` | Appels sortants |
| _à identifier_ | SMS, contacts, calendrier, historique navigateur, photos |

---

## 7. Vulnérabilités identifiées

1. **Pas de vérification SSL** → MITM trivial
2. **SharedPreferences** avec chiffrement maison → extractible via backup ou root
3. **Tous les services/receivers exportés** (`exported="true"`) → surface d'attaque locale
4. **Kill switch distant** (code 410) → l'opérateur peut supprimer les preuves
5. **Domaines C2 en clair** dans les SharedPreferences (après déchiffrement)
6. **Pas de certificate pinning** → interception proxy sans modification de l'APK
7. **Exfiltration SMTP depuis le compte de la cible** → en cas d'investigation forensique du compte mail de la victime, la trace d'envoi remonte à la victime elle-même et non au stalkerware (cf. §5.3) ; à intégrer dans la méthodologie forensique IPV

---

## 8. TODO

- [ ] Analyser `ServiceCore` — logique d'orchestration et collecte GPS
- [ ] Analyser `ServiceRecording` — enregistrement audio/appels
- [ ] Analyser `ServiceScr` — capture d'écran
- [ ] Analyser `ReaderAccessibilityService` — interception IM
- [ ] Analyser la classe de chiffrement des SharedPreferences (`C0870h` / `C0877h`)
- [x] Extraire les domaines C2 hardcodés / par défaut (cf. §2.7)
- [ ] Analyser le format protobuf des logs exfiltrés
- [ ] Documenter le schéma de la base de données locale
- [ ] Coder un mock C2 server pour tester les signatures Suricata
- [ ] Lancer Kharon sur l'APK (check native code)
- [ ] **[§5] Identifier le parseur de `providers.json` et le sender SMTP**
- [ ] **[§5] Documenter le flow credentials → AccountManager → SMTP auth**
- [ ] **[§5] Comparer `providers.json` entre 7.5.369 et 7.5.385 (diff longitudinal)**
- [ ] **[§5] Vérifier présence du même fichier dans la variante SNPA (Snoopza)**
