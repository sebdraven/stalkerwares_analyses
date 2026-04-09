# Hoverwatch — Reverse Engineering du protocole C2

> **Package** : `com.android.core.mntan`
> **Version** : 7.5.369 (versionCode 369)
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

## 2. Protocole C2 — Classe `p092e.p093a.C0736a`

### 2.1 Identification client

| Champ | Valeur |
|-------|--------|
| User-Agent | `Android Monitor 7.5.369` |
| Client ID | `HWA` (prod), `HWA_TST` (test), `SNPA` (variante) |
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

### 2.7 Sécurité SSL

**AUCUNE** vérification SSL :
- `TrustManager` custom (`C0739d`) → accepte tous les certificats
- `HostnameVerifier` → `return true` systématique
- Implication : vulnérable au MITM, n'importe quel proxy peut intercepter le trafic

---

## 3. Settings / État — Classe `p094hw.utils.C0888z`

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
- **Kill switch** : code 410 → déclenche `C0743c.m5397a()` (désinstallation)

---

## 4. Exfiltration des données

### 4.1 Architecture

```
Collecteurs (Services/Receivers)
    ↓ écriture
Base de données locale (AbstractC0746c)
    ↓ lecture batch
Sérialiseur protobuf-like (p082d.p083a.p084a.p085a)
    ↓ POST
C2 server (api/online/logs/)
```

### 4.2 Flux d'exfiltration (`m5329C` → `m5356u`)

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

## 5. Collecteurs identifiés

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

## 6. Vulnérabilités identifiées

1. **Pas de vérification SSL** → MITM trivial
2. **SharedPreferences** avec chiffrement maison → extractible via backup ou root
3. **Tous les services/receivers exportés** (`exported="true"`) → surface d'attaque locale
4. **Kill switch distant** (code 410) → l'opérateur peut supprimer les preuves
5. **Domaines C2 en clair** dans les SharedPreferences (après déchiffrement)
6. **Pas de certificate pinning** → interception proxy sans modification de l'APK

---

## 7. TODO

- [ ] Analyser `ServiceCore` — logique d'orchestration et collecte GPS
- [ ] Analyser `ServiceRecording` — enregistrement audio/appels
- [ ] Analyser `ServiceScr` — capture d'écran
- [ ] Analyser `ReaderAccessibilityService` — interception IM
- [ ] Analyser la classe de chiffrement des SharedPreferences (`C0870h`)
- [ ] Extraire les domaines C2 hardcodés / par défaut
- [ ] Analyser le format protobuf des logs exfiltrés
- [ ] Documenter le schéma de la base de données locale
- [ ] Coder un mock C2 server pour tester les signatures Suricata
- [ ] Lancer Kharon sur l'APK (check native code)
