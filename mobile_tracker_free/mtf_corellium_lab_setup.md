# Mobile Tracker Free — Lab Setup Corellium + Mock C2

> **Objectif** : Exécuter le stalkerware MTF dans une sandbox Corellium,
> rediriger tout le trafic vers notre mock C2 server, et capturer
> l'intégralité de l'exfiltration.

---

## 1. Prérequis

- Compte Corellium (https://corellium.com) — plan Enterprise ou Individual
- Le serveur mock C2 (`mtf_c2_server.py`) hébergé sur une machine accessible depuis le cloud Corellium
- Les APK : dropper v3.9 (`com.mtf.protect`) + payload (`phone.monitor2026`)
- Un certificat SSL auto-signé **installé dans le system trust store** (MTF utilise le vrai `X509TrustManager.checkServerTrusted()`, contrairement à Hoverwatch qui a un trust-all)

---

## 2. Architecture du lab

```
┌──────────────────────────────────────────────────────────┐
│                     CORELLIUM CLOUD                      │
│  ┌─────────────────────┐                                 │
│  │  Android VM (ARM)   │                                 │
│  │  ┌───────────────┐  │     HTTPS (UA: ILAHK...)       │
│  │  │phone.monitor  │──┼──────────────────────┐         │
│  │  │    2026       │  │                      │         │
│  │  └───────────────┘  │                      │         │
│  │  /etc/hosts modifié │                      │         │
│  │  ou proxy MITM      │                      │         │
│  └─────────────────────┘                      │         │
└───────────────────────────────────────────────┼─────────┘
                                                │
                                                ▼
                                   ┌────────────────────┐
                                   │  VPS / Machine lab  │
                                   │  mtf_c2_server.py  │
                                   │  (FastAPI :443)     │
                                   │  captures/ ← logs  │
                                   └────────────────────┘
```

---

## 3. Setup Corellium — VM Android

### 3.1 Créer la VM

- Image : **Android 13 (API 33)** ou **Android 14 (API 34)**
  - Le stalkerware cible minSDK 23, targetSDK 34
  - ⚠️ **API 35+ / Android 15+ casse le payload** (vérifié 21/04/2026 sur API 36)
  - Éviter Android 14+ pour l'instant (restrictions foreground services)
- Device profile : **Generic ARM** (Pixel 4/5 ou Samsung)
- **Rooted** : OUI (par défaut sur Corellium)
- RAM : 4 GB minimum

### 3.2 Snapshot initial

Prendre un snapshot **avant** installation du stalkerware :
```
Corellium UI → Snapshots → "clean_before_mtf"
```

### 3.3 Préparer le réseau — Méthode 1 : /etc/hosts + adb reverse

Même approche que le lab Hoverwatch. **Pas besoin d'`iptables`** : `adbd` tourne en root sur
Corellium, donc `adb reverse` peut binder le port privilégié 443 directement. Le mock reste sur 8443.

Poste lab — tunnel SSH D'ABORD, adb ENSUITE. Identique bash / PowerShell :
```bash
ssh -N -f -L 5001:<DEVICE_IP>:5001 <user>@proxy.corellium.com
adb connect localhost:5001
adb shell dumpsys connectivity | grep "Active default"   # doit ≠ none

adb reverse tcp:443  tcp:8443
adb reverse tcp:8443 tcp:8443
```

PowerShell n'a ni `-f` fiable pour détacher le ssh ni `grep` :
```powershell
Start-Process ssh -ArgumentList "-N","-L","5001:<DEVICE_IP>:5001","<user>@proxy.corellium.com" -WindowStyle Hidden
adb connect localhost:5001
adb shell dumpsys connectivity | Select-String "Active default"

adb reverse tcp:443  tcp:8443
adb reverse tcp:8443 tcp:8443
```

Shell device (root) — redirection DNS :
```bash
mount -o rw,remount /
cat >> /etc/hosts << 'EOF'
# MTF C2 Sinkhole
127.0.0.1 mobile-track-data.com
127.0.0.1 mobile-tracker-free.com
127.0.0.1 tracker-free.com
127.0.0.1 apkv2.tracker-free.com
127.0.0.1 appapk.mtf.re
# Block Firebase/FCM leak
127.0.0.1 fcm.googleapis.com
127.0.0.1 firebaseinstallations.googleapis.com
127.0.0.1 firebaselogging-pa.googleapis.com
127.0.0.1 firebase-settings.crashlytics.com
127.0.0.1 android.clients.google.com
127.0.0.1 mtalk.google.com
127.0.0.1 alt1-mtalk.google.com
127.0.0.1 alt2-mtalk.google.com
127.0.0.1 alt3-mtalk.google.com
127.0.0.1 alt4-mtalk.google.com
127.0.0.1 alt5-mtalk.google.com
127.0.0.1 alt6-mtalk.google.com
127.0.0.1 alt7-mtalk.google.com
127.0.0.1 alt8-mtalk.google.com
EOF
```

Le heredoc ci-dessus tourne **dans le shell device**, pas sur le poste lab : que tu sois sous
bash ou PowerShell, tape-le après être entré en `adb shell`. Si tu veux le faire en one-liner
depuis PowerShell, passe par un fichier :
```powershell
adb push hosts_mtf.txt /sdcard/
adb shell 'mount -o rw,remount / && cat /sdcard/hosts_mtf.txt >> /etc/hosts'
```

⚠️ `mount -o rw,remount /` est à refaire **à chaque reboot**. Et `nslookup` ne lit PAS `/etc/hosts`
(outil DNS pur) — la seule vérif honnête est `curl` depuis le device (cf. §4.2).

### 3.4 Préparer le réseau — Méthode 2 : Proxy MITM (mitmproxy)

Si tu veux aussi voir le trafic en clair dans mitmproxy :

```bash
# Sur le poste lab
mitmproxy --mode transparent --listen-port 8443 \
  --set confdir=~/.mitmproxy \
  --scripts mtf_mitm_addon.py
```

Sur la VM Corellium :
```bash
adb push ~/.mitmproxy/mitmproxy-ca-cert.cer /sdcard/
adb shell su -c "cp /sdcard/mitmproxy-ca-cert.cer /system/etc/security/cacerts/c8750f0d.0"
adb shell su -c "chmod 644 /system/etc/security/cacerts/c8750f0d.0"

adb shell settings put global http_proxy <IP_MITMPROXY>:8443
```

### 3.5 Préparer le réseau — Méthode 3 : Corellium Network Monitor

Corellium a un **network monitor intégré** (PCAP capture) :
```
VM → Network → Monitor → Start Capture
```
Ça capture tout le trafic en PCAP. Combiné avec `/etc/hosts`, tu as le meilleur des deux mondes.

---

## 4. Installation du certificat SSL (OBLIGATOIRE)

⚠️ **Contrairement à Hoverwatch** (qui a un `TrustManager` trust-all, cf. `C0740d.verify() → return true`), MTF utilise le vrai `X509TrustManagerExtensions.checkServerTrusted()` (classe `p000.C0467m4`). Le cert self-signé du mock C2 **DOIT** être installé dans le system trust store Android, sinon le TLS handshake échoue silencieusement et aucune requête n'atteint le mock.

### 4.1 Générer le certificat (automatique au premier lancement)

Le mock C2 génère `mock.crt` + `mock.key` automatiquement au premier lancement. Le SAN couvre `localhost`, `mobile-track-data.com`, `127.0.0.1`, `10.11.1.1`, `10.0.2.2`.

⚠️ Ne JAMAIS régénérer le cert une fois qu'il est posé sur le device — ça invalide la copie installée.

### 4.2 Installer dans le system trust store (root)

Le hash se calcule **sur le poste lab** (`openssl` est absent de l'image device).

```bash
HASH=$(openssl x509 -inform PEM -subject_hash_old -in mock.crt | head -1)
echo $HASH
adb push mock.crt /sdcard/mock.crt
```

```powershell
$HASH = (openssl x509 -inform PEM -subject_hash_old -in mock.crt | Select-Object -First 1)
$HASH
adb push mock.crt /sdcard/mock.crt
```

Shell device (root) :
```bash
mount -o rw,remount /
cp /sdcard/mock.crt /system/etc/security/cacerts/${HASH}.0
chmod 644 /system/etc/security/cacerts/${HASH}.0
```

Vérification — **depuis le device**, pas depuis le poste lab :
```bash
ls -la /system/etc/security/cacerts/${HASH}.0
curl -v https://mobile-track-data.com/ 2>&1 | head -20
# Doit afficher le contenu sans erreur SSL (pas besoin de -k)
```

### 4.3 Lancer le mock server

```bash
uv run python mtf_c2_server.py
```

---

## 5. Installation du stalkerware

### 5.1 Désactiver Play Protect (comme le ferait l'abuseur)

```bash
adb shell settings put global package_verifier_enable 0
adb shell settings put global verifier_verify_adb_installs 0
```

### 5.2 Installer le payload directement (sans dropper)

```bash
adb install phone.monitor2026.apk

# Ou via le dropper pour tester la chaîne complète :
adb install com.mtf.protect.apk
```

### 5.3 Accorder les permissions

```bash
PKG="phone.monitor2026"

for PERM in \
  android.permission.READ_SMS \
  android.permission.RECEIVE_SMS \
  android.permission.SEND_SMS \
  android.permission.READ_CALL_LOG \
  android.permission.READ_CONTACTS \
  android.permission.ACCESS_FINE_LOCATION \
  android.permission.ACCESS_BACKGROUND_LOCATION \
  android.permission.RECORD_AUDIO \
  android.permission.CAMERA \
  android.permission.READ_PHONE_STATE \
  android.permission.READ_CALENDAR \
  android.permission.READ_EXTERNAL_STORAGE \
  android.permission.WRITE_EXTERNAL_STORAGE \
  android.permission.POST_NOTIFICATIONS \
  android.permission.READ_MEDIA_IMAGES \
  android.permission.READ_MEDIA_VIDEO ; do
    adb shell pm grant $PKG $PERM 2>/dev/null
done

adb shell dumpsys deviceidle whitelist +$PKG
adb shell dpm set-active-admin $PKG/com.app.received.PolicyActivate\$PolicyAdmin
```

```powershell
$PKG = "phone.monitor2026"

$PERMS = @(
  "READ_SMS","RECEIVE_SMS","SEND_SMS","READ_CALL_LOG","READ_CONTACTS",
  "ACCESS_FINE_LOCATION","ACCESS_BACKGROUND_LOCATION","RECORD_AUDIO","CAMERA",
  "READ_PHONE_STATE","READ_CALENDAR","READ_EXTERNAL_STORAGE","WRITE_EXTERNAL_STORAGE",
  "POST_NOTIFICATIONS","READ_MEDIA_IMAGES","READ_MEDIA_VIDEO"
)
foreach ($P in $PERMS) { adb shell pm grant $PKG "android.permission.$P" }

adb shell dumpsys deviceidle whitelist +$PKG
adb shell 'dpm set-active-admin phone.monitor2026/com.app.received.PolicyActivate$PolicyAdmin'
```

⚠️ Le `$PolicyAdmin` doit arriver **littéral** jusqu'au device : en bash on échappe (`\$`),
en PowerShell on met la commande entière en quotes simples.

### 5.4 Activer l'AccessibilityService

```bash
adb shell settings put secure enabled_accessibility_services \
  $PKG/com.app.service.AccessService
adb shell settings put secure accessibility_enabled 1
```

### 5.5 Activer le NotificationListener

```bash
adb shell cmd notification allow_listener \
  $PKG/com.app.service.NotificationListener
```

---

## 6. Opérer le lab

### 6.1 Lancer l'app et s'enregistrer

```bash
adb shell am start -n $PKG/com.app.activity.FirstActivity
```

Suivre le flow d'enregistrement :
1. TermsActivity → accepter
2. UseSafeWarningActivity → sélectionner "My own device"
3. LoginActivity → email/password (sera capturé par le mock server)
4. ConfigPhoneActivity → nom du téléphone

Le mock server répond `{status: "ok", idPhone: 99999}` → le stalkerware démarre.

⚠️ Les clics dans la GUI Corellium sont souvent inopérants — piloter via
`adb shell input tap <x> <y>` / `input keyevent` / `input text`.

### 6.2 Générer de l'activité sur la VM

```bash
adb emu sms send 0612345678 "Test SMS for MTF capture"
adb emu gsm call 0612345678
adb emu geo fix 2.3522 48.8566          # Paris
adb push test_photo.jpg /sdcard/DCIM/Camera/
```

### 6.3 Monitorer les captures

```bash
curl http://localhost:8080/_stats | python -m json.tool
tail -f captures/c2_server.log
find captures/ -name "*.json" | wc -l
```

```powershell
curl http://localhost:8080/_stats | python -m json.tool
Get-Content captures\c2_server.log -Wait
(Get-ChildItem captures -Recurse -Filter *.json).Count
```

### 6.4 Tester les commandes FCM

Le stalkerware écoute Firebase pour les commandes. FCM étant sinkholé (§3.3), on injecte
la même structure de commande localement via Frida :

```javascript
// frida -U -n phone.monitor2026 -l send_fcm.js
Java.perform(function() {
    var service = Java.use("com.app.service.MyFirebaseMTFMessagingService");
    var Bundle = Java.use("android.os.Bundle");

    var bundle = Bundle.$new();
    bundle.putString("action", "GetLocation----42");
    console.log("[*] Sending fake FCM command: GetLocation");
});
```

---

## 7. Scénarios de test

### 7.1 Exfiltration passive (sans intervention)

Laisser tourner 24h et observer :
- [ ] SMS/MMS capturés automatiquement via ContentObserver
- [ ] Localisation envoyée à intervalle régulier
- [ ] Screenshots automatiques (défaut : toutes les 2h)
- [ ] Apps installées listées
- [ ] Contacts extraits
- [ ] Calendrier extrait

### 7.2 Commandes actives (via Frida)

- [ ] `TakePictureFront` → capture caméra
- [ ] `RecordAudio` → enregistrement micro
- [ ] `screenShot` → screenshot root
- [ ] `hideIcon` / `showIcon` → toggle icône
- [ ] `LockPhone` → verrouillage device
- [ ] `startLive` → tentative de live streaming (Socket.IO)
- [ ] `startFileExplorer` → explorateur de fichiers distant

### 7.3 Résilience

- [ ] Redémarrer la VM → vérifier que le stalkerware redémarre (BOOT_COMPLETED priority 999)
- [ ] Tuer le process → vérifier la relance automatique
- [ ] Couper le réseau puis restaurer → vérifier la file d'attente SQLite
- [ ] Basculement URL → simuler DNS failure de `mobile-track-data.com`

---

## 8. Extraction des données pour analyse

### 8.1 Depuis le serveur mock

```bash
tar czf mtf_captures_$(date +%Y%m%d).tar.gz captures/

for dir in captures/*/; do
    echo "$(find $dir -name '*.json' | wc -l) $(basename $dir)"
done | sort -rn
```

```powershell
$stamp = Get-Date -Format "yyyyMMdd"
tar czf "mtf_captures_$stamp.tar.gz" captures/

Get-ChildItem captures -Directory | ForEach-Object {
    [pscustomobject]@{
        Dir   = $_.Name
        Count = (Get-ChildItem $_.FullName -Recurse -Filter *.json).Count
    }
} | Sort-Object Count -Descending
```

### 8.2 Depuis la VM Corellium

```bash
adb shell su -c "cp /data/data/phone.monitor2026/shared_prefs/user.xml /sdcard/"
adb pull /sdcard/user.xml

adb shell su -c "ls /data/data/phone.monitor2026/databases/"
adb shell su -c "cp /data/data/phone.monitor2026/databases/*.db /sdcard/"
adb pull /sdcard/*.db
```

Le dernier `adb pull` compte sur le glob du shell local. PowerShell ne l'expand pas —
lister puis tirer un par un :
```powershell
adb shell su -c "cp /data/data/phone.monitor2026/databases/*.db /sdcard/"
adb shell ls /sdcard/*.db | ForEach-Object { adb pull $_.Trim() }
```

PCAP depuis Corellium Network Monitor → Download via l'UI.

### 8.3 Depuis Frida (runtime analysis)

```bash
frida -U -n phone.monitor2026 -l hook_retrofit.js   # tous les POST en temps réel
frida -U -n phone.monitor2026 -l hook_prefs.js      # les configs

frida -U -n phone.monitor2026 -e '
Java.perform(function() {
    var ctx = Java.use("com.app.activity.MyApp").f1307l.value;
    var prefs = ctx.getSharedPreferences("user", 0);
    console.log("idPhone: " + prefs.getInt("idPhone", -1));
    console.log("tokenSecurity: " + prefs.getString("tokenSecurity", ""));
    console.log("codeSecret: " + prefs.getString("codeSecret", "*1234*"));
    console.log("namePhone: " + prefs.getString("namePhone", ""));
    console.log("urlOther: " + prefs.getBoolean("urlOther", false));
});
'
```

Le `-e` avec un script multi-ligne en quotes simples ne passe pas en PowerShell — mettre
le script dans un `.js` et utiliser `-l` :
```powershell
frida -U -n phone.monitor2026 -l dump_prefs.js
```

---

## 9. Tips Corellium spécifiques

- **Ordre impératif** : tunnel SSH → `adb connect`. Sinon rien ne répond.
- **Port ADB exposé = 5001** (pas 5555)
- **Reset entre VM** : `adb kill-server` + `pkill -f proxy.corellium.com` (PowerShell :
  `Get-Process ssh | Stop-Process`) ; `offline` dans `adb devices` = ancienne VM morte
- **Snapshots** : en prendre un après chaque étape majeure
- **Console** : la console série sert au debug kernel si le stalkerware fait du `su`
- **Frida** : le Frida natif de la plateforme peut ne pas exposer le process — pousser un vrai
  `frida-server` sur un port dédié (`-l 0.0.0.0:27043`) + `adb forward tcp:27043 tcp:27043`
- **Network** : le network monitor capture le trafic **avant** le chiffrement TLS avec le kernel module Corellium
- **API** : Corellium a une API REST pour automatiser (création VM, install APK, commandes adb)

---

## 10. Automatisation via Corellium API (optionnel)

```python
import corelliumclient

client = corelliumclient.CorelliumClient(api_token="...")
project = client.projects()[0]

device = project.create_device(
    name="MTF-Lab",
    os="android",
    flavor="ranchu",
    os_version="13.0.0",
)
device.wait_for_ready()

device.adb("install /path/to/phone.monitor2026.apk")
device.adb('shell su -c "echo \'127.0.0.1 mobile-track-data.com\' >> /etc/hosts"')
device.snapshot("mtf_installed")
```
