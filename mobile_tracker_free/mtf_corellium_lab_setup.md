# Mobile Tracker Free — Lab Setup Corellium + Mock C2

> **Objectif** : Exécuter le stalkerware MTF dans une sandbox Corellium,
> rediriger tout le trafic vers notre mock C2 server, et capturer
> l'intégralité de l'exfiltration.

---

## 1. Prérequis

- Compte Corellium (https://corellium.com) — plan Enterprise ou Individual
- Le serveur mock C2 (`mtf_c2_server.py`) hébergé sur une machine accessible depuis le cloud Corellium
- Les APK : dropper v3.9 (`com.mtf.protect`) + payload (`phone.monitor2026`)
- Un certificat SSL auto-signé (le stalkerware utilise HTTPS mais pas de cert pinning)

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

- Image : **Android 12 (API 31)** ou **Android 13 (API 33)**
  - Le stalkerware cible minSDK 23, targetSDK 34
  - Éviter Android 14+ pour l'instant (restrictions foreground services)
- Device profile : **Generic ARM** (Pixel 4/5 ou Samsung)
- **Rooted** : OUI (par défaut sur Corellium)
- RAM : 4 GB minimum

### 3.2 Snapshot initial

Prendre un snapshot **avant** installation du stalkerware :
```
Corellium UI → Snapshots → "clean_before_mtf"
```

### 3.3 Préparer le réseau — Méthode 1 : /etc/hosts

C'est la méthode la plus simple. Via le shell ADB intégré de Corellium :

```bash
# Monter /system en écriture
adb shell su -c "mount -o rw,remount /system"

# Ajouter les redirections DNS
adb shell su -c "cat >> /etc/hosts << 'EOF'
# MTF C2 Sinkhole
<IP_DU_SERVEUR_MOCK>  mobile-track-data.com
<IP_DU_SERVEUR_MOCK>  mobile-tracker-free.com
<IP_DU_SERVEUR_MOCK>  tracker-free.com
<IP_DU_SERVEUR_MOCK>  apkv2.tracker-free.com
<IP_DU_SERVEUR_MOCK>  appapk.mtf.re
EOF"

# Vérifier
adb shell cat /etc/hosts

# Remonter en lecture seule
adb shell su -c "mount -o ro,remount /system"
```

### 3.4 Préparer le réseau — Méthode 2 : Proxy MITM (mitmproxy)

Si tu veux aussi voir le trafic en clair dans mitmproxy :

```bash
# Sur le serveur lab
pip install mitmproxy
mitmproxy --mode transparent --listen-port 8443 \
  --set confdir=~/.mitmproxy \
  --scripts mtf_mitm_addon.py
```

Sur la VM Corellium :
```bash
# Installer le certificat mitmproxy
adb push ~/.mitmproxy/mitmproxy-ca-cert.cer /sdcard/
adb shell su -c "cp /sdcard/mitmproxy-ca-cert.cer /system/etc/security/cacerts/c8750f0d.0"
adb shell su -c "chmod 644 /system/etc/security/cacerts/c8750f0d.0"

# Configurer le proxy WiFi via settings
adb shell settings put global http_proxy <IP_MITMPROXY>:8443
```

### 3.5 Préparer le réseau — Méthode 3 : Corellium Network Monitor

Corellium a un **network monitor intégré** (PCAP capture) :
```
VM → Network → Monitor → Start Capture
```
Ça capture tout le trafic en PCAP. Combiné avec `/etc/hosts`, tu as le meilleur des deux mondes.

---

## 4. Installation du certificat SSL

Le stalkerware attend du HTTPS. Notre mock server doit servir en HTTPS avec un cert que la VM accepte.

### 4.1 Générer un certificat auto-signé

```bash
# Sur le serveur mock
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem \
  -sha256 -days 365 -nodes \
  -subj "/CN=mobile-track-data.com" \
  -addext "subjectAltName=DNS:mobile-track-data.com,DNS:mobile-tracker-free.com,DNS:tracker-free.com,DNS:apkv2.tracker-free.com,DNS:appapk.mtf.re"
```

### 4.2 Installer le CA dans la VM (system-level, root)

```bash
# Convertir au format Android
openssl x509 -inform PEM -in cert.pem -outform DER -out cert.der
HASH=$(openssl x509 -inform PEM -subject_hash_old -in cert.pem | head -1)

# Pousser dans le system trust store
adb push cert.pem /sdcard/${HASH}.0
adb shell su -c "mount -o rw,remount /system"
adb shell su -c "cp /sdcard/${HASH}.0 /system/etc/security/cacerts/"
adb shell su -c "chmod 644 /system/etc/security/cacerts/${HASH}.0"
adb shell su -c "mount -o ro,remount /system"

# Reboot pour prise en compte
adb reboot
```

### 4.3 Lancer le mock server en HTTPS

```bash
python mtf_c2_server.py --port 443 --ssl --cert cert.pem --key key.pem
```

---

## 5. Installation du stalkerware

### 5.1 Désactiver Play Protect (comme le ferait l'abuseur)

```bash
# Via ADB (Corellium est déjà rooté)
adb shell settings put global package_verifier_enable 0
adb shell settings put global verifier_verify_adb_installs 0
```

### 5.2 Installer le payload directement (sans dropper)

```bash
# Push l'APK
adb install phone.monitor2026.apk

# Ou via le dropper pour tester la chaîne complète :
adb install com.mtf.protect.apk
# → Suivre le flow du dropper sur la VM
```

### 5.3 Accorder les permissions

```bash
PKG="phone.monitor2026"

# Permissions runtime critiques
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
  android.permission.POST_NOTIFICATIONS \
  android.permission.READ_MEDIA_IMAGES \
  android.permission.READ_MEDIA_VIDEO ; do
    adb shell pm grant $PKG $PERM 2>/dev/null
done

# Battery optimization whitelist
adb shell dumpsys deviceidle whitelist +$PKG

# Device Admin (le stalkerware le fait via UI, mais en root on peut forcer)
adb shell dpm set-active-admin $PKG/com.app.received.PolicyActivate\$PolicyAdmin
```

### 5.4 Activer l'AccessibilityService

```bash
# Activer l'AccessibilityService (nécessaire pour l'interception IM no-root)
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
# Ouvrir l'app via le secret dialer code
adb shell am start -n $PKG/com.app.activity.FirstActivity

# Ou via l'alias si l'icône est visible
adb shell am start -n $PKG/com.app.activity.FirstActivityAlias
```

Suivre le flow d'enregistrement :
1. TermsActivity → accepter
2. UseSafeWarningActivity → sélectionner "My own device"
3. LoginActivity → email/password (sera capturé par le mock server)
4. ConfigPhoneActivity → nom du téléphone

Le mock server répond `{status: "ok", idPhone: 99999}` → le stalkerware démarre.

### 6.2 Générer de l'activité sur la VM

Pour que le stalkerware ait des données à exfiltrer :

```bash
# Simuler un SMS entrant
adb emu sms send 0612345678 "Test SMS for MTF capture"

# Simuler un appel entrant
adb emu gsm call 0612345678

# Simuler un changement de position GPS
adb emu geo fix 2.3522 48.8566  # Paris

# Installer des apps IM (pour tester l'interception)
# → Installer WhatsApp/Telegram/Signal depuis l'APKMirror

# Copier des photos pour tester l'exfiltration media
adb push test_photo.jpg /sdcard/DCIM/Camera/
```

### 6.3 Monitorer les captures

Sur le serveur mock :
```bash
# Dashboard rapide
curl http://localhost:8080/_stats | python -m json.tool

# Suivre les logs en temps réel
tail -f captures/c2_server.log

# Lister les fichiers capturés (audio, photos, screenshots)
find captures/ -name "*.json" | wc -l
find captures/ -path "*/files/*" -type f | wc -l
```

### 6.4 Tester les commandes FCM

Le stalkerware écoute Firebase pour les commandes. Pour simuler des commandes sans passer par Firebase, on peut utiliser Frida sur la VM Corellium :

```javascript
// frida -U -n phone.monitor2026 -l send_fcm.js
Java.perform(function() {
    var service = Java.use("com.app.service.MyFirebaseMTFMessagingService");
    var Intent = Java.use("android.content.Intent");
    var Bundle = Java.use("android.os.Bundle");

    // Simuler une commande "GetLocation"
    var bundle = Bundle.$new();
    bundle.putString("action", "GetLocation----42");

    // Trigger via broadcast (alternative au FCM)
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

### 7.2 Commandes actives (via Frida ou manipulation Firebase)

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
# Exporter toutes les captures
tar czf mtf_captures_$(date +%Y%m%d).tar.gz captures/

# Compter par catégorie
for dir in captures/*/; do
    echo "$(find $dir -name '*.json' | wc -l) $(basename $dir)"
done | sort -rn
```

### 8.2 Depuis la VM Corellium

```bash
# Extraire la base SQLite locale du stalkerware
adb shell su -c "cp /data/data/phone.monitor2026/shared_prefs/user.xml /sdcard/"
adb pull /sdcard/user.xml

# Extraire les bases de données
adb shell su -c "ls /data/data/phone.monitor2026/databases/"
adb shell su -c "cp /data/data/phone.monitor2026/databases/*.db /sdcard/"
adb pull /sdcard/*.db

# PCAP depuis Corellium Network Monitor
# → Download via l'UI Corellium
```

### 8.3 Depuis Frida (runtime analysis)

```bash
# Hooker les appels Retrofit pour voir tous les POST en temps réel
frida -U -n phone.monitor2026 -l hook_retrofit.js

# Hooker le SharedPreferences pour voir les configs
frida -U -n phone.monitor2026 -l hook_prefs.js

# Dumper le tokenSecurity
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

---

## 9. Tips Corellium spécifiques

- **Snapshots** : prendre un snapshot après chaque étape majeure pour pouvoir revenir en arrière
- **Console** : utiliser la console série Corellium pour le debug kernel si le stalkerware fait du `su`
- **Apps** : Corellium a le Play Store sur certaines images — utile pour installer les IM cibles (WhatsApp, Telegram, etc.)
- **Frida** : pré-installé sur les images rootées Corellium
- **Network** : le network monitor capture le trafic **avant** le chiffrement TLS si tu utilises le kernel module Corellium
- **API** : Corellium a une API REST pour automatiser tout ça (création VM, install APK, adb commands)

---

## 10. Automatisation via Corellium API (optionnel)

```python
import corelliumclient

# Setup
client = corelliumclient.CorelliumClient(api_token="...")
project = client.projects()[0]

# Créer la VM
device = project.create_device(
    name="MTF-Lab",
    os="android",
    flavor="ranchu",  # Generic ARM
    os_version="13.0.0",
)
device.wait_for_ready()

# Installer le stalkerware
device.adb("install /path/to/phone.monitor2026.apk")

# Modifier /etc/hosts
device.adb('shell su -c "echo \'<IP> mobile-track-data.com\' >> /etc/hosts"')

# Prendre un snapshot
device.snapshot("mtf_installed")
```
