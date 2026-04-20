# iKeyMonitor v17.4 — Documentation complète du protocole C2

## Vue d'ensemble

iKeyMonitor utilise une architecture C2 dual-canal :
1. **REST API** (HTTP/HTTPS) — exfiltration périodique de données + configuration
2. **WebSocket** (WSS) — commandes temps réel (caméra, screenshot, streaming, enregistrement ambiant)

Un troisième canal **RTMP** est utilisé pour le streaming vidéo en temps réel de l'écran.

Aucun certificate pinning. Cleartext autorisé. Interception MITM triviale.

---

## 1. Infrastructure réseau

### Domaines

| Domaine | Rôle | Source |
|---|---|---|
| `ikmws.awsapi.io` | C2 REST principal | `C2089e.f4848a` (configurable) |
| `ikmws-mirror.awsapi.io` | Miroir WebSocket #1 | `MyApplication.f1909r` (hardcodé) |
| `ikm-sv2.awsapi.io` | Miroir WebSocket #2 | `MyApplication.f1909r` (hardcodé) |
| `ikm-sv3.awsapi.io` | Miroir WebSocket #3 | `MyApplication.f1909r` (hardcodé) |
| `ikm-sv4.awsapi.io` | Miroir WebSocket #4 | `MyApplication.f1909r` (hardcodé) |
| `emcpanel.com` | Panel d'administration | `network_security_config.xml` |

### Résolution de l'adresse C2

L'adresse REST est stockée dans les SharedPreferences (`C2124g.m5003i0()`). Si vide, fallback sur `https://ikmws.awsapi.io`. L'adresse WebSocket est récupérée dynamiquement via l'endpoint `get_websocket_address`.

### TLS / Network Security

```xml
<!-- network_security_config.xml -->
<base-config cleartextTrafficPermitted="true">
    <trust-anchors>
        <certificates src="system"/>
        <certificates src="user"/>    <!-- PAS de pinning -->
    </trust-anchors>
</base-config>
```

L'APK implémente aussi un `X509TrustManager` custom (`C3559e.m8026c()`) qui bypasse probablement la validation.

### User-Agent WebSocket

```
User-Agent: com.ab.ikm.portal.request
```

Source : `C1803f.m3414m()` — `C3519b0.a().m7625a("User-Agent", "com.ab.ikm.portal.request")`

---

## 2. Identifiants de session

| Champ | Variable | Description |
|---|---|---|
| `Client` | `C2087c.f4746V` | Device ID (MAC address ou UUID généré) |
| `License` | `C2127j.m5084c()` | Clé de licence iKeyMonitor |
| `UnitID` | `C3560f.f7783b` | ID d'unité côté serveur (format `MSIK-ONLINE-*`) |

---

## 3. Chiffrement

### 3.1 Signature des requêtes (payload signing)

**Algorithme** : `DESede/ECB/PKCS5Padding` (Triple DES, mode ECB)

**Classe** : `p128r.C3443z.m7234b(String plaintext, String key)`

**Clé hardcodée** : `ccc707d2924768f2cc12bc8b` (24 bytes)

**Flux** :
```
plaintext (license key)
  → DESede/ECB encrypt avec clé hardcodée
  → Hex encode
  → Base64 encode
  → résultat envoyé dans les requêtes
```

**Utilisation** : signature d'authentification dans le cycle upload et l'init RTMP.

Code source :
```java
SecretKeySpec key = new SecretKeySpec(keyBytes, "DESede");
Cipher cipher = Cipher.getInstance("DESede/ECB/PKCS5Padding");
cipher.init(Cipher.ENCRYPT_MODE, key);
byte[] encrypted = cipher.doFinal(plaintext.getBytes(UTF_8));
return base64(hexEncode(encrypted));
```

### 3.2 Signature RTMP

**Secret** : `C4hgdA%Qc5UHfqEho&Ke` (champ `C2089e.f4849b`)

**Construction de l'URL RTMP** :
```
rtmp://{rtmp_server}/{device_id}?sign={sign_timestamp}-{md5_hash}
```

Où `md5_hash = MD5("/live/" + device_id + "-" + sign_timestamp + "-" + secret)`

---

## 4. Canal REST — Endpoints

### 4.1 Table des endpoints

Base URL : `{C2_SERVER}/index.php?m=api&a={action}`

Classe source : `p070j.C2089e` (compilée depuis `Constants.java`)

#### Contrôle & authentification
| Action | Variable | Méthode | Description |
|---|---|---|---|
| `register` | `f4850c` | POST | Enregistrement initial du device |
| `reset_password` | `f4851d` | POST | Reset mot de passe compte |
| `account` | `f4855h` | POST | Info compte / validation licence |
| `get_settings` | `f4856i` | POST | Récupération configuration serveur |
| `set_settings` | `f4857j` | POST | Modification configuration distante |
| `get_websocket_address` | `f4853f` | POST | Obtenir l'URL WebSocket |
| `check_update` | `f4844A` | POST | Vérification nouvelle version APK |
| `download_update` | `f4845B` | POST | Téléchargement MAJ APK |

#### Cycle de synchronisation
| Action | Variable | Méthode | Description |
|---|---|---|---|
| `cycle` | `f4852e` | POST | Heartbeat + sync bidirectionnel |

#### Exfiltration de données
| Action | Variable | Données exfiltrées |
|---|---|---|
| `uoload_keystrokes` | `f4861n` | Frappes clavier (keylogger) |
| `uoload_chat_logs` | `f4862o` | Messages de messagerie |
| `uoload_website_history` | `f4863p` | Historique de navigation |
| `uoload_call_history` | `f4864q` | Journal d'appels |
| `uoload_gps_history` | `f4865r` | Historique GPS |
| `upload_chat_img` | `f4858k` | Images de conversations |
| `upload_call_img` | `f4859l` | Images liées aux appels |
| `upload_Wifi` | `f4860m` | Informations WiFi |
| `upload_clipboard` | `f4869v` | Contenu presse-papiers |
| `upload_photo` | `f4870w` | Photos |
| `upload_video` | `f4847D` | Vidéos caméra |
| `upload_screenvideo` | `f4846C` | Vidéos d'écran |
| `contact` | `f4867t` | Contacts |
| `calendar` | `f4868u` | Événements calendrier |
| `surrounding` | `f4871x` | Enregistrements audio ambiant |
| `get_screenshot` | `f4866s` | Screenshots (upload) |
| `schedule_surround` | `f4854g` | Planification enregistrement ambiant |

#### Debug & crash
| Action | Variable | Description |
|---|---|---|
| `upload_debug_logs` | `f4872y` | Logs de debug |
| `upload_weekly_crash_logs` | `f4873z` | Crash reports ACRA (hebdo) |

**IOC réseau** : 4 endpoints contiennent la typo `uoload` au lieu de `upload`. C'est un fingerprint réseau fiable.

### 4.2 Format des requêtes REST

Les requêtes utilisent `C3560f.m8040O()` qui envoie un POST avec les données en form-data.

Champs communs dans le body :
```
UnitID={unit_id}
License={license_key}
Client={device_id}
Data={payload_xml_ou_json}
```

### 4.3 Protocole Cycle (heartbeat)

Classe : `p149u.C3565k` (compilée depuis `Sync_PortalCycle.java`)

**Requête** : POST vers `cycle` endpoint avec les données collectées depuis le dernier cycle.

**Réponse** : XML contenant les champs suivants.

#### Codes de retour `<Ret>`

| Code | Signification | Action APK |
|---|---|---|
| `500` | Succès — session active | Parse les commandes embarquées, upload des logs |
| `501` | Licence expirée | Supprime la licence locale, arrête le monitoring |
| `502` | Device dissocié | Réinitialisation complète |
| `503` | Ré-authentification requise | Re-sync du device ID |

#### Champs de la réponse cycle (quand Ret=500)

```xml
<IKMService>
  <Ret>500</Ret>
  <Client>{device_id_serveur}</Client>
  <UnitID>MSIK-ONLINE-{id}</UnitID>
  <MonitorStatus>0</MonitorStatus>
  <AlertWord>
    <Update>1</Update>
    <!-- mots-clés d'alerte à surveiller -->
  </AlertWord>
  <Surrounding>
    <Enable>1</Enable>
    <Duration>60</Duration>
  </Surrounding>
  <!-- ... commandes supplémentaires ... -->
</IKMService>
```

Le serveur peut donc **pousser des commandes via le cycle response** — pas uniquement via WebSocket.

#### MonitorStatus

| Valeur | Signification |
|---|---|
| `0` | Monitoring actif — upload autorisé |
| `1` | Monitoring désactivé — supprimer la licence |
| `2` | Monitoring désactivé — supprimer la licence |
| `3` | Monitoring en pause |
| `4` | Status spécial (flag interne) |

---

## 5. Canal WebSocket — Protocole temps réel

### 5.1 Connexion

Classe : `p027d.C1803f` (compilée depuis `WsManager.java`)

L'APK se connecte au WebSocket dont l'URL est récupérée via l'endpoint REST `get_websocket_address`. La connexion utilise OkHttp3 avec :
- Read timeout : 30s
- Write timeout : 30s  
- Connect timeout : 10s
- Reconnection automatique toutes les 20s en cas d'échec

### 5.2 Handshake — onConnect

Quand le serveur envoie un message avec `<RequestType>onConnect</RequestType>`, l'APK répond :

```xml
<IKMService>
  <License>{license_key}</License>
  <Logstype>1</Logstype>
  <Client>{device_id}</Client>
  <Body></Body>
  <Ret>1</Ret>
  <WSTimeStamp>{unix_ts_seconds}</WSTimeStamp>
</IKMService>
```

### 5.3 Keepalive

Après chaque message reçu (si pas un onConnect), l'APK renvoie un ACK identique au handshake, avec un throttle de 15 secondes minimum entre deux envois.

### 5.4 Commandes serveur → APK

Le serveur envoie des commandes XML. L'APK dispatch vers 4 handlers dans `C1800c` (`MyWebSocketOper.java`) :

#### 5.4.1 Camera — Capture photo (`m3390c`)

**Commande serveur** :
```xml
<IKMService>
  <RequestType>{type}</RequestType>
  <RequestId>{id}</RequestId>
  <Camera>
    <Enable>1</Enable>
    <Type>front</Type>   <!-- ou "back" -->
  </Camera>
</IKMService>
```

**Réponse APK** :
```xml
<IKMService>
  <RequestType>{type}</RequestType>
  <RequestId>{id}</RequestId>
  <Ret>1</Ret>
  <Logstype>5</Logstype>
  <Client>{device_id}</Client>
  <License>{license}</License>
  <WSTimeStamp>{ts}</WSTimeStamp>
</IKMService>
```

L'APK prend ensuite la photo via `Camera2Service` et l'exfiltre.

#### 5.4.2 Screenshots — Capture d'écran (`m3391d`)

**Commande serveur** :
```xml
<IKMService>
  <RequestType>{type}</RequestType>
  <RequestId>{id}</RequestId>
  <Screenshots>
    <Enable>1</Enable>
  </Screenshots>
</IKMService>
```

**Réponse APK** :
```xml
<IKMService>
  <RequestType>{type}</RequestType>
  <RequestId>{id}</RequestId>
  <Ret>1</Ret>         <!-- 1=OK, 6=écran éteint -->
  <Logstype>5</Logstype>
  <Client>{device_id}</Client>
  <License>{license}</License>
  <WSTimeStamp>{ts}</WSTimeStamp>
</IKMService>
```

Le screenshot est capturé via MediaProjection si disponible, ou AccessibilityService en fallback, puis envoyé en binaire via le WebSocket.

#### 5.4.3 ScreenshotVideo — Stream écran RTMP (`m3392e`)

**Commande serveur** :
```xml
<IKMService>
  <RequestType>{type}</RequestType>
  <RequestId>{id}</RequestId>
  <ScreenshotVideo>
    <Enable>1</Enable>    <!-- 1=start, 0=stop -->
  </ScreenshotVideo>
  <SignTimeStamp>{sign_ts}</SignTimeStamp>
</IKMService>
```

**Réponse APK** :
```xml
<IKMService>
  <RequestType>screen_video</RequestType>
  <RequestId>{id}</RequestId>
  <Ret>1</Ret>         <!-- 1=streaming, 6=écran éteint -->
  <Logstype>5</Logstype>
  <Client>{device_id}</Client>
  <License>{license}</License>
  <WSTimeStamp>{ts}</WSTimeStamp>
</IKMService>
```

L'APK construit l'URL RTMP et démarre le VirtualDisplay + MediaProjection pour streamer.

**Paramètres vidéo** (hardcodés dans `C2119b`) :
- Résolution : 720 × 1080
- FPS : 10
- Bitrate : 1024000 bps

#### 5.4.4 Surrounding — Enregistrement audio ambiant (`m3393f`)

**Commande serveur** :
```xml
<IKMService>
  <RequestType>{type}</RequestType>
  <RequestId>{id}</RequestId>
  <Surrounding>
    <Enable>1</Enable>    <!-- 1=start, 0=stop -->
  </Surrounding>
</IKMService>
```

**Réponse APK** :
```xml
<IKMService>
  <RequestType>{type}</RequestType>
  <RequestId>{id}</RequestId>
  <Ret>1</Ret>
  <Logstype>5</Logstype>
  <Client>{device_id}</Client>
  <License>{license}</License>
  <WSTimeStamp>{ts}</WSTimeStamp>
</IKMService>
```

L'enregistrement utilise un encodeur audio et stream via RTMP (`MyApplication.f1895d`).

### 5.5 Codes de retour WebSocket `<Ret>`

| Code | Signification |
|---|---|
| `1` | Commande exécutée / en cours |
| `6` | Écran éteint ou fonctionnalité indisponible |
| `7` | Erreur RTMP (write error) |
| `8` | Arrêt d'enregistrement |

### 5.6 États de connexion WebSocket

| Valeur `f3222e` | État |
|---|---|
| `-1` | Déconnecté |
| `0` | En cours de connexion |
| `1` | Connecté |
| `2` | Reconnexion en cours |

---

## 6. Health Check

L'APK envoie périodiquement un rapport d'état au C2. 

Classe : `p128r.C3443z.m7240h()`

```xml
<HealthCheck>
  <Accessibility>1</Accessibility>       <!-- 1=activé, 0=désactivé -->
  <UsageAccess>1</UsageAccess>            <!-- 1=activé -->
  <RootPermission>0</RootPermission>      <!-- 1=rooté -->
  <GooglePlayPprotect>NULL</GooglePlayPprotect>
  <BatteryOptimization>NULL</BatteryOptimization>
  <BatterySaver>NULL</BatterySaver>
  <BackgroundApp>NULL</BackgroundApp>
  <ThreerdPartySecurityapps>0</ThreerdPartySecurityapps>
</HealthCheck>
```

---

## 7. Séquence de communication type

```
[APK Boot]
  │
  ├── 1. POST /api/register          → enregistrement device
  ├── 2. POST /api/account            → validation licence
  ├── 3. POST /api/get_settings       → récupération config
  ├── 4. POST /api/get_websocket_address → obtenir URL WS
  │
  ├── 5. WSS connect                  → connexion WebSocket
  │       └── recv: <RequestType>onConnect</RequestType>
  │       └── send: ACK avec License + Client
  │
  ├── 6. Boucle cycle (toutes les ~5 min)
  │       ├── Collecte locale (SMS, contacts, GPS, keystrokes, chats, etc.)
  │       ├── POST /api/cycle         → heartbeat + sync
  │       │   └── Réponse contient MonitorStatus, AlertWord, Surrounding
  │       ├── POST /api/uoload_keystrokes
  │       ├── POST /api/uoload_chat_logs
  │       ├── POST /api/uoload_gps_history
  │       ├── POST /api/upload_photo
  │       ├── POST /api/upload_clipboard
  │       └── ... (autres endpoints d'exfiltration)
  │
  └── 7. Commandes temps réel (via WebSocket, à tout moment)
          ├── recv: Camera → capture photo → upload
          ├── recv: Screenshots → capture écran → envoi via WS
          ├── recv: ScreenshotVideo → démarrage stream RTMP
          └── recv: Surrounding → enregistrement micro → stream RTMP
```

---

## 8. Spécifications pour mock C2

### 8.1 Serveur REST (FastAPI)

Implémenter les 25 endpoints en `POST`. Le routing est `?m=api&a={action}`.

**Réponse minimale pour `cycle`** (maintenir l'APK active) :
```xml
<IKMService>
  <Ret>500</Ret>
  <Client>{device_id_reçu}</Client>
  <UnitID>MSIK-ONLINE-TEST001</UnitID>
  <MonitorStatus>0</MonitorStatus>
</IKMService>
```

**Réponse pour `get_websocket_address`** : retourner l'adresse du mock WS.

**Réponse pour `register`** et `account` : retourner un Ret=500 avec les identifiants.

Les endpoints d'upload (`uoload_*`, `upload_*`) doivent accepter les form-data/multipart et stocker les fichiers pour analyse.

### 8.2 Serveur WebSocket

1. À la connexion, envoyer :
```xml
<IKMService><RequestType>onConnect</RequestType></IKMService>
```

2. Attendre l'ACK client avec License + Client.

3. Pour trigger une commande, envoyer le XML correspondant (§5.4).

### 8.3 Serveur RTMP

nginx-rtmp ou `rtmp-server` Python. L'APK push vers :
```
rtmp://{server}/{device_id}?sign={sign_ts}-{md5}
```

Le serveur peut ignorer la vérification du sign pour le lab.

### 8.4 DNS / réseau

Rediriger `ikmws.awsapi.io` et les miroirs vers le lab :
```
# /etc/hosts sur le device de test
192.168.1.X  ikmws.awsapi.io
192.168.1.X  ikmws-mirror.awsapi.io
192.168.1.X  ikm-sv2.awsapi.io
192.168.1.X  ikm-sv3.awsapi.io
192.168.1.X  ikm-sv4.awsapi.io
```

### 8.5 Certificat TLS

Certificat auto-signé ou mitmproxy, installé comme user cert sur le device. L'APK l'accepte nativement.

### 8.6 Hooks Frida recommandés

```javascript
// Logger les payloads avant chiffrement 3DES
Java.perform(function() {
    var C3443z = Java.use("p128r.C3443z");
    C3443z.m7234b.implementation = function(plaintext, key) {
        console.log("[3DES] plaintext=" + plaintext + " key=" + key);
        return this.m7234b(plaintext, key);
    };
});

// Intercepter les messages WebSocket sortants
Java.perform(function() {
    var WsManager = Java.use("p027d.C1803f");
    WsManager.m3421q.implementation = function(msg) {
        console.log("[WS OUT] " + msg);
        return this.m3421q(msg);
    };
});

// Intercepter les messages WebSocket entrants
Java.perform(function() {
    var WsOper = Java.use("p027d.C1803f$b");
    WsOper.m3426h.implementation = function(msg) {
        console.log("[WS IN] " + msg);
        this.m3426h(msg);
    };
});
```
