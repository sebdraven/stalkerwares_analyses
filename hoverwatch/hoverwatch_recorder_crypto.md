## 6. Enregistrement audio — Classe `p094hw.recorder.ServiceRecording`

### 6.1 Architecture

- Tourne dans un **process séparé** (`:r`) pour survivre à l'arrêt du service principal
- Deux slots d'enregistrement simultanés : `C0846c(10)` (10 min max) et `C0846c(300)` (5h max)
- Trois modes via l'enum `EnumC0845b` :
  - `OFFHOOK` — détection d'appel en cours
  - `RECORD` — enregistrement actif
  - `STOP` — arrêt
- Démarre en `foregroundService` (Android 8+) avec une notification vide/invisible

### 6.2 Technique de capture invisible

Le service crée des **views invisibles** (`LinearLayout`) ajoutées au `WindowManager` pour maintenir le service actif en arrière-plan :
```
f5810g[i].f5821c[i2] = new LinearLayout(this);
windowManager.addView(view, C0877o.m6325b0(i2));
```
C'est une astuce classique pour contourner les restrictions Android sur les services en arrière-plan : une view attachée au WindowManager empêche le système de tuer le service.

### 6.3 Enregistrement des appels

- Détection d'appel via `OFFHOOK` → bascule automatiquement en `RECORD`
- Vérifie si le micro est déjà occupé (`C0877o.m6289J0()`) pour éviter les conflits
- Support appels VoIP (détecté via l'AccessibilityService sur WhatsApp/Telegram)
- L'enregistrement est géré par `C0856j` (classe d'enregistrement audio réel)
- Fichier temporaire stocké dans le Bundle (`"tmpfile"`)

### 6.4 Mécanisme de persistance

- `onTaskRemoved()` → se relance automatiquement
- `onDestroy()` → nettoie les receivers mais survit au restart
- Notification foreground avec ID `110111` → notification invisible
- `START_STICKY` implicite (return 2 = `START_NOT_STICKY` ← erreur ? devrait être `START_STICKY = 1`)

---

## 7. Chiffrement — Classe `p094hw.utils.C0870h`

### 7.1 Algorithme

**DES en mode ECB** — Single DES, pas de IV, pas de padding spécifié.

```java
SecretKey key = SecretKeyFactory.getInstance("DES")
    .generateSecret(new DESKeySpec(keyStr.getBytes(UTF_8)));
Cipher cipher = Cipher.getInstance("DES");  // = DES/ECB/PKCS5Padding
cipher.init(DECRYPT_MODE, key);
return new String(cipher.doFinal(Base64.decode(input)));
```

### 7.2 Clés identifiées

| Méthode | Clé | Usage |
|---------|-----|-------|
| `m6219c(str)` → `m6217a(str, false)` | `"val"` | Déchiffrement des SharedPreferences (ActivationID, Password, domains, Subscription) |
| `m6218b(str, key, z)` | Variable | Chiffrement/déchiffrement avec clé custom |
| Padding si clé < 8 chars | `clé + "length 8"` | Ex: `"val"` → `"vallength 8"` (8+ chars) → DESKeySpec prend les 8 premiers octets = `"vallength"` |

### 7.3 Vulnérabilités cryptographiques

1. **DES** — cassé depuis 1998 (56 bits, brute-force trivial)
2. **ECB** — pas de chaînage, patterns visibles dans le chiffré
3. **Clé `"val"` hardcodée** — n'importe qui peut déchiffrer toutes les prefs
4. **Pas de IV** — même plaintext = même ciphertext à chaque fois
5. **Pas de MAC/HMAC** — aucune intégrité, modification silencieuse possible
6. **Base64** — encoding, pas chiffrement additionnel

### 7.4 Déchiffrement des strings obfusquées

Les noms de packages dans `C0626d` (liste des apps ciblées) sont parfois chiffrés :
```java
C0870h.m6219c("lrH2Zm0JF+MdZcKkUKBf1FtNxAV67vik/HT3Km2t/Qo=\n")
```
→ Déchiffrable avec DES/ECB, clé = `"vallength"` (8 premiers octets de `"val" + "length 8"`)

### 7.5 Impact forensique

Les SharedPreferences de la victime contiennent les données chiffrées avec cette clé triviale :
- `ActivationID` → identifiant de l'acheteur sur le C2
- `Password` → PIN de l'acheteur (preuve directe)
- `domains` → infrastructure C2 (IOCs)

**Un expert forensique peut tout déchiffrer avec 3 lignes de Python** :
```python
from Crypto.Cipher import DES
import base64
key = b"vallength"[:8]  # = b"vallenge" (8 bytes pour DES)
cipher = DES.new(key, DES.MODE_ECB)
plaintext = cipher.decrypt(base64.b64decode(ciphertext))
```

---

## 8. Résumé des vulnérabilités

| # | Vulnérabilité | Sévérité | Impact |
|---|---------------|----------|--------|
| 1 | Pas de vérification SSL (TrustAll + HostnameVerifier=true) | **CRITIQUE** | MITM trivial sur le trafic C2 |
| 2 | DES/ECB avec clé hardcodée `"val"` | **CRITIQUE** | Déchiffrement de toutes les données locales |
| 3 | Services/Receivers exportés (`exported="true"`) | **HAUTE** | Contrôle local par une app tierce |
| 4 | Kill switch distant (HTTP 410) | **HAUTE** | Suppression de preuves à distance |
| 5 | Pas de certificate pinning | **HAUTE** | Proxy interception sans modification APK |
| 6 | Credentials acheteur récupérables | **HAUTE** | Identification de l'abuseur via forensics |
| 7 | Domaines C2 en clair après déchiffrement | MOYENNE | IOC extraction facilitée |
| 8 | Notifications foreground vides | FAIBLE | Détectable par utilisateur averti (Android 13+) |
