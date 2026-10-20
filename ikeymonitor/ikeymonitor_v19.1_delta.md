# iKeyMonitor v17.4 → v19.1 — Rapport d'analyse delta

**Analyste :** Sébastien Larinier  
**Date :** 2026-04-20  
**Sample v19.1 :** `com.android.internet.a20251031` (versionCode 322, versionName 19.1-a20251031)  
**Sample v17.4 (ref) :** `com.sec.android.internet.im.service.im20210815` (versionCode 322, versionName 17.4)  
**Outil :** JADX-GUI + JADX MCP Server  

---

## 1. Résumé des changements

| Aspect | v17.4 | v19.1 | Impact |
|---|---|---|---|
| **Package name** | `com.sec.android.internet.im.service.im20210815` | `com.android.internet.a20251031` | Stratégie de camouflage modifiée |
| **Code package** | `com.p025as.monitoringapp` | `com.p029as.mainapp` | Namespace interne réorganisé |
| **Obfuscation** | Noms partiellement lisibles | Hash MD5 (`com.a_Xf1Mc3Fh6Tb0Bv1Od8Jv.A_*`) | RE + complexe |
| **Endpoints REST** | 25 (5 avec typo `uoload`) | 28 (typos corrigées, endpoints renommés) | **⚠️ Casse les IOCs réseau** |
| **Apps ciblées (chat)** | 9 | 15 (+6 nouvelles) | Surface de surveillance étendue |
| **GPP bypass** | Présent | Étendu à 15 langues | Anti-détection renforcée |
| **Crypto** | 3DES/ECB, clé identique | Identique | Pas de changement |
| **C2 infra** | `ikmws.awsapi.io` + 4 mirrors | Identique | Pas de changement |
| **RTMP** | Secret identique | Identique | Pas de changement |

---

## 2. Changement de camouflage (package name)

### v17.4 — Imitation Samsung
```
com.sec.android.internet.im.service.im20210815
```
Imitait la nomenclature Samsung (`com.sec.android.*`), avec un suffixe date `im20210815`.

### v19.1 — Imitation Android stock
```
com.android.internet.a20251031
```
Imite une app Android système générique. Le suffixe `a20251031` est un tag de build date (31 octobre 2025).

### Code package interne
- v17.4 : `com.p025as.monitoringapp` (JADX renomme `com.as.monitoringapp`)
- v19.1 : `com.p029as.mainapp` (JADX renomme `com.as.mainapp`)

Le namespace d'origine est `com.as.*` dans les deux cas. La constante de namespace `as` confirme l'identité commune.

### Application class
- v17.4 : `com.p025as.monitoringapp.logging.MyApplication`
- v19.1 : `com.a_Xf1Mc3Fh6Tb0Bv1Od8Jv.A_4d2056b271679e1c108f720cdec6fd4c`

---

## 3. Obfuscation renforcée

### v17.4
Classes métier partiellement lisibles :
- `Stenographer_Service` → AccessibilityService / keylogger
- `MyWebSocketOper` → `p027d.C1800c`
- `Constants` → `p070j.C2089e`
- `Sync_PortalCycle` → `p149u.C3565k`
- `Utility_ContentInfo` → `p128r.C3443z`
- `WsManager` → `p027d.C1803f`

### v19.1
Package obfusqué `com.a_Xf1Mc3Fh6Tb0Bv1Od8Jv` avec des noms de classes en hash MD5 :
- `A_0b5bb70f0f56008c14513534c171bea3` → AccessibilityService
- `A_4d2056b271679e1c108f720cdec6fd4c` → Application class
- `A_5a0b892c5e516098513557d18725710b` → BackService
- `A_ca106b9f435d43c4dddd0c39ead0937e` → MediaProjection service
- `A_ec724c8198bec96b81ff3cc31650beb9` → NotificationListener
- `A_73c76da18d1254f3807b651e08a38117` → Screen recording service

Les classes non-obfusquées restent dans :
- `com.android.internet.*` (web, chats, guard)
- `com.p029as.mainapp.*` (activities, UI)

Constants class déplacée : `p070j.C2089e` → `p111m.AbstractC3202e`

Crypto class déplacée : `p128r.C3443z` → `p185u.AbstractC4687z`

---

## 4. Endpoints REST — Corrections et renommages

### 4.1 Typos `uoload` corrigées (⚠️ BREAKING IOC)

| v17.4 (avec typo) | v19.1 (corrigé) |
|---|---|
| `uoload_keystrokes` | `upload_keystrokes` |
| `uoload_chat_logs` | `upload_chat_logs` |
| `uoload_website_history` | `upload_website_history` |
| `uoload_call_history` | `upload_call_history` |
| `uoload_gps_history` | `upload_gps_history` |

**Impact** : toute règle de détection réseau basée sur le pattern `uoload` ne matchera **plus** la v19.1.

### 4.2 Endpoints renommés

| v17.4 | v19.1 |
|---|---|
| `surrounding` | `upload_surrounding` |
| `contact` | `upload_contact` |
| `calendar` | `upload_calendar` |
| `get_screenshot` | `upload_screenshot` |
| `upload_Wifi` | `upload_wifi` |

### 4.3 Liste complète v19.1 (28 endpoints)

```
# Contrôle & auth
register
reset_password
account
cycle
get_settings
set_settings
get_websocket_address
check_update
download_update
schedule_surround

# Exfiltration données
upload_keystrokes
upload_chat_logs
upload_website_history
upload_call_history
upload_gps_history
upload_chat_img
upload_call_img
upload_wifi
upload_clipboard
upload_photo
upload_video
upload_screenvideo
upload_surrounding
upload_contact
upload_calendar
upload_screenshot
upload_debug_logs
upload_weekly_crash_logs
```

---

## 5. Cibles de chat interception : 9 → 15 apps

### Apps maintenues (9, depuis v17.4)
1. WhatsApp (`com.whatsapp`) — `GetChatInfo_WhatsApp`
2. Telegram — `GetChatInfo_Telegram`
3. Facebook Messenger — `GetChatInfo_FB_Messenger`
4. WeChat (`com.tencent.mm`) — `GetChatInfo_WeChat`
5. Line — `GetChatInfo_Line`
6. Viber — `GetChatInfo_Viber`
7. Signal — `GetChatInfo_Signal`
8. Snapchat — `GetChatInfo_Snapchat`
9. Zalo — `GetChatInfo_Zalo`

### Nouvelles cibles v19.1 (+6)
10. **WhatsApp Business** (`com.whatsapp.w4b`) — `GetChatInfo_WhatsApp_4B`
11. **Gmail** — `GetChatInfo_Gmail`
12. **Instagram** — `GetChatInfo_Instagram`
13. **Skype** — `GetChatInfo_Skype`
14. **TikTok** — `GetChatInfo_TikTok`
15. **Twitter/X** — `GetChatInfo_Twitter`

L'ajout de Gmail est notable : iKeyMonitor intercepte désormais les **emails** en plus des messageries instantanées.

L'ajout de WhatsApp Business cible spécifiquement les **profils professionnels**, ce qui étend la surface de surveillance aux communications d'entreprise.

---

## 6. Anti-détection — Bypass Google Play Protect

### Mécanisme
Le stalkerware détecte le dialog Google Play Protect via l'AccessibilityService en comparant le texte affiché à l'écran avec des chaînes hardcodées dans `AbstractC3165b`. Si match :
1. `performGlobalAction(GLOBAL_ACTION_BACK)` — ferme la page
2. `performGlobalAction(GLOBAL_ACTION_HOME)` — retour au home
3. Redirection vers `support.google.com/googleplay/answer/2812853` — distraction

### Langues supportées (15)
Anglais, chinois simplifié, chinois traditionnel, russe, italien, français, espagnol, hindi, coréen, japonais, allemand, arabe + variantes régionales.

Les strings couvrent 3 surfaces d'attaque :
- **Dialog de scan GPP** (`f7075g` — 15 variantes "Turn on Play Protect scanning")
- **Page complète GPP** (`f7076h` — texte intégral du dialog dans chaque langue)
- **Popup "Turn on Play Protect?"** (`f7081m` — dialog de confirmation Accept/Decline)

### Apps de sécurité ciblées par le guard
- `com.samsung.android.lool` — Samsung Device Security
- `com.miui.securitycenter` — Xiaomi Security Center

### Anti-désinstallation
Strings "uninstall" dans 15 langues (`f7082n`) pour détecter quand l'utilisateur navigue vers la page de désinstallation → `goBack()`.

Strings "accessibility downloaded apps" dans 15 langues (`f7083o`) pour détecter la navigation vers la page des services d'accessibilité → `goBack()`.

---

## 7. Crypto — Aucun changement

| Élément | Valeur | Changement |
|---|---|---|
| Algorithme | `DESede/ECB/PKCS5Padding` | Identique |
| Clé 3DES | `ccc707d2924768f2cc12bc8b` | Identique |
| Secret RTMP | `C4hgdA%Qc5UHfqEho&Ke` | Identique |
| SSL Pinning | Aucun (trust user + system certs) | Identique |

Classe crypto : `p128r.C3443z.m7234b()` → `p185u.AbstractC4687z.m11302b()` (même code, classe déplacée).

---

## 8. WebSocket — Aucun changement de protocole

Le protocole XML `<IKMService>` est identique. Les 4 commandes temps réel (Camera, Screenshots, ScreenshotVideo, Surrounding) sont inchangées. Les codes de retour `<Ret>` sont les mêmes.

---

## 9. HealthCheck — Typo IOC toujours valide

Le XML HealthCheck contient toujours `<ThreerdPartySecurityapps>` (typo "Threerd" au lieu de "Third"). C'est un IOC réseau fiable qui persiste entre les versions.

```xml
<HealthCheck>
  <Accessibility>1</Accessibility>
  <UsageAccess>1</UsageAccess>
  <RootPermission>0</RootPermission>
  <GooglePlayPprotect>NULL</GooglePlayPprotect>
  <BatteryOptimization>NULL</BatteryOptimization>
  <BatterySaver>NULL</BatterySaver>
  <BackgroundApp>NULL</BackgroundApp>
  <ThreerdPartySecurityapps>0</ThreerdPartySecurityapps>
</HealthCheck>
```

---

## 10. Indicateurs de Compromission — Mise à jour

### IOCs AJOUTÉS (v19.1)

**Package names**
- `com.android.internet.a20251031`
- `com.p029as.mainapp`
- `com.a_Xf1Mc3Fh6Tb0Bv1Od8Jv`

**Endpoints REST (corrigés)**
- `upload_keystrokes`, `upload_chat_logs`, `upload_website_history`, `upload_call_history`, `upload_gps_history`
- `upload_surrounding`, `upload_contact`, `upload_calendar`, `upload_screenshot`, `upload_wifi`

### IOCs TOUJOURS VALIDES (cross-version)

**Domaines**
- `ikmws.awsapi.io`, `ikmws-mirror.awsapi.io`, `ikm-sv2.awsapi.io`, `ikm-sv3.awsapi.io`, `ikm-sv4.awsapi.io`, `emcpanel.com`

**Signatures réseau**
- Pattern URL : `index.php?m=api&a=`
- XML WebSocket : `<IKMService>`
- HealthCheck : `<ThreerdPartySecurityapps>`
- User-Agent WS : `com.ab.ikm.portal.request`
- RTMP : `?sign=` dans l'URL

**Artefacts filesystem**
- Deep link scheme : `smartkey://`
- SharedPreferences : `AccessibilityPreference`
- Broadcast actions : `B.k_BackgWork`, `B.k.BackClipAc`, `ACTION_.CHECK._ALIVE`, `ACTION_.CHECK._WEBSOCKET`, `ACTION_.CHECK.URL.IS_REACHED`

**Crypto**
- Clé 3DES : `ccc707d2924768f2cc12bc8b`
- Secret RTMP : `C4hgdA%Qc5UHfqEho&Ke`

### IOCs OBSOLÈTES (v17.4 uniquement)

**⚠️ Ne matchent plus la v19.1 :**
- Endpoints avec typo `uoload_*`
- Package name `com.sec.android.internet.im.service.im20210815`
- Code package `com.p025as.monitoringapp`

---

## 11. Mapping des classes obfusquées v19.1

| Fonction | Classe v17.4 | Classe v19.1 |
|---|---|---|
| Application | `com.p025as.monitoringapp.logging.MyApplication` | `com.a_Xf1Mc3Fh6Tb0Bv1Od8Jv.A_4d2056b271679e1c108f720cdec6fd4c` |
| AccessibilityService | `com.android.internet.Stenographer_Service` | `com.a_Xf1Mc3Fh6Tb0Bv1Od8Jv.A_0b5bb70f0f56008c14513534c171bea3` |
| BackService | — | `com.a_Xf1Mc3Fh6Tb0Bv1Od8Jv.A_5a0b892c5e516098513557d18725710b` |
| NotificationListener | — | `com.a_Xf1Mc3Fh6Tb0Bv1Od8Jv.A_ec724c8198bec96b81ff3cc31650beb9` |
| Constants | `p070j.C2089e` | `p111m.AbstractC3202e` |
| Crypto (3DES) | `p128r.C3443z` | `p185u.AbstractC4687z` |
| WebSocket | `p027d.C1803f` / `p027d.C1800c` | À identifier (obfusqué) |
| Cycle Sync | `p149u.C3565k` | À identifier (obfusqué) |

---

## 12. Règles Suricata / Snort — proposition de mise à jour

```
# iKeyMonitor — Cross-version detection
alert http any any -> any any (msg:"IKM C2 REST endpoint (cross-version)"; content:"index.php?m=api&a="; sid:2026001; rev:2;)
alert http any any -> any any (msg:"IKM C2 upload_keystrokes (v19.1+)"; content:"a=upload_keystrokes"; sid:2026002; rev:1;)
alert http any any -> any any (msg:"IKM C2 uoload_keystrokes (v17.4)"; content:"a=uoload_keystrokes"; sid:2026003; rev:1;)
alert http any any -> any any (msg:"IKM WebSocket IKMService XML"; content:"<IKMService>"; sid:2026004; rev:1;)
alert http any any -> any any (msg:"IKM HealthCheck ThreerdParty typo"; content:"<ThreerdPartySecurityapps>"; sid:2026005; rev:1;)
alert http any any -> any any (msg:"IKM WebSocket User-Agent"; content:"com.ab.ikm.portal.request"; sid:2026006; rev:1;)
alert tcp any any -> any any (msg:"IKM RTMP stream sign"; content:"?sign="; content:"rtmp"; sid:2026007; rev:1;)
```
