## 5. Applications ciblées — Classe `p053c.p077c.p081d.C0626d`

### 5.1 Messageries instantanées (54 apps, flag 304)

| Catégorie | Package | App |
|-----------|---------|-----|
| **Messaging** | `com.whatsapp` | WhatsApp |
| | `com.facebook.orca` | Facebook Messenger |
| | `com.viber.voip` | Viber |
| | `org.telegram.messenger` | Telegram |
| | `org.telegram.plus` | Telegram Plus (fork) |
| | `com.google.android.talk` | Google Hangouts |
| | `com.google.android.apps.dynamite` | Google Chat |
| | `com.google.android.apps.meetings` | Google Meet |
| | `com.snapchat.android` | Snapchat |
| | `com.imo.android.imoim` | imo |
| | `jp.naver.line.android` | LINE |
| | `com.linecorp.linelite` | LINE Lite |
| | `com.textmeinc.textme` | TextMe |
| | `kik.android` | Kik |
| | `com.tencent.mm` | WeChat |
| | `org.thoughtcrime.securesms` | Signal |
| | `com.discord` | Discord |
| | `com.microsoft.teams` | Microsoft Teams |
| | `com.kakao.talk` | KakaoTalk |
| | `ch.threema.app.work` | Threema Work |
| | `ch.threema.app.onprem` | Threema OnPrem |
| | `org.vidogram.messenger` | Vidogram |
| | `com.zing.zalo` | Zalo |
| | `com.Slack` | Slack |
| | `com.Slack.intune` | Slack (Intune) |
| **Social** | `com.instagram.android` | Instagram |
| | `com.vk.im` | VK Messenger |
| | `com.vkontakte.android` | VKontakte |
| | `ru.ok.android` | Odnoklassniki |
| | `com.zhiliaoapp.musically` | TikTok |
| | `com.zhiliaoapp.musically.go` | TikTok Lite |
| | `com.tumblr` | Tumblr |
| | `com.weico.international` | Weico (Weibo client) |
| | `com.reddit.frontpage` | Reddit |
| | `com.twitter.android` | Twitter/X |
| | `com.skype.raider` | Skype |
| **Dating** | `com.tinder` | Tinder |
| | `ru.gostinder` | Tinder (RU) |
| | `ru.mamba.client` | Mamba |
| | `com.getpure.pure` | Pure |
| | `fitil.smsystem` | Fitil |
| | `com.wamba.bbs` | Wamba |
| | `com.muzmatch.muzmatchapp` | Muzmatch |
| | `su.xdesign.skylove` | Skylove |
| | `enterprises.dating.boo` | Boo |
| | `com.waplog.social` | Waplog |
| | `ru.mobstudio.andgalaxy` | Galaxy (RU dating) |
| **Email** | `com.google.android.gm` | Gmail |
| | `ru.yandex.mail` | Yandex Mail |
| | `ru.mail.mailapp` | Mail.ru |
| | `me.bluemail.mail` | BlueMail |
| | `com.microsoft.office.outlook` | Outlook |
| | `com.microsoft.outlooklite` | Outlook Lite |
| | `com.samsung.android.email.provider` | Samsung Email |
| **BBM** | `com.bbm.enterprise` | BBM Enterprise |

### 5.2 Navigateurs web (44+ apps, flag 305)

| Package | Navigateur |
|---------|------------|
| `com.android.browser` | AOSP Browser |
| `com.android.chrome` | Chrome |
| `com.chrome.beta` | Chrome Beta |
| `org.mozilla.firefox` | Firefox |
| `com.opera.browser` | Opera |
| `com.opera.mini.native` | Opera Mini |
| `com.opera.browser.afin` | Opera (variante) |
| `com.UCMobile.intl` | UC Browser |
| `com.yandex.browser` | Yandex Browser |
| `com.ninesky.browser` | Ninesky Browser |
| `org.torproject.torbrowser` | Tor Browser |
| `com.duckduckgo.mobile.android` | DuckDuckGo |
| `com.microsoft.emmx` | Microsoft Edge |
| `com.sec.android.app.sbrowser` | Samsung Internet |
| `com.sec.android.app.sbrowser.beta` | Samsung Internet Beta |
| `com.asus.browser` | ASUS Browser |
| `com.asus.browsergenie` | ASUS Browser Genie |
| `com.sonymobile.smallbrowser` | Sony Browser |
| `com.htc.sense.browser` | HTC Sense Browser |
| `com.htc.browser` | HTC Browser |
| `com.cyngn.browser` | Cyanogen Browser |
| `com.miui.browser` | Xiaomi MIUI Browser |
| `com.mi.globalbrowser.mini` | Mi Browser Mini |
| `com.mi.globalbrowser` | Mi Browser |
| `com.hsv.freeadblockerbrowser` | Free Adblocker Browser |
| `com.vivo.browser` | Vivo Browser |
| `com.heytap.browser` | Heytap/OPPO Browser |
| `com.coloros.browser` | ColorOS Browser |
| `com.brave.browser` | Brave |
| `com.huawei.browser` | Huawei Browser |
| `com.quark.browser` | Quark Browser |
| `com.kiwibrowser.browser` | Kiwi Browser |
| `com.tcl.browser` | TCL Browser |
| `com.nearme.browser` | Nearme/Realme Browser |
| `org.adblockplus.browser` | Adblock Plus Browser |
| `org.cromite.cromite` | Cromite |
| `com.pawxy.browser` | Pawxy Browser |
| ... + apps chiffrées via `C0870h.m6219c()` | + navigateurs additionnels obfusqués |

### 5.3 SMS (flag 313)

| Package | App |
|---------|-----|
| `com.google.android.apps.messaging` | Google Messages |
| + apps dynamiques via config serveur | Ajoutées à distance |

### 5.4 Observations

- **Total** : 100+ applications ciblées
- **Focus géographique** : forte présence d'apps russophones (VK, OK, Yandex, Mail.ru, Mamba, Tinder RU)
- **Apps de dating** : 10 apps de rencontres ciblées → surveillance relationnelle/IPV
- **Apps chiffrées** : Signal, Threema ciblées via Accessibility (contourne le E2E)
- **Navigateurs** : couverture exhaustive y compris Tor Browser et DuckDuckGo
- **Config dynamique** : le serveur peut ajouter des apps à surveiller à distance (flag 313)
- **Chiffrement des noms** : certains packages sont chiffrés via `C0870h.m6219c()` (AES)
