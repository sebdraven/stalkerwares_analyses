/**
 * iKeyMonitor v19.1 — Frida hooks
 * =================================
 * Hook C2 communication, crypto, and WebSocket messages.
 * Adapted from v17.4 hooks with updated obfuscated class names.
 *
 * Package: com.android.internet.a20251031
 * Code package: com.p029as.mainapp (JADX: com.a_Xf1Mc3Fh6Tb0Bv1Od8Jv.A_*)
 *
 * Usage:
 *   frida -U -f com.android.internet.a20251031 -l ikeymonitor_v19.1_hook.js --no-pause
 *
 * Research use only.
 */

Java.perform(function () {
    console.log("[*] iKeyMonitor v19.1 hooks loading...");
    console.log("[*] Package: com.android.internet.a20251031");

    // -----------------------------------------------------------------------
    // 1. 3DES encryption — log plaintext + key before encrypt
    //    v17.4: p128r.C3443z.m7234b -> v19.1: p185u.AbstractC4687z.m11302b
    // -----------------------------------------------------------------------
    try {
        var CryptoClass = Java.use("p185u.AbstractC4687z");
        CryptoClass.m11302b.implementation = function (plaintext, key) {
            console.log("[3DES] encrypt: plaintext=" + plaintext + " key=" + key);
            var result = this.m11302b(plaintext, key);
            console.log("[3DES] result: " + result);
            return result;
        };
        console.log("[+] Hooked 3DES encrypt (AbstractC4687z.m11302b)");
    } catch (e) {
        console.log("[-] Failed to hook 3DES: " + e);
    }

    // -----------------------------------------------------------------------
    // 2. Constants init — capture C2 server address
    //    v17.4: p070j.C2089e.m4542a -> v19.1: p111m.AbstractC3202e.m8688a
    // -----------------------------------------------------------------------
    try {
        var Constants = Java.use("p111m.AbstractC3202e");
        Constants.m8688a.implementation = function () {
            this.m8688a();
            console.log("[C2 ADDR] REST server: " + Constants.f7402a.value);
            console.log("[C2 ADDR] RTMP secret: " + Constants.f7403b.value);
            console.log("[C2 ADDR] Register: " + Constants.f7404c.value);
            console.log("[C2 ADDR] WS addr endpoint: " + Constants.f7407f.value);
        };
        console.log("[+] Hooked C2 address init (AbstractC3202e.m8688a)");
    } catch (e) {
        console.log("[-] Failed to hook C2 addr: " + e);
    }

    // -----------------------------------------------------------------------
    // 3. All REST endpoint URLs — log on build
    //    v19.1: p111m.AbstractC3202e.m8689b
    // -----------------------------------------------------------------------
    try {
        var ConstantsB = Java.use("p111m.AbstractC3202e");
        ConstantsB.m8689b.implementation = function () {
            this.m8689b();
            console.log("[ENDPOINTS] Built all endpoint URLs:");
            console.log("  register:      " + ConstantsB.f7404c.value);
            console.log("  cycle:         " + ConstantsB.f7406e.value);
            console.log("  keystrokes:    " + ConstantsB.f7415n.value);
            console.log("  chat_logs:     " + ConstantsB.f7416o.value);
            console.log("  web_history:   " + ConstantsB.f7417p.value);
            console.log("  call_history:  " + ConstantsB.f7418q.value);
            console.log("  gps_history:   " + ConstantsB.f7419r.value);
            console.log("  screenshot:    " + ConstantsB.f7420s.value);
            console.log("  contact:       " + ConstantsB.f7421t.value);
            console.log("  calendar:      " + ConstantsB.f7422u.value);
            console.log("  clipboard:     " + ConstantsB.f7423v.value);
            console.log("  photo:         " + ConstantsB.f7424w.value);
            console.log("  surrounding:   " + ConstantsB.f7425x.value);
            console.log("  screenvideo:   " + ConstantsB.f7400C.value);
            console.log("  video:         " + ConstantsB.f7401D.value);
            console.log("  check_update:  " + ConstantsB.f7398A.value);
            console.log("  crash_logs:    " + ConstantsB.f7427z.value);
        };
        console.log("[+] Hooked endpoint builder (AbstractC3202e.m8689b)");
    } catch (e) {
        console.log("[-] Failed to hook endpoint builder: " + e);
    }

    // -----------------------------------------------------------------------
    // 4. AccessibilityService — onAccessibilityEvent
    //    v19.1: com.a_Xf1Mc3Fh6Tb0Bv1Od8Jv.A_0b5bb70f0f56008c14513534c171bea3
    // -----------------------------------------------------------------------
    try {
        var AccService = Java.use("com.a_Xf1Mc3Fh6Tb0Bv1Od8Jv.A_0b5bb70f0f56008c14513534c171bea3");
        AccService.onAccessibilityEvent.implementation = function (event) {
            var pkg = "?";
            try {
                var root = this.getRootInActiveWindow();
                if (root != null && root.getPackageName() != null) {
                    pkg = root.getPackageName().toString();
                }
            } catch (e2) {}
            var eventType = event.getEventType();
            if (eventType === 16 || eventType === 32 || eventType === 1) {
                console.log("[ACC EVENT] type=" + eventType + " pkg=" + pkg);
            }
            this.onAccessibilityEvent(event);
        };
        console.log("[+] Hooked AccessibilityService.onAccessibilityEvent");
    } catch (e) {
        console.log("[-] Failed to hook AccService: " + e);
    }

    // -----------------------------------------------------------------------
    // 5. Keylogger — text change handler
    //    v19.1: A_0b5bb70f0f56008c14513534c171bea3.m1641o (onViewTextChanged)
    // -----------------------------------------------------------------------
    try {
        var AccService2 = Java.use("com.a_Xf1Mc3Fh6Tb0Bv1Od8Jv.A_0b5bb70f0f56008c14513534c171bea3");
        AccService2.m1641o.implementation = function (event, nodeInfo) {
            try {
                var textList = event.getText();
                if (textList != null && !textList.isEmpty()) {
                    var text = textList.get(0);
                    if (text != null) {
                        console.log("[KEYLOG] " + text.toString());
                    }
                }
            } catch (e2) {}
            this.m1641o(event, nodeInfo);
        };
        console.log("[+] Hooked keylogger text handler (m1641o)");
    } catch (e) {
        console.log("[-] Failed to hook keylogger: " + e);
    }

    // -----------------------------------------------------------------------
    // 6. Chat interception dispatcher
    //    v19.1: com.android.internet.chats.Sts_chats.Deal_Chat_Info
    // -----------------------------------------------------------------------
    try {
        var StsChats = Java.use("com.android.internet.chats.Sts_chats");
        StsChats.Deal_Chat_Info.implementation = function (ctx, event, nodeInfo, pkg) {
            console.log("[CHAT INTERCEPT] target_pkg=" + pkg);
            this.Deal_Chat_Info(ctx, event, nodeInfo, pkg);
        };
        console.log("[+] Hooked chat interceptor (Sts_chats.Deal_Chat_Info)");
    } catch (e) {
        console.log("[-] Failed to hook chat intercept: " + e);
    }

    // -----------------------------------------------------------------------
    // 7. Web history interception
    //    v19.1: com.android.internet.web.Sts_web.getWebHisr
    // -----------------------------------------------------------------------
    try {
        var StsWeb = Java.use("com.android.internet.web.Sts_web");
        StsWeb.getWebHisr.implementation = function (ctx, nodeInfo, pkg, source) {
            console.log("[WEB HISTORY] pkg=" + pkg + " source=" + source);
            this.getWebHisr(ctx, nodeInfo, pkg, source);
        };
        console.log("[+] Hooked web history (Sts_web.getWebHisr)");
    } catch (e) {
        console.log("[-] Failed to hook web history: " + e);
    }

    // -----------------------------------------------------------------------
    // 8. Guard — anti-uninstall / anti-detection
    //    v19.1: ACC_Guard, AppInfo_Guard, PPP_Guard, Security_Apps_Guard
    // -----------------------------------------------------------------------
    try {
        var AccGuard = Java.use("com.android.internet.guard.ACC_Guard");
        AccGuard.detectACCPage.implementation = function (ctx, nodeInfo, pkg, extra) {
            var detected = this.detectACCPage(ctx, nodeInfo, pkg, extra);
            if (detected) {
                console.log("[GUARD] ACC page detected for pkg=" + pkg + " -> BLOCKING");
            }
            return detected;
        };
        console.log("[+] Hooked ACC_Guard.detectACCPage");
    } catch (e) {
        console.log("[-] Failed to hook ACC_Guard: " + e);
    }

    try {
        var PppGuard = Java.use("com.android.internet.guard.PPP_Guard");
        PppGuard.detectPPP.implementation = function (ctx, nodeInfo, pkg, extra) {
            var result = this.detectPPP(ctx, nodeInfo, pkg, extra);
            console.log("[GUARD] PPP check for pkg=" + pkg + " result=" + result.toString());
            return result;
        };
        console.log("[+] Hooked PPP_Guard.detectPPP");
    } catch (e) {
        console.log("[-] Failed to hook PPP_Guard: " + e);
    }

    try {
        var SecGuard = Java.use("com.android.internet.guard.Security_Apps_Guard");
        SecGuard.detect_Security_Apps.implementation = function (ctx, nodeInfo, pkg, extra) {
            var detected = this.detect_Security_Apps(ctx, nodeInfo, pkg, extra);
            if (detected) {
                console.log("[GUARD] Security app detected: pkg=" + pkg + " -> BLOCKING");
            }
            return detected;
        };
        console.log("[+] Hooked Security_Apps_Guard.detect_Security_Apps");
    } catch (e) {
        console.log("[-] Failed to hook Security_Apps_Guard: " + e);
    }

    // -----------------------------------------------------------------------
    // 9. HealthCheck XML generation
    //    v19.1: p185u.AbstractC4687z.m11308h
    // -----------------------------------------------------------------------
    try {
        var HealthCheck = Java.use("p185u.AbstractC4687z");
        HealthCheck.m11308h.implementation = function (ctx) {
            var xml = this.m11308h(ctx);
            console.log("[HEALTHCHECK] " + xml);
            return xml;
        };
        console.log("[+] Hooked HealthCheck (AbstractC4687z.m11308h)");
    } catch (e) {
        console.log("[-] Failed to hook HealthCheck: " + e);
    }

    // -----------------------------------------------------------------------
    // 10. Clipboard exfiltration (Android 10+ broadcast)
    //     v19.1: A_5d424b22af0a8e71d3dee1c6815c96b6 (Get10ClpInfoReceiver)
    // -----------------------------------------------------------------------
    try {
        var ClipReceiver = Java.use("com.a_Xf1Mc3Fh6Tb0Bv1Od8Jv.A_5d424b22af0a8e71d3dee1c6815c96b6");
        ClipReceiver.onReceive.implementation = function (ctx, intent) {
            console.log("[CLIPBOARD] Clipboard exfiltration triggered");
            this.onReceive(ctx, intent);
        };
        console.log("[+] Hooked clipboard receiver");
    } catch (e) {
        console.log("[-] Failed to hook clipboard: " + e);
    }

    // -----------------------------------------------------------------------
    // 11. OkHttp interceptor — catch all HTTP requests
    // -----------------------------------------------------------------------
    try {
        var OkHttpClient = Java.use("okhttp3.OkHttpClient");
        var RealCall = Java.use("okhttp3.RealCall");
        RealCall.execute.implementation = function () {
            var request = this.request();
            console.log("[HTTP] " + request.method() + " " + request.url().toString());
            var response = this.execute();
            console.log("[HTTP] Response: " + response.code());
            return response;
        };
        console.log("[+] Hooked OkHttp RealCall.execute");
    } catch (e) {
        console.log("[-] Failed to hook OkHttp: " + e);
    }

    // Async variant
    try {
        var RealCall2 = Java.use("okhttp3.RealCall");
        RealCall2.enqueue.implementation = function (callback) {
            var request = this.request();
            console.log("[HTTP ASYNC] " + request.method() + " " + request.url().toString());
            this.enqueue(callback);
        };
        console.log("[+] Hooked OkHttp RealCall.enqueue");
    } catch (e) {
        console.log("[-] Failed to hook OkHttp async: " + e);
    }

    // -----------------------------------------------------------------------
    // 12. Application class — startup init
    //     v19.1: com.a_Xf1Mc3Fh6Tb0Bv1Od8Jv.A_4d2056b271679e1c108f720cdec6fd4c
    // -----------------------------------------------------------------------
    try {
        var AppClass = Java.use("com.a_Xf1Mc3Fh6Tb0Bv1Od8Jv.A_4d2056b271679e1c108f720cdec6fd4c");
        AppClass.onCreate.implementation = function () {
            console.log("[APP] Application.onCreate — iKeyMonitor v19.1 starting up");
            this.onCreate();
        };
        console.log("[+] Hooked Application.onCreate");
    } catch (e) {
        console.log("[-] Failed to hook Application: " + e);
    }

    // -----------------------------------------------------------------------
    // 13. BuildConfig — dump all hardcoded values
    // -----------------------------------------------------------------------
    try {
        var BC = Java.use("com.android.internet.BuildConfig");
        console.log("[CONFIG] APPLICATION_ID: " + BC.APPLICATION_ID.value);
        console.log("[CONFIG] VERSION_NAME: " + BC.VERSION_NAME.value);
        console.log("[CONFIG] VERSION_CODE: " + BC.VERSION_CODE.value);
        console.log("[CONFIG] SERVER_NAME: " + BC.SERVER_NAME.value);
        console.log("[CONFIG] SERVER_URLS: " + BC.SERVER_URLS.value);
        console.log("[CONFIG] SCREEN_VIDEO_SECRET: " + BC.SCREEN_VIDEO_SECRET.value);
        console.log("[CONFIG] FLAVOR: " + BC.FLAVOR.value);
        console.log("[CONFIG] IS_TestSvr: " + BC.IS_TestSvr.value);
    } catch (e) {
        console.log("[-] Failed to read BuildConfig: " + e);
    }

    console.log("[*] All v19.1 hooks installed — monitoring iKeyMonitor C2 traffic");
    console.log("[*] Target chat apps: WhatsApp, WA Business, Telegram, FB Messenger,");
    console.log("    WeChat, Line, Viber, Signal, Snapchat, Zalo, Gmail, Instagram,");
    console.log("    Skype, TikTok, Twitter/X");
});
