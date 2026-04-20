/**
 * iKeyMonitor v17.4 — Frida hooks
 * ================================
 * Hook C2 communication, crypto, and WebSocket messages.
 *
 * Usage:
 *   frida -U -f com.sec.android.internet.im.service.im20210815 -l ikeymonitor_hook.js --no-pause
 */

Java.perform(function () {
    console.log("[*] iKeyMonitor hooks loaded");

    // -----------------------------------------------------------------------
    // 1. 3DES encryption — log plaintext + key before encrypt
    // -----------------------------------------------------------------------
    try {
        var C3443z = Java.use("p128r.C3443z");
        C3443z.m7234b.implementation = function (plaintext, key) {
            console.log("[3DES] encrypt: plaintext=" + plaintext + " key=" + key);
            var result = this.m7234b(plaintext, key);
            console.log("[3DES] result: " + result);
            return result;
        };
        console.log("[+] Hooked 3DES encrypt (C3443z.m7234b)");
    } catch (e) {
        console.log("[-] Failed to hook 3DES: " + e);
    }

    // -----------------------------------------------------------------------
    // 2. WebSocket outgoing messages
    // -----------------------------------------------------------------------
    try {
        var WsManager = Java.use("p027d.C1803f");
        WsManager.m3421q.implementation = function (msg) {
            console.log("[WS OUT] " + msg);
            return this.m3421q(msg);
        };
        console.log("[+] Hooked WS send (C1803f.m3421q)");
    } catch (e) {
        console.log("[-] Failed to hook WS send: " + e);
    }

    // -----------------------------------------------------------------------
    // 3. WebSocket incoming messages (dispatched on main thread)
    // -----------------------------------------------------------------------
    try {
        var WsListener = Java.use("p027d.C1803f$b");
        WsListener.m3426h.implementation = function (msg) {
            console.log("[WS IN] " + msg);
            this.m3426h(msg);
        };
        console.log("[+] Hooked WS recv (C1803f$b.m3426h)");
    } catch (e) {
        console.log("[-] Failed to hook WS recv: " + e);
    }

    // -----------------------------------------------------------------------
    // 4. REST cycle POST — outgoing data
    // -----------------------------------------------------------------------
    try {
        var SyncCycle = Java.use("p149u.C3565k");
        SyncCycle.m8100a.implementation = function (ctx) {
            console.log("[CYCLE] cycle sync triggered");
            this.m8100a(ctx);
        };
        console.log("[+] Hooked cycle sync (C3565k.m8100a)");
    } catch (e) {
        console.log("[-] Failed to hook cycle: " + e);
    }

    // -----------------------------------------------------------------------
    // 5. Cycle response parsing — see what server pushes
    // -----------------------------------------------------------------------
    try {
        var SyncCycle2 = Java.use("p149u.C3565k");
        SyncCycle2.m8101b.implementation = function (response, ctx) {
            console.log("[CYCLE RESP] " + response);
            this.m8101b(response, ctx);
        };
        console.log("[+] Hooked cycle response (C3565k.m8101b)");
    } catch (e) {
        console.log("[-] Failed to hook cycle response: " + e);
    }

    // -----------------------------------------------------------------------
    // 6. REST HTTP POST — generic upload interceptor
    // -----------------------------------------------------------------------
    try {
        var C3560f = Java.use("p149u.C3560f");
        C3560f.m8040O.implementation = function (ctx, url, data, extra) {
            console.log("[HTTP POST] url=" + url);
            console.log("[HTTP POST] data=" + data.substring(0, Math.min(data.length, 500)));
            var resp = this.m8040O(ctx, url, data, extra);
            console.log("[HTTP RESP] " + (resp ? resp.substring(0, Math.min(resp.length, 500)) : "null"));
            return resp;
        };
        console.log("[+] Hooked HTTP POST (C3560f.m8040O)");
    } catch (e) {
        console.log("[-] Failed to hook HTTP POST: " + e);
    }

    // -----------------------------------------------------------------------
    // 7. C2 server address resolution
    // -----------------------------------------------------------------------
    try {
        var Constants = Java.use("p070j.C2089e");
        Constants.m4542a.implementation = function () {
            this.m4542a();
            console.log("[C2 ADDR] REST: " + Constants.f4848a.value);
            console.log("[C2 ADDR] Secret: " + Constants.f4849b.value);
        };
        console.log("[+] Hooked C2 address init (C2089e.m4542a)");
    } catch (e) {
        console.log("[-] Failed to hook C2 addr: " + e);
    }

    // -----------------------------------------------------------------------
    // 8. WebSocket camera command handler
    // -----------------------------------------------------------------------
    try {
        var WsOper = Java.use("p027d.C1800c");
        WsOper.m3390c.implementation = function (ws, xml) {
            console.log("[CMD CAMERA] " + xml);
            this.m3390c(ws, xml);
        };
        console.log("[+] Hooked Camera cmd (C1800c.m3390c)");
    } catch (e) {
        console.log("[-] Failed to hook camera cmd: " + e);
    }

    // -----------------------------------------------------------------------
    // 9. WebSocket screenshot command handler
    // -----------------------------------------------------------------------
    try {
        var WsOper2 = Java.use("p027d.C1800c");
        WsOper2.m3391d.implementation = function (ws, xml) {
            console.log("[CMD SCREENSHOT] " + xml);
            this.m3391d(ws, xml);
        };
        console.log("[+] Hooked Screenshot cmd (C1800c.m3391d)");
    } catch (e) {
        console.log("[-] Failed to hook screenshot cmd: " + e);
    }

    // -----------------------------------------------------------------------
    // 10. WebSocket screen stream command handler
    // -----------------------------------------------------------------------
    try {
        var WsOper3 = Java.use("p027d.C1800c");
        WsOper3.m3392e.implementation = function (ws, xml) {
            console.log("[CMD SCREENSTREAM] " + xml);
            this.m3392e(ws, xml);
        };
        console.log("[+] Hooked ScreenStream cmd (C1800c.m3392e)");
    } catch (e) {
        console.log("[-] Failed to hook screenstream cmd: " + e);
    }

    // -----------------------------------------------------------------------
    // 11. WebSocket surrounding command handler
    // -----------------------------------------------------------------------
    try {
        var WsOper4 = Java.use("p027d.C1800c");
        WsOper4.m3393f.implementation = function (ws, xml) {
            console.log("[CMD SURROUNDING] " + xml);
            this.m3393f(ws, xml);
        };
        console.log("[+] Hooked Surrounding cmd (C1800c.m3393f)");
    } catch (e) {
        console.log("[-] Failed to hook surrounding cmd: " + e);
    }

    // -----------------------------------------------------------------------
    // 12. RTMP URL generation — capture stream URL
    // -----------------------------------------------------------------------
    try {
        var MyApp = Java.use("com.p025as.monitoringapp.logging.MyApplication");
        MyApp.m2032g.implementation = function () {
            var url = this.m2032g();
            console.log("[RTMP URL] " + url);
            return url;
        };
        console.log("[+] Hooked RTMP URL gen (MyApplication.m2032g)");
    } catch (e) {
        console.log("[-] Failed to hook RTMP URL: " + e);
    }

    // -----------------------------------------------------------------------
    // 13. Keylogger input capture
    // -----------------------------------------------------------------------
    try {
        var AccInput = Java.use("com.android.internet.Acc_InputText");
        AccInput.onNewText.implementation = function (text, event, nodeInfo) {
            console.log("[KEYLOG] " + text);
            this.onNewText(text, event, nodeInfo);
        };
        console.log("[+] Hooked keylogger (Acc_InputText.onNewText)");
    } catch (e) {
        console.log("[-] Failed to hook keylogger: " + e);
    }

    console.log("[*] All hooks installed — monitoring iKeyMonitor C2 traffic");
});
