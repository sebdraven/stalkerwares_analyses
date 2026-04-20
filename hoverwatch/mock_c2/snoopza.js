/*
 * Snoopza C2 Redirect — Frida Hook v2.0
 * =======================================
 * Cible : com.android.core.mngam (Snoopza v6.5.83, brand SNPA)
 * Synchronisé avec hoverwatch_analysis.md v3 + mock_c2 v2.0.0
 *
 * Note : même codebase que Hoverwatch (Refog Inc.), seuls le package
 * et le brand code (HWA → SNPA) diffèrent. Les noms DEX post-R8
 * (hw.utils.z, e.a.a, etc.) sont identiques.
 *
 * Lancement :
 *   frida -U -f com.android.core.mngam -l snoopza_hook.js --no-pause
 *
 * Modifier MOCK_C2_URL avec l'IP du mock côté VPN Corellium.
 */

const BRAND          = "SNOOPZA";
const TARGET_PACKAGE = "com.android.core.mngam";
const MOCK_C2_URL    = "https://10.11.1.1:8443/";
const MOCK_DOMAINS   = MOCK_C2_URL + ";" + MOCK_C2_URL + ";" + MOCK_C2_URL;

const VERBOSE    = true;
const LOG_CRYPTO = true;
const BLOCK_KILL = true;

function ts() { return new Date().toISOString().substring(11, 23); }
function log(tag, msg) { console.log("[" + ts() + "] [" + BRAND + "] [" + tag + "] " + msg); }
function logKV(tag, k, v) { console.log("[" + ts() + "] [" + BRAND + "] [" + tag + "] " + k + " = \"" + v + "\""); }

function safeHook(label, fn) {
    try { fn(); log("INIT", "   ✅ " + label); }
    catch (e) { log("INIT", "   ⚠️  " + label + " — skipped: " + e.message); }
}

Java.perform(function () {
    log("INIT", "🎯 Hook v2.0 loaded for " + TARGET_PACKAGE);
    log("INIT", "   Mock C2: " + MOCK_C2_URL);
    log("INIT", "   Mode: crypto=" + LOG_CRYPTO + " | blockKill=" + BLOCK_KILL + " | verbose=" + VERBOSE);
    log("INIT", "");

    // -------------------------------------------------------------------
    // 1. SETTINGS — hw.utils.z (toutes les méthodes sont public static)
    // -------------------------------------------------------------------
    safeHook("Settings: ActivationID getter (s)", function () {
        var S = Java.use("hw.utils.z");
        S.s.implementation = function () { var v = S.s(); logKV("AUTH", "ActivationID", v); return v; };
    });

    safeHook("Settings: misc String getter (t)", function () {
        var S = Java.use("hw.utils.z");
        S.t.implementation = function () { var v = S.t(); logKV("AUTH", "t()", v); return v; };
    });

    safeHook("Settings: PIN/Password getter (u)", function () {
        var S = Java.use("hw.utils.z");
        S.u.implementation = function () { var v = S.u(); logKV("AUTH", "PIN/Password", v); return v; };
    });

    safeHook("Settings: current C2 domain (x) — REDIRECTED", function () {
        var S = Java.use("hw.utils.z");
        S.x.implementation = function () {
            var orig = S.x();
            log("C2-DOMAIN", "x() original: \"" + orig + "\" → \"" + MOCK_C2_URL + "\"");
            return MOCK_C2_URL;
        };
    });

    safeHook("Settings: domains list (y) — REDIRECTED", function () {
        var S = Java.use("hw.utils.z");
        S.y.implementation = function () {
            var orig = S.y();
            log("C2-DOMAIN", "y() original: \"" + orig + "\" → mock");
            return MOCK_DOMAINS;
        };
    });

    safeHook("Settings: domains setter (w0) — INTERCEPTED", function () {
        var S = Java.use("hw.utils.z");
        S.w0.implementation = function (newDomains) {
            log("C2-DOMAIN", "⚠️  App tried to SET domains: \"" + newDomains + "\" — forwarding mock");
            return S.w0(MOCK_DOMAINS);
        };
    });

    safeHook("Settings: ActivationID setter (s0)", function () {
        var S = Java.use("hw.utils.z");
        S.s0.implementation = function (newKey) {
            log("AUTH", "🔑 New ActivationID set by server: \"" + newKey + "\"");
            S.s0(newKey);
        };
    });

    safeHook("Settings: PIN setter (u0)", function () {
        var S = Java.use("hw.utils.z");
        S.u0.implementation = function (newPin) {
            log("AUTH", "🔐 PIN changed by server: \"" + newPin + "\"");
            S.u0(newPin);
        };
    });

    safeHook("Settings: app state getter (o)", function () {
        var S = Java.use("hw.utils.z");
        S.o.implementation = function () {
            var st = S.o();
            log("STATE", "app state read: " + st);
            return st;
        };
    });

    safeHook("Settings: app state setter (z0) — watch UNINSTALL_ASK", function () {
        var S = Java.use("hw.utils.z");
        S.z0.implementation = function (newState) {
            var name = newState ? newState.toString() : "null";
            log("STATE", "app state SET → " + name);
            if (BLOCK_KILL && name.indexOf("UNINSTALL_ASK") >= 0) {
                log("KILLSWITCH", "☠️  Blocking UNINSTALL_ASK state transition");
                return;
            }
            S.z0(newState);
        };
    });

    safeHook("Settings: enable monitor (v0)", function () {
        var S = Java.use("hw.utils.z");
        S.v0.implementation = function (enable) {
            log("CONTROL", "EnableMonitor → " + enable);
            S.v0(enable);
        };
    });

    safeHook("Settings: hide icon (x0)", function () {
        var S = Java.use("hw.utils.z");
        S.x0.implementation = function (hide) {
            log("STEALTH", "HideIcon → " + hide);
            S.x0(hide);
        };
    });

    // -------------------------------------------------------------------
    // 2. CRYPTO — hw.utils.h (clé effective "vallengt")
    // -------------------------------------------------------------------
    if (LOG_CRYPTO) {
        safeHook("Crypto: decrypt with default key 'val' (c)", function () {
            var C = Java.use("hw.utils.h");
            C.c.implementation = function (b64) {
                var pt = C.c(b64);
                var preview = b64.length > 30 ? b64.substring(0, 30) + "…" : b64;
                log("CRYPTO", "🔓 DES.dec(\"" + preview + "\") = \"" + pt + "\"");
                return pt;
            };
        });

        safeHook("Crypto: encrypt/decrypt with custom key (b)", function () {
            var C = Java.use("hw.utils.h");
            C.b.implementation = function (str, key, encrypt) {
                var r = C.b(str, key, encrypt);
                var op = encrypt ? "ENC" : "DEC";
                var inP  = str.length > 20 ? str.substring(0, 20) + "…" : str;
                var outP = (r && r.length > 40) ? r.substring(0, 40) + "…" : r;
                log("CRYPTO", "🔐 DES." + op + "(key=\"" + key + "\") \"" + inP + "\" → \"" + outP + "\"");
                return r;
            };
        });
    }

    // -------------------------------------------------------------------
    // 3. HTTP CLIENT — e.a.a (registration, activation, sync, event)
    // -------------------------------------------------------------------
    safeHook("HttpClient: registration (q)", function () {
        var H = Java.use("e.a.a");
        H.q.overload("java.lang.String", "java.lang.String", "int")
            .implementation = function (username, password, userType) {
                var typeLabel = ["CHILD","EMPLOYEE","OWN","UNDEFINED"][userType] || "?";
                log("REGISTER", "═══════════════════════════════════");
                log("REGISTER", "📱 REGISTRATION call");
                log("REGISTER", "   Username:  \"" + username + "\"");
                log("REGISTER", "   Password:  \"" + password + "\"");
                log("REGISTER", "   user_type: " + userType + " (" + typeLabel + ")");
                log("REGISTER", "═══════════════════════════════════");
                return H.q(username, password, userType);
            };
    });

    safeHook("HttpClient: activation (B)", function () {
        var H = Java.use("e.a.a");
        H.B.implementation = function (json) {
            log("ACTIVATE", "📝 Activation payload: " + json);
            return H.B(json);
        };
    });

    safeHook("HttpClient: sync (t)", function () {
        var H = Java.use("e.a.a");
        H.t.implementation = function (extraHeaders) {
            if (extraHeaders !== null) {
                log("SYNC", "📡 Sync triggered with " + extraHeaders.length + " extra headers:");
                for (var i = 0; i + 1 < extraHeaders.length; i += 2) {
                    log("SYNC", "   " + extraHeaders[i] + ": " + extraHeaders[i + 1]);
                }
            } else {
                log("SYNC", "📡 Sync triggered");
            }
            return H.t(extraHeaders);
        };
    });

    safeHook("HttpClient: client event (r)", function () {
        var H = Java.use("e.a.a");
        H.r.implementation = function (eventData, callback) {
            log("EVENT", "📤 Client event: \"" + eventData + "\"");
            H.r(eventData, callback);
        };
    });

    // -------------------------------------------------------------------
    // 4. MODULE CONFIG — hw.utils.y
    // -------------------------------------------------------------------
    safeHook("ModuleConfig: accept new settings (n)", function () {
        var M = Java.use("hw.utils.y");
        M.n.implementation = function (json) {
            log("SETTINGS", "═══════════════════════════════════");
            log("SETTINGS", "⚙️  NEW SETTINGS FROM C2:");
            log("SETTINGS", json.toString());
            log("SETTINGS", "═══════════════════════════════════");
            M.n(json);
        };
    });

    safeHook("ModuleConfig: enable/disable module (c0)", function () {
        var moduleNames = {
            302: "Screenshots", 304: "IM Reader", 305: "Browser",
            312: "Call Recording", 313: "SMS", 314: "Location",
            319: "Front Camera"
        };
        var M = Java.use("hw.utils.y");
        M.c0.implementation = function (moduleId, enabled) {
            var name = moduleNames[moduleId] || ("Module_" + moduleId);
            log("MODULE", (enabled ? "✅" : "❌") + " " + name + " (" + moduleId + ") → " + enabled);
            M.c0(moduleId, enabled);
        };
    });

    // -------------------------------------------------------------------
    // 5. INTERNAL LOGGER — hw.utils.l
    // -------------------------------------------------------------------
    if (VERBOSE) {
        safeHook("Logger: info (s)", function () {
            var L = Java.use("hw.utils.l");
            L.s.overload("java.lang.String", "java.lang.String")
                .implementation = function (tag, msg) { log("HW-" + tag, msg); L.s(tag, msg); };
        });

        safeHook("Logger: error (t)", function () {
            var L = Java.use("hw.utils.l");
            L.t.overload("java.lang.String", "java.lang.String")
                .implementation = function (tag, msg) { log("HW-" + tag, "[ERR] " + msg); L.t(tag, msg); };
        });

        safeHook("Logger: exception (u)", function () {
            var L = Java.use("hw.utils.l");
            L.u.implementation = function (tag, msg, ex) {
                log("HW-" + tag, "[EX] " + msg + " → " + ex);
                L.u(tag, msg, ex);
            };
        });
    }

    // -------------------------------------------------------------------
    // 6. KILL SWITCH — hw.core.c (m5393a → a, m5395c → c)
    // -------------------------------------------------------------------
    if (BLOCK_KILL) {
        safeHook("KillSwitch: arm setter (a)", function () {
            var U = Java.use("hw.core.c");
            U.a.implementation = function () {
                log("KILLSWITCH", "═══════════════════════════════════");
                log("KILLSWITCH", "☠️  KILL SWITCH armed (HTTP 410 received) — BLOCKED");
                log("KILLSWITCH", "═══════════════════════════════════");
            };
        });

        safeHook("KillSwitch: trigger uninstall prompt (c)", function () {
            var U = Java.use("hw.core.c");
            U.c.implementation = function (activity, z) {
                log("KILLSWITCH", "☠️  Uninstall prompt would be shown — BLOCKED");
            };
        });
    }

    // -------------------------------------------------------------------
    // 7. RECORDING — hw.recorder.ServiceRecording
    // -------------------------------------------------------------------
    safeHook("Recording: start (o)", function () {
        var R = Java.use("hw.recorder.ServiceRecording");
        R.o.implementation = function (type, bundle) {
            log("RECORDER", "🎙️  RECORDING START — type=" + type);
            if (bundle !== null) log("RECORDER", "   bundle=" + bundle);
            R.o(type, bundle);
        };
    });

    safeHook("Recording: stop (p)", function () {
        var R = Java.use("hw.recorder.ServiceRecording");
        R.p.implementation = function (type) {
            log("RECORDER", "⏹️  RECORDING STOP — type=" + type);
            R.p(type);
        };
    });

    // -------------------------------------------------------------------
    // 8. IM INTERCEPTION — hw.imreader.InstantMessage (texte avant BDD)
    // -------------------------------------------------------------------
    safeHook("InstantMessage: setText", function () {
        var IM = Java.use("hw.imreader.InstantMessage");
        IM.setText.overload("java.lang.String").implementation = function (text) {
            log("IM", "💬 msg.setText(\"" + text + "\")");
            this.setText(text);
        };
    });

    safeHook("InstantMessage: appendText", function () {
        var IM = Java.use("hw.imreader.InstantMessage");
        IM.appendText.overload("java.lang.String").implementation = function (text) {
            log("IM", "💬 msg.appendText(\"" + text + "\")");
            this.appendText(text);
        };
    });

    // -------------------------------------------------------------------
    // 9. IM DATABASE — hw.database.h.M (insertion mpk_events, cf. §9.5)
    // -------------------------------------------------------------------
    safeHook("IMDatabase: add event (M)", function () {
        var DB = Java.use("hw.database.h");
        DB.M.implementation = function (i) {
            log("IM-DB", "📥 add: " + i.toString());
            this.M(i);
        };
    });

    // -------------------------------------------------------------------
    // 10. LOCATION — c.c.c.e (callback GPS)
    // -------------------------------------------------------------------
    safeHook("Location: callback (F)", function () {
        var Loc = Java.use("c.c.c.e");
        Loc.F.implementation = function () {
            var args = [];
            for (var i = 0; i < arguments.length; i++) args.push(String(arguments[i]));
            log("GPS", "📍 " + args.join(" | "));
            return Loc.F.apply(this, arguments);
        };
    });

    log("INIT", "");
    log("INIT", "🚀 Hooks installed. Trafic redirected to mock C2.");
    log("INIT", "   Mock URL: " + MOCK_C2_URL);
    log("INIT", "");
});
