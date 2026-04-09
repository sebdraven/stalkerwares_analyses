/*
 * Hoverwatch C2 Redirect — Frida Hook Script
 * ============================================
 * Redirige tout le trafic C2 de Hoverwatch vers le mock server.
 * Loggue les données interceptées (credentials, PIN, events, crypto).
 *
 * Noms de classes/méthodes = noms ORIGINAUX du DEX (pas les noms JADX).
 * Mapping: voir hoverwatch_analysis.md section 14.
 *
 * Usage:
 *   frida -U -f com.android.core.mntan -l hoverwatch_hook.js --no-pause
 *   # ou si déjà lancé:
 *   frida -U com.android.core.mntan -l hoverwatch_hook.js
 *
 * Config: modifier MOCK_C2_URL ci-dessous avec l'IP du mock via VPN Corellium.
 */

// ===========================================================================
// CONFIG — Modifier ici
// ===========================================================================

const MOCK_C2_URL = "https://10.11.1.1:8443/";  // ← IP de ta machine via VPN Corellium
const VERBOSE = true;    // logs détaillés
const LOG_CRYPTO = true; // logger les déchiffrements DES

// ===========================================================================
// Helpers
// ===========================================================================

function ts() {
    return new Date().toISOString().substring(11, 23);
}

function log(tag, msg) {
    console.log(`[${ts()}] [${tag}] ${msg}`);
}

function logData(tag, key, value) {
    console.log(`[${ts()}] [${tag}] ${key} = "${value}"`);
}

// ===========================================================================
// Hooks
// ===========================================================================

Java.perform(function () {
    log("INIT", "🎯 Hoverwatch C2 hook loaded");
    log("INIT", `   Mock C2: ${MOCK_C2_URL}`);
    log("INIT", `   Package: com.android.core.mntan`);
    log("INIT", "   Hooking...");

    // -----------------------------------------------------------------------
    // 1. DOMAIN REDIRECT — hw.utils.z (C0888z / Settings)
    //    x() → retourne le domaine C2 actif (premier de la liste)
    //    y() → retourne la liste complète des domaines
    // -----------------------------------------------------------------------

    var Settings = Java.use("hw.utils.z");

    // x() — domaine courant
    Settings.x.implementation = function () {
        var original = this.x();
        log("C2-DOMAIN", `Original domain: "${original}" → Redirected to: "${MOCK_C2_URL}"`);
        return MOCK_C2_URL;
    };

    // y() — liste de tous les domaines (séparés par ;)
    Settings.y.implementation = function () {
        var original = this.y();
        log("C2-DOMAIN", `Original domains list: "${original}"`);
        return MOCK_C2_URL;
    };

    // u0(String) — quand l'app essaie de changer les domaines
    Settings.u0.implementation = function (newDomains) {
        log("C2-DOMAIN", `⚠️ App tried to change domains to: "${newDomains}" → Blocked, keeping mock`);
        return false; // on bloque le changement
    };

    // J(String) — rotation de domaines
    Settings.J.implementation = function (domain) {
        log("C2-DOMAIN", `Domain rotation requested: "${domain}" → Returning mock`);
        return MOCK_C2_URL;
    };

    // -----------------------------------------------------------------------
    // 2. CREDENTIALS INTERCEPT — log tout ce qui passe
    // -----------------------------------------------------------------------

    // s() — ActivationID (auth_key)
    Settings.s.implementation = function () {
        var val = this.s();
        logData("AUTH", "ActivationID", val);
        return val;
    };

    // u() — Password/PIN
    Settings.u.implementation = function () {
        var val = this.u();
        logData("AUTH", "PIN/Password", val);
        return val;
    };

    // q0(String) — quand le serveur envoie un nouveau auth_key
    Settings.q0.implementation = function (newKey) {
        log("AUTH", `🔑 New auth_key received: "${newKey}"`);
        this.q0(newKey);
    };

    // r0(String) — quand le PIN est changé
    Settings.r0.implementation = function (newPin) {
        log("AUTH", `🔐 PIN changed to: "${newPin}"`);
        this.r0(newPin);
    };

    // -----------------------------------------------------------------------
    // 3. SETTINGS INTERCEPT — log la config distante
    // -----------------------------------------------------------------------

    // V0(String) — quand le serveur envoie valid_through
    Settings.V0.implementation = function (validThrough) {
        log("LICENSE", `Valid through: "${validThrough}"`);
        return this.V0(validThrough);
    };

    // T0(String) — quand le serveur envoie le type d'abonnement
    Settings.T0.implementation = function (sub) {
        log("LICENSE", `Subscription: "${sub}"`);
        return this.T0(sub);
    };

    // v0(boolean) — enable/disable monitoring
    Settings.v0.implementation = function (enable) {
        log("CONTROL", `EnableMonitor → ${enable}`);
        this.v0(enable);
    };

    // w0(boolean) — hide/show icon
    Settings.w0.implementation = function (hide) {
        log("STEALTH", `HideIcon → ${hide}`);
        this.w0(hide);
    };

    log("INIT", "   ✅ Settings hooks installed");

    // -----------------------------------------------------------------------
    // 4. HTTP CLIENT — hw.utils.z has the domain, but e.a.a builds the URL
    //    Hook the static field f5119a (current domain) via method access
    // -----------------------------------------------------------------------

    var HttpClient = Java.use("e.a.a");

    // q(String, String, int) — registration (username, password, user_type)
    HttpClient.q.overload(
        "java.lang.String", "java.lang.String", "int"
    ).implementation = function (username, password, userType) {
        log("REGISTER", "═══════════════════════════════════════");
        log("REGISTER", `📱 REGISTRATION`);
        log("REGISTER", `   Username: "${username}"`);
        log("REGISTER", `   Password: "${password}"`);
        log("REGISTER", `   UserType: ${userType}`);
        log("REGISTER", "═══════════════════════════════════════");
        return this.q(username, password, userType);
    };

    // B(JSONObject) — activation
    HttpClient.B.implementation = function (json) {
        log("ACTIVATE", `📋 Activation payload: ${json}`);
        return this.B(json);
    };

    // t(String[]) — sync/send events (main exfiltration trigger)
    HttpClient.t.implementation = function (headers) {
        if (headers !== null) {
            log("SYNC", `📡 Sync triggered with ${headers.length} extra headers`);
            for (var i = 0; i < headers.length; i += 2) {
                if (i + 1 < headers.length) {
                    log("SYNC", `   ${headers[i]}: ${headers[i + 1]}`);
                }
            }
        } else {
            log("SYNC", "📡 Sync triggered (no extra headers)");
        }
        return this.t(headers);
    };

    // r(String, d) — async event send
    HttpClient.r.implementation = function (eventData, callback) {
        log("EVENT", `📤 Client event: "${eventData}"`);
        this.r(eventData, callback);
    };

    log("INIT", "   ✅ HTTP client hooks installed");

    // -----------------------------------------------------------------------
    // 5. CRYPTO — hw.utils.h (C0870h / CryptoHelper)
    //    Log all DES decrypt operations
    // -----------------------------------------------------------------------

    if (LOG_CRYPTO) {
        var Crypto = Java.use("hw.utils.h");

        // c(String) — decrypt with default key "val"
        Crypto.c.implementation = function (encrypted) {
            var decrypted = this.c(encrypted);
            log("CRYPTO", `🔓 DES decrypt: "${encrypted.substring(0, 30)}..." → "${decrypted}"`);
            return decrypted;
        };

        // b(String, String, boolean) — decrypt/encrypt with custom key
        Crypto.b.implementation = function (str, key, encrypt) {
            var result = this.b(str, key, encrypt);
            var op = encrypt ? "ENCRYPT" : "DECRYPT";
            log("CRYPTO", `🔐 DES ${op} (key="${key}"): "${str.substring(0, 20)}..." → "${result.substring(0, 40)}..."`);
            return result;
        };

        log("INIT", "   ✅ Crypto hooks installed");
    }

    // -----------------------------------------------------------------------
    // 6. MODULE CONFIG — hw.utils.y (C0887y / ModuleConfig)
    //    Log when server pushes new settings
    // -----------------------------------------------------------------------

    var ModuleConfig = Java.use("hw.utils.y");

    // n(JSONObject) — accept new settings from server
    ModuleConfig.n.implementation = function (json) {
        log("SETTINGS", "═══════════════════════════════════════");
        log("SETTINGS", "⚙️ NEW SETTINGS FROM C2:");
        log("SETTINGS", `${json}`);
        log("SETTINGS", "═══════════════════════════════════════");
        this.n(json);
    };

    // c0(int, boolean) — enable/disable a specific module
    ModuleConfig.c0.implementation = function (moduleId, enabled) {
        var names = {
            302: "Screenshots", 304: "IM Reader", 305: "Browser",
            312: "Call Recording", 313: "SMS", 314: "Location",
            319: "Front Camera"
        };
        var name = names[moduleId] || `Module_${moduleId}`;
        log("MODULE", `${enabled ? "✅" : "❌"} ${name} (${moduleId}) → ${enabled}`);
        this.c0(moduleId, enabled);
    };

    // h0(int, boolean) — enable/disable screenshot on event
    ModuleConfig.h0.implementation = function (moduleId, enabled) {
        log("MODULE", `📸 Screenshot-on-event for module ${moduleId} → ${enabled}`);
        this.h0(moduleId, enabled);
    };

    // X(int, boolean) — enable/disable audio recording on event
    ModuleConfig.X.implementation = function (moduleId, enabled) {
        log("MODULE", `🎙️ Audio-on-event for module ${moduleId} → ${enabled}`);
        this.X(moduleId, enabled);
    };

    log("INIT", "   ✅ Module config hooks installed");

    // -----------------------------------------------------------------------
    // 7. INTERNAL LOGGER — hw.utils.l (C0874l / Logger)
    //    Intercept all Hoverwatch internal logs
    // -----------------------------------------------------------------------

    if (VERBOSE) {
        var Logger = Java.use("hw.utils.l");

        // s(String, String) — info log
        Logger.s.overload("java.lang.String", "java.lang.String").implementation = function (tag, msg) {
            log(`HW-${tag}`, msg);
            this.s(tag, msg);
        };

        // t(String, String) — debug log
        Logger.t.overload("java.lang.String", "java.lang.String").implementation = function (tag, msg) {
            log(`HW-${tag}`, `[DBG] ${msg}`);
            this.t(tag, msg);
        };

        // u(String, String, Exception) — error log
        Logger.u.implementation = function (tag, msg, ex) {
            log(`HW-${tag}`, `[ERR] ${msg} → ${ex}`);
            this.u(tag, msg, ex);
        };

        log("INIT", "   ✅ Internal logger hooks installed (VERBOSE)");
    }

    // -----------------------------------------------------------------------
    // 8. RECORDING — hw.recorder.ServiceRecording
    //    Log when audio recording starts/stops
    // -----------------------------------------------------------------------

    var Recording = Java.use("hw.recorder.ServiceRecording");

    Recording.o.implementation = function (type, bundle) {
        log("RECORDER", `🎙️ RECORDING START — type: ${type}`);
        if (bundle !== null) {
            log("RECORDER", `   Bundle: ${bundle}`);
        }
        this.o(type, bundle);
    };

    Recording.p.implementation = function (type) {
        log("RECORDER", `⏹️ RECORDING STOP — type: ${type}`);
        this.p(type);
    };

    log("INIT", "   ✅ Recording hooks installed");

    // -----------------------------------------------------------------------
    // 9. ACCESSIBILITY / IM READER — log intercepted messages
    // -----------------------------------------------------------------------

    var InstantMessage = Java.use("hw.imreader.InstantMessage");

    InstantMessage.setText.overload("java.lang.String").implementation = function (text) {
        log("IM-INTERCEPT", `💬 Message text set: "${text}"`);
        this.setText(text);
    };

    InstantMessage.appendText.overload("java.lang.String").implementation = function (text) {
        log("IM-INTERCEPT", `💬 Message text appended: "${text}"`);
        this.appendText(text);
    };

    log("INIT", "   ✅ IM intercept hooks installed");

    // -----------------------------------------------------------------------
    // 10. LOCATION — log GPS data
    // -----------------------------------------------------------------------

    try {
        var Location = Java.use("c.c.c.e");

        Location.F.implementation = function (cat, lat, lon, acc, cellid, ssid, bssid, speed) {
            log("GPS", `📍 lat=${lat} lon=${lon} acc=${acc}m spd=${speed}km/h ssid="${ssid}" bssid="${bssid}" cell="${cellid}"`);
            return this.F(cat, lat, lon, acc, cellid, ssid, bssid, speed);
        };

        log("INIT", "   ✅ Location hooks installed");
    } catch (e) {
        log("INIT", `   ⚠️ Location hooks skipped: ${e}`);
    }

    // -----------------------------------------------------------------------
    // 11. KILL SWITCH — intercept auto-uninstall
    // -----------------------------------------------------------------------

    try {
        var Uninstaller = Java.use("hw.core.c");

        Uninstaller.a.implementation = function () {
            log("KILLSWITCH", "☠️ ═══════════════════════════════════");
            log("KILLSWITCH", "☠️ KILL SWITCH TRIGGERED — BLOCKING!");
            log("KILLSWITCH", "☠️ ═══════════════════════════════════");
            // NE PAS appeler this.a() — on bloque la désinstallation
        };

        log("INIT", "   ✅ Kill switch blocker installed");
    } catch (e) {
        log("INIT", `   ⚠️ Kill switch hook skipped: ${e}`);
    }

    // -----------------------------------------------------------------------
    // DONE
    // -----------------------------------------------------------------------

    log("INIT", "");
    log("INIT", "🚀 All hooks installed. Hoverwatch traffic redirected to mock C2.");
    log("INIT", `   Mock URL: ${MOCK_C2_URL}`);
    log("INIT", "   Waiting for stalkerware activity...");
    log("INIT", "");
});
