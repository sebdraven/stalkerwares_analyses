/*
 * iKeyMonitor — Unified Frida hook (v17.4 + v19.1)
 * ==================================================
 * Détecte automatiquement la version de l'APK et charge les classes correspondantes.
 *
 * Usage :
 *   # Auto-detect (essaie les deux packages)
 *   frida -U -f <package> -l ikeymonitor_hook_unified.js --no-pause
 *
 *   # Forcer une version
 *   frida -U -f com.sec.android.internet.im.service.im20210815 \
 *       -l ikeymonitor_hook_unified.js --no-pause
 *   frida -U -f com.android.internet.a20251031 \
 *       -l ikeymonitor_hook_unified.js --no-pause
 *
 * Hooks :
 *   - 3DES encrypt/decrypt (plaintext + key)
 *   - WebSocket messages entrants et sortants (XML)
 *   - Construction URL REST (action + body)
 *   - RTMP sign
 *
 * Research use only — ASTRA / LHS-LORIA.
 */

'use strict';

var VERSION = null;
var CLASSES = {};

// Mapping des classes par version
var CLASS_MAP = {
    'v17.4': {
        crypto: 'p128r.C3443z',
        constants: 'p070j.C2089e',
        wsManager: 'p027d.C1803f',
        wsOper: 'p027d.C1800c',
        wsListener: 'p027d.C1803f$b',
        portalCycle: 'p149u.C3565k',
        app: 'com.p025as.monitoringapp.logging.MyApplication'
    },
    'v19.1': {
        crypto: 'p185u.AbstractC4687z',
        constants: 'p111m.AbstractC3202e',
        // WS classes in v19.1 are MD5-hashed — these need to be identified per sample
        // Set to null and detect dynamically
        wsManager: null,
        wsOper: null,
        wsListener: null,
        portalCycle: null,
        app: 'com.a_Xf1Mc3Fh6Tb0Bv1Od8Jv.A_4d2056b271679e1c108f720cdec6fd4c'
    }
};

function log(tag, msg) {
    var ts = new Date().toISOString().slice(11, 23);
    console.log('[' + ts + '] [' + tag + '] ' + msg);
}

function detectVersion() {
    // Try to load version-specific classes
    try {
        Java.use('p128r.C3443z');
        return 'v17.4';
    } catch (e) {}

    try {
        Java.use('p185u.AbstractC4687z');
        return 'v19.1';
    } catch (e) {}

    return null;
}

function hookCrypto(className) {
    try {
        var cls = Java.use(className);

        // 3DES encrypt — m7234b (v17.4) / m11302b (v19.1)
        // Both have signature: String method(String plaintext, String key)
        var encryptMethods = cls.class.getDeclaredMethods().filter(function(m) {
            var params = m.getParameterTypes();
            return params.length === 2
                && params[0].getName() === 'java.lang.String'
                && params[1].getName() === 'java.lang.String'
                && m.getReturnType().getName() === 'java.lang.String';
        });

        encryptMethods.forEach(function(method) {
            var name = method.getName();
            cls[name].overload('java.lang.String', 'java.lang.String').implementation = function(plaintext, key) {
                var result = this[name](plaintext, key);
                log('3DES-ENC', 'plaintext="' + plaintext + '" key="' + key + '" → "' + result.substring(0, 40) + '..."');
                return result;
            };
            log('HOOK', 'Crypto encrypt: ' + className + '.' + name);
        });

    } catch (e) {
        log('ERR', 'Failed to hook crypto ' + className + ': ' + e);
    }
}

function hookWebSocket_v174() {
    try {
        // WS outgoing — WsManager.m3421q (sendMessage)
        var WsManager = Java.use('p027d.C1803f');
        var sendMethods = ['m3421q'];
        sendMethods.forEach(function(name) {
            try {
                WsManager[name].implementation = function(msg) {
                    log('WS-OUT', msg);
                    return this[name](msg);
                };
                log('HOOK', 'WS send: p027d.C1803f.' + name);
            } catch (e) {}
        });
    } catch (e) {
        log('ERR', 'Failed to hook WS manager: ' + e);
    }

    try {
        // WS incoming — WsManager$b.m3426h (onMessage)
        var WsListener = Java.use('p027d.C1803f$b');
        var recvMethods = ['m3426h'];
        recvMethods.forEach(function(name) {
            try {
                WsListener[name].implementation = function(msg) {
                    log('WS-IN', msg);
                    this[name](msg);
                };
                log('HOOK', 'WS recv: p027d.C1803f$b.' + name);
            } catch (e) {}
        });
    } catch (e) {
        log('ERR', 'Failed to hook WS listener: ' + e);
    }
}

function hookWebSocket_v191() {
    // v19.1 WS classes are obfuscated — try to find them by pattern
    // Strategy: hook OkHttp3 WebSocket directly (works for both versions)
    hookOkHttpWebSocket();
}

function hookOkHttpWebSocket() {
    // Generic OkHttp3 WebSocket hook — works regardless of version
    try {
        var WebSocketListener = Java.use('okhttp3.WebSocketListener');
        WebSocketListener.onMessage.overload('okhttp3.WebSocket', 'java.lang.String').implementation = function(ws, text) {
            log('WS-IN', text.length > 500 ? text.substring(0, 500) + '...' : text);
            this.onMessage(ws, text);
        };
        log('HOOK', 'OkHttp3 WebSocketListener.onMessage (text)');
    } catch (e) {
        log('WARN', 'OkHttp3 WebSocketListener hook failed: ' + e);
    }

    try {
        var RealWebSocket = Java.use('okhttp3.internal.ws.RealWebSocket');
        RealWebSocket.send.overload('java.lang.String').implementation = function(text) {
            log('WS-OUT', text.length > 500 ? text.substring(0, 500) + '...' : text);
            return this.send(text);
        };
        log('HOOK', 'OkHttp3 RealWebSocket.send (text)');
    } catch (e) {
        log('WARN', 'OkHttp3 RealWebSocket.send hook failed: ' + e);
    }
}

function hookHTTPRequests() {
    // Hook OkHttp3 pour capturer les requêtes REST
    try {
        var OkHttpClient = Java.use('okhttp3.OkHttpClient');
        var Call = Java.use('okhttp3.Call');
        var RealCall = Java.use('okhttp3.internal.connection.RealCall');

        RealCall.getOriginalRequest.implementation = function() {
            var req = this.getOriginalRequest();
            var url = req.url().toString();
            var method = req.method();

            if (url.indexOf('index.php') !== -1 || url.indexOf('m=api') !== -1) {
                log('HTTP', method + ' ' + url);

                var body = req.body();
                if (body !== null) {
                    try {
                        var buffer = Java.use('okio.Buffer').$new();
                        body.writeTo(buffer);
                        var bodyStr = buffer.readUtf8();
                        if (bodyStr.length > 0) {
                            log('HTTP-BODY', bodyStr.length > 500 ? bodyStr.substring(0, 500) + '...' : bodyStr);
                        }
                    } catch (e) {}
                }
            }
            return req;
        };
        log('HOOK', 'OkHttp3 RealCall.getOriginalRequest');
    } catch (e) {
        // Fallback : hook URL connection
        log('WARN', 'OkHttp3 RealCall hook failed, trying HttpURLConnection: ' + e);
        hookURLConnection();
    }
}

function hookURLConnection() {
    try {
        var URL = Java.use('java.net.URL');
        URL.openConnection.overload().implementation = function() {
            var conn = this.openConnection();
            var url = this.toString();
            if (url.indexOf('index.php') !== -1 || url.indexOf('m=api') !== -1) {
                log('HTTP', 'URL.openConnection: ' + url);
            }
            return conn;
        };
        log('HOOK', 'java.net.URL.openConnection');
    } catch (e) {
        log('ERR', 'URL hook failed: ' + e);
    }
}

function hookRTMP() {
    // Hook MD5 pour capturer la signature RTMP
    try {
        var MessageDigest = Java.use('java.security.MessageDigest');
        MessageDigest.digest.overload('[B').implementation = function(input) {
            var result = this.digest(input);
            var inputStr = '';
            for (var i = 0; i < input.length; i++) {
                inputStr += String.fromCharCode(input[i] & 0xFF);
            }
            if (inputStr.indexOf('/live/') !== -1) {
                log('RTMP-SIGN', 'input="' + inputStr + '"');
                var hexResult = '';
                for (var j = 0; j < result.length; j++) {
                    hexResult += ('0' + (result[j] & 0xFF).toString(16)).slice(-2);
                }
                log('RTMP-SIGN', 'md5=' + hexResult);
            }
            return result;
        };
        log('HOOK', 'MessageDigest.digest (RTMP sign detection)');
    } catch (e) {
        log('WARN', 'MessageDigest hook failed: ' + e);
    }
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

Java.perform(function() {
    log('INIT', '═══════════════════════════════════════════════');
    log('INIT', '  iKeyMonitor Unified Hook — ASTRA/LHS-LORIA');
    log('INIT', '═══════════════════════════════════════════════');

    VERSION = detectVersion();

    if (VERSION === null) {
        log('ERR', 'Could not detect iKeyMonitor version!');
        log('ERR', 'Neither p128r.C3443z (v17.4) nor p185u.AbstractC4687z (v19.1) found.');
        log('INFO', 'Falling back to generic OkHttp hooks...');

        hookOkHttpWebSocket();
        hookHTTPRequests();
        hookRTMP();
        return;
    }

    log('INIT', 'Detected version: ' + VERSION);
    var classMap = CLASS_MAP[VERSION];
    log('INIT', 'Crypto class: ' + classMap.crypto);
    log('INIT', 'App class: ' + classMap.app);

    // 3DES
    hookCrypto(classMap.crypto);

    // WebSocket
    if (VERSION === 'v17.4') {
        hookWebSocket_v174();
    } else {
        hookWebSocket_v191();
    }
    // Always hook OkHttp as fallback/complement
    hookOkHttpWebSocket();

    // HTTP REST
    hookHTTPRequests();

    // RTMP
    hookRTMP();

    log('INIT', 'All hooks installed (' + VERSION + ')');
    log('INIT', '═══════════════════════════════════════════════');
});
