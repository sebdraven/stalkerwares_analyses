/**
 * Mobile Tracker Free — FCM Command Injector (Frida)
 * 
 * Injecte des commandes FCM directement dans le service
 * MyFirebaseMTFMessagingService sans passer par Firebase.
 * 
 * Usage :
 *   frida -U -f phone.monitor2026 -l mtf_fcm_injector.js
 *   
 *   Puis dans la console Frida :
 *   > cmd("GetLocation----42")
 *   > cmd("TakePictureFront--1##0--42")
 *   > cmd("RecordAudio--30--1--42")
 *   > cmd("hideIcon----42")
 * 
 * Format des commandes : action--param1--param2--...--idLog
 * Le séparateur est "--" (double tiret).
 */

"use strict";

// ============================================================
// Injection core
// ============================================================

let serviceInstance = null;

function getServiceClass() {
    return Java.use("com.app.service.MyFirebaseMTFMessagingService");
}

/**
 * Envoie une commande FCM au stalkerware.
 * 
 * @param {string} actionStr - Commande complète (ex: "GetLocation----42")
 */
function cmd(actionStr) {
    Java.perform(function () {
        console.log("[*] Injecting FCM command: " + actionStr);

        // Construire un faux RemoteMessage avec le champ "action"
        const Bundle = Java.use("android.os.Bundle");
        const bundle = Bundle.$new();
        bundle.putString("action", actionStr);

        // On a besoin d'une instance du service.
        // Option 1 : hooker onMessageReceived pour capturer l'instance
        // Option 2 : créer une instance et appeler la méthode directement
        // Option 3 : appeler via le context de l'app

        const MyApp = Java.use("com.app.activity.MyApp");
        const ctx = MyApp.f1307l.value.getApplicationContext();

        // Créer un Intent pour démarrer le service avec les données FCM
        const Intent = Java.use("android.content.Intent");
        const serviceClass = Java.use("com.app.service.MyFirebaseMTFMessagingService").class;
        
        const intent = Intent.$new(ctx, serviceClass);
        intent.putExtra("action", actionStr);
        
        // Approche directe : instancier et appeler la méthode de parsing
        // Le service parse action.split("--"), on peut simuler ça
        
        // Méthode alternative plus fiable : hooker le service au démarrage
        // et injecter via la méthode mo1078c
        
        try {
            // Essayer d'appeler directement via réflexion
            _callServiceDirect(ctx, actionStr);
        } catch (e) {
            console.log("[-] Direct call failed: " + e);
            console.log("[*] Trying broadcast approach...");
            _callViaBroadcast(ctx, actionStr);
        }
    });
}

/**
 * Appel direct : crée un faux RemoteMessage et appelle mo1078c.
 */
function _callServiceDirect(ctx, actionStr) {
    Java.perform(function () {
        // Construire le RemoteMessage.Builder
        const RemoteMessageBuilder = Java.use("com.google.firebase.messaging.RemoteMessage$Builder");
        const builder = RemoteMessageBuilder.$new("fake@fcm.googleapis.com");
        builder.addData("action", actionStr);
        const remoteMessage = builder.build();

        // Obtenir l'instance du service via les services actifs
        const ActivityThread = Java.use("android.app.ActivityThread");
        const currentApp = ActivityThread.currentApplication();

        // Chercher l'instance du service dans les services actifs
        if (serviceInstance !== null) {
            console.log("[+] Using cached service instance");
            serviceInstance.mo1078c(remoteMessage);
            console.log("[+] Command injected successfully!");
            return;
        }

        // Si pas d'instance cachée, on hook pour la capturer au prochain appel
        // En attendant, on essaie via startService
        console.log("[*] No cached instance, starting service with intent...");
        
        const Intent = Java.use("android.content.Intent");
        const serviceClass = Java.use("com.app.service.MyFirebaseMTFMessagingService").class;
        const intent = Intent.$new(ctx, serviceClass);
        
        const Build = Java.use("android.os.Build");
        if (Build.VERSION.SDK_INT.value >= 26) {
            ctx.startForegroundService(intent);
        } else {
            ctx.startService(intent);
        }
        
        // Attendre un peu puis réessayer
        setTimeout(function() {
            if (serviceInstance !== null) {
                serviceInstance.mo1078c(remoteMessage);
                console.log("[+] Command injected after service start!");
            } else {
                console.log("[-] Service instance not captured. Use hook_service() first.");
            }
        }, 1000);
    });
}

/**
 * Méthode broadcast : envoie un broadcast custom que le service pourrait capter.
 * Fallback si l'appel direct échoue.
 */
function _callViaBroadcast(ctx, actionStr) {
    Java.perform(function () {
        console.log("[*] Broadcasting FCM action: " + actionStr);
        const Intent = Java.use("android.content.Intent");
        const intent = Intent.$new("com.google.android.c2dm.intent.RECEIVE");
        intent.putExtra("action", actionStr);
        intent.setPackage("phone.monitor2026");
        ctx.sendBroadcast(intent);
        console.log("[+] Broadcast sent");
    });
}


// ============================================================
// Hook pour capturer l'instance du service
// ============================================================

function hook_service() {
    Java.perform(function () {
        const ServiceClass = getServiceClass();
        
        // Hook mo1078c (onMessageReceived)
        ServiceClass.mo1078c.implementation = function (remoteMessage) {
            serviceInstance = this;
            
            const data = remoteMessage.m4449a();  // getData()
            let action = "?";
            try {
                action = Java.cast(data, Java.use("java.util.Map")).get("action");
            } catch (e) {}
            
            console.log("[FCM RECV] action=" + action);
            
            // Appeler l'implémentation originale
            this.mo1078c(remoteMessage);
        };
        
        console.log("[+] Service hooked — instance will be captured on next FCM message");
        console.log("[+] You can also force capture with: force_capture()");
    });
}

/**
 * Force la capture de l'instance du service en le démarrant.
 */
function force_capture() {
    Java.perform(function () {
        const MyApp = Java.use("com.app.activity.MyApp");
        const ctx = MyApp.f1307l.value.getApplicationContext();
        
        // Hook onCreate du service pour capturer this
        const ServiceClass = getServiceClass();
        ServiceClass.onCreate.implementation = function () {
            serviceInstance = this;
            console.log("[+] Service instance captured via onCreate!");
            this.onCreate();
        };
        
        // Démarrer le service
        const Intent = Java.use("android.content.Intent");
        const intent = Intent.$new(ctx, ServiceClass.class);
        try {
            ctx.startForegroundService(intent);
        } catch (e) {
            ctx.startService(intent);
        }
    });
}


// ============================================================
// Commandes prédéfinies (raccourcis)
// ============================================================

/**
 * Raccourcis pour les commandes les plus utiles.
 * Le dernier paramètre est toujours l'idLog.
 */

function getLocation(idLog) {
    cmd("GetLocation----" + (idLog || 1));
}

function takePictureFront(idLog) {
    // 1 = front camera, 0 = no flash
    cmd("TakePictureFront--1##0--" + (idLog || 2));
}

function takePictureRear(idLog) {
    // 2 = rear camera, 1 = flash on
    cmd("TakePictureFront--2##1--" + (idLog || 3));
}

function recordAudio(durationSec, idLog) {
    // type 1 = standard, durée en secondes
    cmd("RecordAudio--" + (durationSec || 30) + "--1--" + (idLog || 4));
}

function screenshot(idLog) {
    cmd("screenShot----" + (idLog || 5));
}

function screenshotMediaProjection(idLog) {
    cmd("takeScreenShot----" + (idLog || 6));
}

function hideIcon(idLog) {
    cmd("hideIcon----" + (idLog || 7));
}

function showIcon(idLog) {
    cmd("showIcon----" + (idLog || 8));
}

function lockPhone(code, idLog) {
    cmd("LockPhone--" + (code || "1234") + "----" + (idLog || 9));
}

function unlockPhone(idLog) {
    cmd("UnLockPhone----" + (idLog || 10));
}

function vibrate(duration, idLog) {
    cmd("Vibrate--" + (duration || 3000) + "--Vibrate--" + (idLog || 11));
}

function ring(duration, idLog) {
    cmd("Ring--" + (duration || 5000) + "--Ring--" + (idLog || 12));
}

function textToSpeech(text, idLog) {
    cmd("TextSpeaker--" + text + "--fr--" + (idLog || 13));
}

function sendSMS(number, message, idLog) {
    cmd("sendSMS--" + number + "--" + message + "--" + (idLog || 14));
}

function startLive(idLog) {
    cmd("startLive--1----" + (idLog || 15));
}

function stopLive(idLog) {
    cmd("startLive--0----" + (idLog || 16));
}

function startFileExplorer(idLog) {
    cmd("startFileExplorer----" + (idLog || 17));
}

function wipeData(idLog) {
    // ⚠️ DANGER — efface le téléphone !
    console.log("[!!!] WARNING: wipeData will ERASE the device!");
    cmd("wipeData----" + (idLog || 99));
}

function restartPhone(idLog) {
    // ⚠️ Redémarre le téléphone (root)
    cmd("restartPhone----" + (idLog || 98));
}

function enableWifi(idLog) {
    cmd("activateWIFI----" + (idLog || 20));
}

function disableWifi(idLog) {
    cmd("disabledWIFI----" + (idLog || 21));
}

function getIMRoot(app, idLog) {
    // app : getListFacebook, getListWhatsApp, getListTelegram, etc.
    cmd(app + "----" + (idLog || 30));
}

function trackToggle(feature, onOff) {
    // feature : trackSMS, trackCalls, trackLoc, etc.
    // onOff : 1 = enable, 0 = disable
    cmd(feature + "--" + onOff);
}

function dashboardUpdate() {
    cmd("dashboardUpdate");
}

function settingsCheck() {
    cmd("settingsCheck");
}

function getAccessibility() {
    cmd("getAccessibility");
}

function getNotifications() {
    cmd("getNotifications");
}


// ============================================================
// Hook réseau — Voir tous les POST Retrofit en temps réel
// ============================================================

function hook_network() {
    Java.perform(function () {
        const kl = Java.use("p000.AbstractC0410kl");
        
        // Hook m3135s — POST form-data
        kl.m3135s.implementation = function (endpoint, params) {
            const paramsStr = Java.cast(params, Java.use("java.util.HashMap")).toString();
            console.log("[NET POST] " + endpoint);
            console.log("  params: " + paramsStr.substring(0, 300));
            const result = this.m3135s(endpoint, params);
            console.log("  result: " + result);
            return result;
        };
        
        // Hook m3136t — POST multipart + file
        kl.m3136t.implementation = function (endpoint, params, file) {
            const paramsStr = Java.cast(params, Java.use("java.util.HashMap")).toString();
            console.log("[NET UPLOAD] " + endpoint);
            console.log("  params: " + paramsStr.substring(0, 200));
            console.log("  file: " + file);
            const result = this.m3136t(endpoint, params, file);
            console.log("  result: " + result);
            return result;
        };
        
        // Hook m3129l — POST → JSON response
        kl.m3129l.implementation = function (endpoint, params) {
            console.log("[NET JSON] " + endpoint);
            const result = this.m3129l(endpoint, params);
            console.log("  response: " + result);
            return result;
        };
        
        console.log("[+] Network hooks active — all Retrofit calls will be logged");
    });
}


// ============================================================
// Hook SharedPreferences — Voir toutes les configs
// ============================================================

function dump_config() {
    Java.perform(function () {
        const MyApp = Java.use("com.app.activity.MyApp");
        const ctx = MyApp.f1307l.value.getApplicationContext();
        const prefs = ctx.getSharedPreferences("user", 0);
        const all = prefs.getAll();
        const map = Java.cast(all, Java.use("java.util.Map"));
        const entries = map.entrySet().iterator();
        
        console.log("\n=== SharedPreferences 'user' ===");
        while (entries.hasNext()) {
            const entry = Java.cast(entries.next(), Java.use("java.util.Map$Entry"));
            const key = entry.getKey();
            const val = entry.getValue();
            if (val !== null) {
                const valStr = val.toString();
                if (valStr.length > 100) {
                    console.log("  " + key + " = " + valStr.substring(0, 100) + "...");
                } else {
                    console.log("  " + key + " = " + valStr);
                }
            }
        }
        console.log("================================\n");
    });
}


// ============================================================
// Auto-init
// ============================================================

Java.perform(function () {
    console.log("╔══════════════════════════════════════════╗");
    console.log("║  MTF FCM Command Injector — Frida        ║");
    console.log("╠══════════════════════════════════════════╣");
    console.log("║  cmd(\"action--p1--p2--idLog\")             ║");
    console.log("║                                          ║");
    console.log("║  Shortcuts:                              ║");
    console.log("║    getLocation()                         ║");
    console.log("║    takePictureFront() / takePictureRear() ║");
    console.log("║    recordAudio(30)                       ║");
    console.log("║    screenshot()                          ║");
    console.log("║    hideIcon() / showIcon()               ║");
    console.log("║    lockPhone(\"1234\") / unlockPhone()     ║");
    console.log("║    vibrate() / ring()                    ║");
    console.log("║    textToSpeech(\"hello\")                 ║");
    console.log("║    startLive() / startFileExplorer()     ║");
    console.log("║                                          ║");
    console.log("║  Utilities:                              ║");
    console.log("║    hook_service()  — capture FCM instance ║");
    console.log("║    hook_network()  — log all Retrofit     ║");
    console.log("║    dump_config()   — dump SharedPrefs     ║");
    console.log("║    force_capture() — force service start  ║");
    console.log("╚══════════════════════════════════════════╝");
    
    // Auto-hook le service
    hook_service();
});
