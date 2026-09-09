/*
 * iKeyMonitor — Wizard / Configuration Check bypass (v19.1)
 * =========================================================
 * Force tous les checks de config (u.x.*) à true, plus le check accessibility
 * (h1.w.b) et le flag réseau (l1.d.f6481b), pour passer le wizard sans devoir
 * cliquer les toggles dans la GUI Corellium (clics souvent inopérants).
 *
 * Les permissions dangerous + accessibility + usage sont déjà accordées via ADB ;
 * ce hook couvre les checks applicatifs custom que l'APK fait en plus (et qui
 * lisent l'état d'une manière que le grant ADB ne satisfait pas toujours,
 * ex. resolveServiceClassByReflection pour l'accessibility, ou MediaProjection).
 *
 * Usage (Corellium, Frida réseau) :
 *   frida -H 127.0.0.1:27042 -f com.android.internet.a20251031 \
 *       -l ikeymonitor_wizard_bypass.js --no-pause
 *
 * Research use only.
 */

'use strict';

function log(tag, msg) {
    var ts = new Date().toISOString().slice(11, 23);
    console.log('[' + ts + '] [' + tag + '] ' + msg);
}

Java.perform(function () {
    log('INIT', 'iKeyMonitor wizard-bypass hooks loading…');

    // -----------------------------------------------------------------------
    // 1. u.x.* — tous les checks de config du wizard (boolean <m>(Context))
    //    a/e/f/g/h : accessibility, usage access, overlay, screenshot, etc.
    // -----------------------------------------------------------------------
    try {
        var ux = Java.use('u.x');
        var methods = ux.class.getDeclaredMethods();
        methods.forEach(function (m) {
            var name = m.getName();
            if (m.getReturnType().getName() !== 'boolean') return;
            var params = m.getParameterTypes();
            // signatures: boolean m()  OU  boolean m(Context)
            try {
                if (params.length === 0) {
                    ux[name].overload().implementation = function () {
                        log('WIZARD', 'u.x.' + name + '() -> forced true');
                        return true;
                    };
                } else if (params.length === 1 && params[0].getName() === 'android.content.Context') {
                    ux[name].overload('android.content.Context').implementation = function (ctx) {
                        log('WIZARD', 'u.x.' + name + '(Context) -> forced true');
                        return true;
                    };
                }
            } catch (e) {
                log('WARN', 'u.x.' + name + ' hook failed: ' + e);
            }
        });
        log('HOOK', 'u.x.* boolean checks forced true');
    } catch (e) {
        log('ERR', 'u.x not found: ' + e);
    }

    // -----------------------------------------------------------------------
    // 2. h1.w.* — check accessibility bas niveau (lit enabled_accessibility_services)
    // -----------------------------------------------------------------------
    try {
        var w = Java.use('h1.w');
        var wm = w.class.getDeclaredMethods();
        wm.forEach(function (m) {
            var name = m.getName();
            if (m.getReturnType().getName() !== 'boolean') return;
            var params = m.getParameterTypes();
            try {
                if (params.length === 1 && params[0].getName() === 'android.content.Context') {
                    w[name].overload('android.content.Context').implementation = function (ctx) {
                        log('WIZARD', 'h1.w.' + name + '(Context) -> forced true');
                        return true;
                    };
                } else if (params.length === 2
                        && params[0].getName() === 'android.content.Context'
                        && params[1].getName() === 'java.lang.String') {
                    w[name].overload('android.content.Context', 'java.lang.String').implementation = function (ctx, s) {
                        log('WIZARD', 'h1.w.' + name + '(Context,"' + s + '") -> forced true');
                        return true;
                    };
                }
            } catch (e) {
                log('WARN', 'h1.w.' + name + ' hook failed: ' + e);
            }
        });
        log('HOOK', 'h1.w.* accessibility checks forced true');
    } catch (e) {
        log('ERR', 'h1.w not found: ' + e);
    }

    // -----------------------------------------------------------------------
    // 3. l1.d.f6481b — flag réseau "internet dispo" (au cas où)
    //    forcé true en continu (les receivers de connectivité le remettent)
    // -----------------------------------------------------------------------
    try {
        var d = Java.use('l1.d');
        setInterval(function () {
            Java.perform(function () {
                try { d.f6481b.value = true; } catch (e) {}
            });
        }, 1000);
        log('HOOK', 'l1.d.f6481b forced true (1s loop)');
    } catch (e) {
        log('WARN', 'l1.d.f6481b not hookable: ' + e);
    }

    log('INIT', 'wizard-bypass installed');
});
