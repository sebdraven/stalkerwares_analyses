/*
 * iKeyMonitor v19.1 — WS trace / unlock
 * =====================================
 * j.b() est déjà false, donc le verrou n'est pas là. On trace le vrai chemin
 * du WS check pour voir où ça casse :
 *   - A_91ba….onReceive  : le broadcast ACTION_.CHECK._WEBSOCKET arrive-t-il ?
 *   - A_91ba….b(Context) : le handler get_websocket_address est-il atteint ?
 *   - x.u.a()            : le parseur de la réponse (LoginStatus/websocket_address)
 *   - les conditions e0.g.B(), j.c(), j.b()
 *
 * On force aussi A_91ba….b(context) à s'exécuter manuellement au bout de 5s
 * (au cas où le receiver dynamique ne serait jamais enregistré).
 *
 * Usage :
 *   uv run frida -H 127.0.0.1:27043 -n "Internet Service" -l ikeymonitor_ws_unlock.js
 */

'use strict';

var RECV = 'com.a_Xf1Mc3Fh6Tb0Bv1Od8Jv.A_91ba67c73d4a0a77607b808863fd40d9';

function log(t, m) {
    var ts = new Date().toISOString().slice(11, 23);
    console.log('[' + ts + '] [' + t + '] ' + m);
}

Java.perform(function () {
    log('INIT', 'WS trace loading…');

    // 1. Tracer le receiver onReceive
    try {
        var R = Java.use(RECV);
        R.onReceive.implementation = function (ctx, intent) {
            var act = intent ? intent.getAction() : '(null)';
            log('RECV', 'onReceive action=' + act);
            return this.onReceive(ctx, intent);
        };
        log('HOOK', 'A_91ba….onReceive');
    } catch (e) { log('ERR', 'onReceive hook: ' + e); }

    // 2. Tracer le handler b(Context) (get_websocket_address)
    try {
        var R2 = Java.use(RECV);
        R2.b.overload('android.content.Context').implementation = function (ctx) {
            log('WSCHK', 'A_91ba….b(Context) CALLED — get_websocket_address handler');
            return this.b(ctx);
        };
        log('HOOK', 'A_91ba….b(Context)');
    } catch (e) { log('ERR', 'b hook: ' + e); }

    // 3. Tracer les conditions du onReceive
    try {
        var eg = Java.use('e0.g');
        eg.B.implementation = function () {
            var v = this.B();
            log('COND', 'e0.g.B() (KEY_SessionValue) = "' + v + '"');
            return v;
        };
    } catch (e) {}
    try {
        var lj = Java.use('l1.j');
        lj.c.implementation = function () {
            var v = this.c();
            log('COND', 'l1.j.c() (license) = "' + v + '"');
            return v;
        };
        lj.b.implementation = function () {
            var v = this.b();
            log('COND', 'l1.j.b() = ' + v);
            return v;
        };
    } catch (e) {}

    // 4. Tracer le parseur de réponse x.u.a()
    try {
        var xu = Java.use('x.u');
        xu.a.overload('android.content.Context', 'java.lang.String', 'java.lang.String')
          .implementation = function (ctx, str, tag) {
            log('PARSE', 'x.u.a() tag=' + tag + ' resp=' + (str ? str.substring(0, 200) : 'null'));
            return this.a(ctx, str, tag);
        };
        log('HOOK', 'x.u.a()');
    } catch (e) { log('ERR', 'x.u.a hook: ' + e); }

    // 5. Forcer l'appel du handler manuellement après 5s
    setTimeout(function () {
        Java.perform(function () {
            try {
                var ctx = Java.use('android.app.ActivityThread')
                    .currentApplication().getApplicationContext();
                var inst = Java.use(RECV).$new();
                log('FORCE', 'Appel manuel de A_91ba….b(context)…');
                inst.b(ctx);
                log('FORCE', 'Appel manuel terminé');
            } catch (e) {
                log('FORCE-ERR', e);
            }
        });
    }, 5000);

    log('INIT', 'WS trace installed');
});
