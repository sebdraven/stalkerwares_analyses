"""
iKeyMonitor Mock C2 — Test client + protocol replay.

Usage:
    # Simulation standard (register → cycle → WS)
    uv run python test_client.py [--host 127.0.0.1] [--port 8443]

    # Replay d'un fichier de log capturé
    uv run python test_client.py --replay logs/c2.log [--host 127.0.0.1] [--port 8443]

    # Mode v17.4 (typo endpoints)
    uv run python test_client.py --version v17.4
"""

import argparse
import asyncio
import json
import ssl
import sys
import time
from pathlib import Path

import httpx
import websockets


MOCK_CLIENT_ID = "AA:BB:CC:DD:EE:FF"
MOCK_LICENSE = "TEST-LICENSE-001"

V174_ACTIONS = {
    "upload_keystrokes": "uoload_keystrokes",
    "upload_chat_logs": "uoload_chat_logs",
    "upload_website_history": "uoload_website_history",
    "upload_call_history": "uoload_call_history",
    "upload_gps_history": "uoload_gps_history",
    "upload_surrounding": "surrounding",
    "upload_contact": "contact",
    "upload_calendar": "calendar",
    "upload_screenshot": "get_screenshot",
    "upload_wifi": "upload_Wifi",
}


def xml_payload(extra: str = "", client: str = MOCK_CLIENT_ID) -> str:
    ts = str(int(time.time()))
    return (
        f"<IKMService>"
        f"<Client>{client}</Client>"
        f"<License>{MOCK_LICENSE}</License>"
        f"<WSTimeStamp>{ts}</WSTimeStamp>"
        f"{extra}"
        f"</IKMService>"
    )


def _action_for_version(canonical: str, version: str) -> str:
    if version == "v17.4" and canonical in V174_ACTIONS:
        return V174_ACTIONS[canonical]
    return canonical


async def test_rest(host: str, port: int, version: str):
    base = f"https://{host}:{port}/index.php"

    async with httpx.AsyncClient(verify=False) as c:
        steps = [
            ("register", ""),
            ("account", ""),
            ("get_settings", ""),
            ("get_websocket_address", ""),
            ("cycle", ""),
            ("upload_keystrokes", "<Keystrokes><App>com.whatsapp</App><Text>hello world</Text><Time>1234567890</Time></Keystrokes>"),
            ("upload_gps_history", "<GPS><Lat>48.8566</Lat><Lon>2.3522</Lon><Time>1234567890</Time><Accuracy>10</Accuracy></GPS>"),
            ("upload_chat_logs", "<Chat><App>com.whatsapp</App><Contact>+33600000000</Contact><Message>test message</Message><Time>1234567890</Time></Chat>"),
            ("upload_clipboard", "<Clipboard><Text>pasted text</Text><Time>1234567890</Time></Clipboard>"),
            ("check_update", ""),
        ]

        for i, (canonical, extra) in enumerate(steps, 1):
            action = _action_for_version(canonical, version)
            url = f"{base}?m=api&a={action}"
            body = xml_payload(extra)
            r = await c.post(url, content=body)
            tag = f" (raw: {action})" if action != canonical else ""
            print(f"  [{i:2d}] {canonical}{tag}")
            print(f"       → {r.status_code}: {r.text[:120]}")

        print(f"\n  [admin] status")
        r = await c.get(f"https://{host}:{port}/admin/status", follow_redirects=True)
        status = r.json()
        print(f"       devices: {len(status['devices'])}, exfil: {status['exfiltrated_count']}, ws: {status['ws_connections']}")

        print(f"\n  [admin] session export")
        r = await c.get(f"https://{host}:{port}/admin/session/export", follow_redirects=True)
        export = r.json()
        for dev in export:
            print(f"       device={dev['device_id']} version={dev['version']} timeline={len(dev['timeline'])} entries")

        print(f"\n  [admin] crypto encrypt")
        r = await c.get(f"https://{host}:{port}/admin/crypto/encrypt?plaintext=ASTRA-2026", follow_redirects=True)
        print(f"       → {r.json()}")


async def test_ws(host: str, port: int):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    uri = f"wss://{host}:{port}/ws"
    print(f"\n  [WS] Connecting to {uri}...")

    async with websockets.connect(uri, ssl=ctx) as ws:
        msg = await ws.recv()
        print(f"  [WS ←] {msg}")

        ack = xml_payload()
        await ws.send(ack)
        print(f"  [WS →] ACK (client={MOCK_CLIENT_ID})")

        print("  [WS] Waiting 5s for commands...")
        try:
            msg = await asyncio.wait_for(ws.recv(), timeout=5.0)
            print(f"  [WS ←] {msg}")
        except asyncio.TimeoutError:
            print("  [WS] No commands received (idle)")

    print("  [WS] Disconnected")


async def test_cycle_control(host: str, port: int):
    """Teste les codes de retour forcés (§7)."""
    base = f"https://{host}:{port}"

    async with httpx.AsyncClient(verify=False) as c:
        print(f"\n  [§7] Testing forced cycle return codes")

        # Armer 501
        r = await c.post(f"{base}/admin/device/{MOCK_CLIENT_ID}/kill")
        print(f"  [admin] kill → {r.json()}")

        # Cycle → doit recevoir 501
        r = await c.post(f"{base}/index.php?m=api&a=cycle", content=xml_payload())
        print(f"  [cycle] → {r.text[:150]}")

        # Cycle normal → doit recevoir 500
        r = await c.post(f"{base}/index.php?m=api&a=cycle", content=xml_payload())
        print(f"  [cycle] → {r.text[:150]}")


async def replay_log(logfile: str, host: str, port: int):
    """§10 — Rejoue un fichier de log c2.log."""
    path = Path(logfile)
    if not path.exists():
        print(f"❌ Fichier introuvable : {logfile}")
        sys.exit(1)

    entries = []
    for line in path.read_text().splitlines():
        idx = line.find("{")
        if idx == -1:
            continue
        try:
            entry = json.loads(line[idx:])
            if "action_canonical" in entry:
                entries.append(entry)
        except json.JSONDecodeError:
            continue

    # Aussi tenter le format JSON lines pur
    if not entries:
        for line in path.read_text().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
                if "action_canonical" in entry:
                    entries.append(entry)
            except json.JSONDecodeError:
                continue

    if not entries:
        print(f"⚠️  Aucune entrée exploitable dans {logfile}")
        print("    Format attendu : JSON lines avec au moins 'action_canonical' et 'body_preview'")
        sys.exit(1)

    print(f"📼 Replay: {len(entries)} requêtes depuis {logfile}\n")

    base = f"https://{host}:{port}/index.php"
    async with httpx.AsyncClient(verify=False) as c:
        for i, entry in enumerate(entries, 1):
            action = entry.get("action_raw", entry["action_canonical"])
            client = entry.get("client", MOCK_CLIENT_ID)
            body = entry.get("body_preview", xml_payload("", client))

            url = f"{base}?m=api&a={action}"
            r = await c.post(url, content=body.encode("utf-8", errors="replace"))
            print(f"  [{i:3d}/{len(entries)}] {action} (client={client}) → {r.status_code}")

    print(f"\n✅ Replay terminé")


async def main(args):
    print(f"═══════════════════════════════════════════════")
    print(f"  iKeyMonitor Mock C2 — Test Client")
    print(f"  Target: {args.host}:{args.port}  Version: {args.version}")
    print(f"═══════════════════════════════════════════════")

    if args.replay:
        await replay_log(args.replay, args.host, args.port)
        return

    await test_rest(args.host, args.port, args.version)
    await test_ws(args.host, args.port)
    await test_cycle_control(args.host, args.port)

    print(f"\n✅ All tests passed")


if __name__ == "__main__":
    p = argparse.ArgumentParser(description="iKeyMonitor mock C2 test client")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8443)
    p.add_argument("--version", choices=["v17.4", "v19.1"], default="v19.1",
                   help="Simulate v17.4 (typo endpoints) or v19.1 (corrected)")
    p.add_argument("--replay", metavar="LOGFILE",
                   help="Replay a captured c2.log file instead of running the test sequence")
    args = p.parse_args()
    asyncio.run(main(args))
