#!/usr/bin/env python3
"""
Mobile Tracker Free — Dropper APK downloader
Supporte v2.7 (com.mtf.download) et v3.9 (com.mtf.protect)

Protocoles :
  v2.7 : getURLFTP.php → JSON → download streaming
  v3.9 : downloadAPK.php direct → streaming APK

Usage :
  python download_mtf_payload.py              # v3.9, ARM (défaut)
  python download_mtf_payload.py --v27        # v2.7 legacy
  python download_mtf_payload.py --arch x86   # variante x86
  python download_mtf_payload.py --check      # version check seulement
"""

import argparse
import requests
import sys
import json
from datetime import datetime, timedelta
from pathlib import Path

# === IoC v3.9 (com.mtf.protect) ===
V39_BASE_URL = "https://tracker-free.com/"
V39_DOWNLOAD_URL = "https://apkv2.tracker-free.com/downloadAPK.php"
V39_VERSION_ENDPOINT = "getVersionApp.php"

# === IoC v2.7 (com.mtf.download) ===
V27_BASE_URL = "https://appapk.mtf.re/"
V27_GET_URL_ENDPOINT = "getURLFTP.php"

# === Commun ===
USER_AGENT = "KABNKNHFFHDHYD58698347556988AD89GH2020"
HEADERS = {
    "User-Agent": USER_AGENT,
    "Accept-Language": "UTF-8",
    "Connection": "close",
}

TYPE_ARM = "0"
TYPE_OTHER = "1"

OUTPUT_DIR = Path(__file__).parent / "downloaded_apks"


def get_date_check() -> str:
    """Reproduit le timestamp du dropper : now() + 10 secondes."""
    dt = datetime.now() + timedelta(seconds=10)
    return dt.strftime("%Y/%m/%d %H:%M:%S")


# =============================================
# v3.9 — Download direct
# =============================================

def v39_check_version(session: requests.Session) -> str | None:
    """GET/POST getVersionApp.php — récupère la dernière version du dropper."""
    url = V39_BASE_URL + V39_VERSION_ENDPOINT
    print(f"[*] Version check: POST {url}")
    try:
        resp = session.post(url, data={}, headers=HEADERS, timeout=30)
        resp.raise_for_status()
        version = resp.text.strip()
        print(f"[+] Version serveur : {version}")
        return version
    except requests.exceptions.RequestException as e:
        print(f"[!] Erreur : {e}")
        return None


def v39_download(session: requests.Session, type_version: str = TYPE_ARM) -> Path | None:
    """v3.9 — POST direct vers downloadAPK.php."""
    params = {
        "dateCheck": get_date_check(),
        "typeVersion": type_version,
    }

    print(f"\n[*] POST {V39_DOWNLOAD_URL}")
    print(f"    Params: {params}")

    try:
        resp = session.post(
            V39_DOWNLOAD_URL,
            data=params,
            headers=HEADERS,
            timeout=120,
            stream=True,
        )
        resp.raise_for_status()
        return _save_apk(resp, type_version, "v39")
    except requests.exceptions.RequestException as e:
        print(f"[!] Erreur : {e}")
        return None


# =============================================
# v2.7 — Two-step (getURLFTP → download)
# =============================================

def v27_get_url(session: requests.Session) -> dict | None:
    """v2.7 — Étape 1 : POST getURLFTP.php → JSON avec URL du payload."""
    params = {"dateCheck": get_date_check()}
    url = V27_BASE_URL + V27_GET_URL_ENDPOINT

    print(f"[*] POST {url}")
    print(f"    Params: {params}")

    try:
        resp = session.post(url, data=params, headers=HEADERS, timeout=30)
        resp.raise_for_status()
        print(f"    Status: {resp.status_code}")
        print(f"    Body: {resp.text[:500]}")

        data = resp.json()
        if data.get("status") == "no":
            print("[!] Serveur a répondu status=no")
            return None

        apk_url = data.get("url", "")
        if not apk_url:
            print(f"[!] Pas de champ 'url' dans la réponse")
            return None

        print(f"[+] URL payload : {apk_url}")
        return {"url": apk_url, "full_response": data}

    except (requests.exceptions.RequestException, json.JSONDecodeError) as e:
        print(f"[!] Erreur : {e}")
        return None


def v27_download(session: requests.Session, apk_url: str, type_version: str = TYPE_ARM) -> Path | None:
    """v2.7 — Étape 2 : POST streaming du payload."""
    params = {
        "dateCheck": get_date_check(),
        "typeVersion": type_version,
    }
    full_url = V27_BASE_URL + apk_url if not apk_url.startswith("http") else apk_url

    print(f"\n[*] POST {full_url}")
    print(f"    Params: {params}")

    try:
        resp = session.post(
            full_url,
            data=params,
            headers=HEADERS,
            timeout=120,
            stream=True,
        )
        resp.raise_for_status()
        return _save_apk(resp, type_version, "v27")
    except requests.exceptions.RequestException as e:
        print(f"[!] Erreur : {e}")
        return None


# =============================================
# Utilitaires
# =============================================

def _save_apk(resp: requests.Response, type_version: str, version_tag: str) -> Path | None:
    """Sauvegarde la réponse streaming en APK."""
    content_type = resp.headers.get("Content-Type", "")
    content_length = resp.headers.get("Content-Length", "unknown")
    print(f"    Content-Type: {content_type}")
    print(f"    Content-Length: {content_length}")

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    arch = "arm" if type_version == TYPE_ARM else "x86"
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"mtf_payload_{version_tag}_{arch}_{ts}.apk"
    output_path = OUTPUT_DIR / filename

    downloaded = 0
    with open(output_path, "wb") as f:
        for chunk in resp.iter_content(chunk_size=4096):
            if chunk:
                f.write(chunk)
                downloaded += len(chunk)
                print(f"\r    Downloaded: {downloaded:,} bytes", end="", flush=True)

    print(f"\n[+] Sauvegardé : {output_path} ({downloaded:,} bytes)")

    if downloaded < 1000:
        print(f"[!] Fichier suspicieusement petit — probablement une erreur serveur")
        print(f"    Contenu : {output_path.read_text(errors='replace')[:500]}")

    return output_path


def main():
    parser = argparse.ArgumentParser(description="Mobile Tracker Free — Payload Downloader")
    parser.add_argument("--v27", action="store_true", help="Utiliser le protocole v2.7 (legacy)")
    parser.add_argument("--arch", choices=["arm", "x86"], default="arm", help="Architecture cible")
    parser.add_argument("--check", action="store_true", help="Version check seulement (v3.9)")
    args = parser.parse_args()

    type_version = TYPE_ARM if args.arch == "arm" else TYPE_OTHER

    print("=" * 60)
    print("Mobile Tracker Free — Dropper APK Downloader")
    print(f"Protocole : {'v2.7 (legacy)' if args.v27 else 'v3.9'}")
    print(f"Architecture : {args.arch}")
    print("=" * 60)

    session = requests.Session()

    # Version check (v3.9 only)
    if args.check or not args.v27:
        print(f"\n{'='*40}")
        print("VERSION CHECK")
        print(f"{'='*40}")
        v39_check_version(session)
        if args.check:
            return 0

    if args.v27:
        # ===== v2.7 legacy =====
        print(f"\n{'='*40}")
        print("ÉTAPE 1 : getURLFTP.php")
        print(f"{'='*40}")
        result = v27_get_url(session)
        if result is None:
            return 1

        OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
        json_path = OUTPUT_DIR / "server_response_v27.json"
        with open(json_path, "w") as f:
            json.dump(result["full_response"], f, indent=2)
        print(f"[+] JSON sauvegardé : {json_path}")

        print(f"\n{'='*40}")
        print("ÉTAPE 2 : Download payload")
        print(f"{'='*40}")
        apk_path = v27_download(session, result["url"], type_version)

    else:
        # ===== v3.9 =====
        print(f"\n{'='*40}")
        print("DOWNLOAD DIRECT (v3.9)")
        print(f"{'='*40}")
        apk_path = v39_download(session, type_version)

    if apk_path is None:
        print("\n[!] Échec.")
        return 1

    print(f"\n{'='*60}")
    print("DONE — Prochaine étape : analyser dans JADX")
    print(f"  APK : {apk_path}")
    print(f"{'='*60}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
