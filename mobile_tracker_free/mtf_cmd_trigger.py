#!/usr/bin/env python3
"""
Mobile Tracker Free — FCM Command Trigger via ADB
Alternative à Frida pour envoyer des commandes au stalkerware.

Utilise `am broadcast` pour injecter des commandes FCM via le
FirebaseInstanceIdReceiver (exporté dans le manifest).

Usage :
  python mtf_cmd_trigger.py location          # Position GPS
  python mtf_cmd_trigger.py photo_front       # Photo caméra frontale
  python mtf_cmd_trigger.py photo_rear        # Photo caméra arrière + flash
  python mtf_cmd_trigger.py audio 60          # Enregistrement micro 60s
  python mtf_cmd_trigger.py screenshot        # Screenshot
  python mtf_cmd_trigger.py hide              # Cacher l'icône
  python mtf_cmd_trigger.py show              # Afficher l'icône
  python mtf_cmd_trigger.py lock 1234         # Verrouiller avec code
  python mtf_cmd_trigger.py unlock            # Déverrouiller
  python mtf_cmd_trigger.py vibrate 5000      # Vibrer 5s
  python mtf_cmd_trigger.py ring 5000         # Sonner 5s
  python mtf_cmd_trigger.py tts "bonjour"     # Text-to-speech
  python mtf_cmd_trigger.py wifi_on           # Activer WiFi
  python mtf_cmd_trigger.py wifi_off          # Couper WiFi
  python mtf_cmd_trigger.py dashboard         # MAJ dashboard
  python mtf_cmd_trigger.py settings          # Check settings
  python mtf_cmd_trigger.py list              # Liste toutes les commandes
  python mtf_cmd_trigger.py raw "cmd--p1--p2" # Commande brute

⚠️  Nécessite ADB connecté au device/Corellium.
"""

import subprocess
import sys
import time
from typing import Optional

PKG = "phone.monitor2026"

# Compteur global pour les idLog
_id_log = [100]

def next_id() -> int:
    _id_log[0] += 1
    return _id_log[0]


def adb(cmd: str, check: bool = True) -> str:
    """Exécute une commande ADB."""
    full = f"adb shell {cmd}"
    print(f"  $ {full}")
    result = subprocess.run(full, shell=True, capture_output=True, text=True)
    if result.stdout.strip():
        print(f"    → {result.stdout.strip()[:200]}")
    if result.stderr.strip() and check:
        print(f"    ⚠ {result.stderr.strip()[:200]}")
    return result.stdout.strip()


def send_fcm_command(action: str):
    """
    Envoie une commande FCM au stalkerware.
    
    Méthode : startservice avec extra "action" dans le bundle.
    Le service FCM du stalkerware parse le champ "action" du RemoteMessage data.
    On simule ça via un am startservice avec extras.
    """
    print(f"\n[*] Sending FCM command: {action}")
    
    # Méthode 1 : Via am broadcast au FirebaseInstanceIdReceiver (exporté)
    # Le receiver est exporté et écoute com.google.android.c2dm.intent.RECEIVE
    adb(
        f'am broadcast '
        f'-a com.google.android.c2dm.intent.RECEIVE '
        f'-n {PKG}/com.google.firebase.iid.FirebaseInstanceIdReceiver '
        f'--es "action" "{action}" '
        f'-c com.google.android.c2dm.intent.RECEIVE '
        f'--ei "google.sent_time" {int(time.time() * 1000)} '
        f'--es "google.message_id" "mock_{next_id()}" '
        f'--es "from" "38496474107" '
        f'--es "collapse_key" "do_not_collapse"',
        check=False
    )
    
    print(f"[+] Command sent: {action.split('--')[0]}")


def send_via_content_provider(action: str):
    """
    Méthode alternative : écrire directement dans SharedPreferences
    pour simuler un changement de config (pour les commandes de toggle).
    """
    print(f"\n[*] Writing config via su: {action}")
    # Extraire le nom de la pref et la valeur
    parts = action.split("--")
    if len(parts) >= 2:
        pref_name = parts[0]
        pref_value = parts[1]
        adb(
            f'su -c "am start-foreground-service '
            f'-n {PKG}/com.app.service.ServiceCheckSettings"',
            check=False
        )


# ============================================================
# Commandes prédéfinies
# ============================================================

COMMANDS = {
    # --- Localisation ---
    "location": lambda args: send_fcm_command(f"GetLocation----{next_id()}"),
    "loc_live_on": lambda args: send_fcm_command(f"startLocLive--1----{next_id()}"),
    "loc_live_off": lambda args: send_fcm_command(f"startLocLive--0----{next_id()}"),
    "gps_on": lambda args: send_fcm_command(f"activateLocGPS----{next_id()}"),
    "gps_off": lambda args: send_fcm_command(f"disabledLocGPS----{next_id()}"),
    "gps_status": lambda args: send_fcm_command(f"isActiveGPS"),
    
    # --- Caméra ---
    "photo_front": lambda args: send_fcm_command(f"TakePictureFront--1##0--{next_id()}"),
    "photo_front_flash": lambda args: send_fcm_command(f"TakePictureFront--1##1--{next_id()}"),
    "photo_rear": lambda args: send_fcm_command(f"TakePictureFront--2##0--{next_id()}"),
    "photo_rear_flash": lambda args: send_fcm_command(f"TakePictureFront--2##1--{next_id()}"),
    "camera_off": lambda args: send_fcm_command(f"disableCamera----{next_id()}"),
    "camera_on": lambda args: send_fcm_command(f"enableCamera----{next_id()}"),
    
    # --- Audio ---
    "audio": lambda args: send_fcm_command(
        f"RecordAudio--{args[0] if args else 30}--1--{next_id()}"
    ),
    
    # --- Screen ---
    "screenshot": lambda args: send_fcm_command(f"screenShot----{next_id()}"),
    "screenshot_mp": lambda args: send_fcm_command(f"takeScreenShot----{next_id()}"),
    
    # --- Stealth ---
    "hide": lambda args: send_fcm_command(f"hideIcon----{next_id()}"),
    "show": lambda args: send_fcm_command(f"showIcon----{next_id()}"),
    
    # --- Device control ---
    "lock": lambda args: send_fcm_command(
        f"LockPhone--{args[0] if args else '1234'}----{next_id()}"
    ),
    "unlock": lambda args: send_fcm_command(f"UnLockPhone----{next_id()}"),
    "vibrate": lambda args: send_fcm_command(
        f"Vibrate--{args[0] if args else 3000}--Vibrate--{next_id()}"
    ),
    "ring": lambda args: send_fcm_command(
        f"Ring--{args[0] if args else 5000}--Ring--{next_id()}"
    ),
    "tts": lambda args: send_fcm_command(
        f"TextSpeaker--{' '.join(args) if args else 'test'}--fr--{next_id()}"
    ),
    "message": lambda args: send_fcm_command(
        f"Message--{next_id()}--Alert--{' '.join(args) if args else 'Test message'}"
    ),
    "reboot": lambda args: send_fcm_command(f"restartPhone----{next_id()}"),
    
    # --- Réseau ---
    "wifi_on": lambda args: send_fcm_command(f"activateWIFI----{next_id()}"),
    "wifi_off": lambda args: send_fcm_command(f"disabledWIFI----{next_id()}"),
    "data_on": lambda args: send_fcm_command(f"enabledDataMobile----{next_id()}"),
    "data_off": lambda args: send_fcm_command(f"disabledDataMobile----{next_id()}"),
    
    # --- Data extraction ---
    "get_sms": lambda args: send_fcm_command(f"getListMessage--30--{next_id()}"),
    "get_calls": lambda args: send_fcm_command(f"getListCall--30--{next_id()}"),
    "get_contacts": lambda args: send_fcm_command(f"getListContacts----{next_id()}"),
    "get_history": lambda args: send_fcm_command(f"getListHistoryChrome--30--{next_id()}"),
    "get_bookmarks": lambda args: send_fcm_command(f"getListBookmarksChrome--30--{next_id()}"),
    
    # --- IM root ---
    "get_facebook": lambda args: send_fcm_command(f"getListFacebook----{next_id()}"),
    "get_whatsapp": lambda args: send_fcm_command(f"getListWhatsApp----{next_id()}"),
    "get_telegram": lambda args: send_fcm_command(f"getListTelegram----{next_id()}"),
    "get_instagram": lambda args: send_fcm_command(f"getListInstagram----{next_id()}"),
    "get_viber": lambda args: send_fcm_command(f"getListViber----{next_id()}"),
    "get_gmail": lambda args: send_fcm_command(f"getListGmail----{next_id()}"),
    
    # --- Tracking toggles ---
    "track_sms_on": lambda args: send_fcm_command("trackSMS--1"),
    "track_sms_off": lambda args: send_fcm_command("trackSMS--0"),
    "track_calls_on": lambda args: send_fcm_command("trackCalls--1"),
    "track_calls_off": lambda args: send_fcm_command("trackCalls--0"),
    "track_loc_on": lambda args: send_fcm_command("trackLoc--1"),
    "track_loc_off": lambda args: send_fcm_command("trackLoc--0"),
    "track_screenshot_on": lambda args: send_fcm_command("trackScreenshot--1"),
    "track_screenshot_off": lambda args: send_fcm_command("trackScreenshot--0"),
    "track_clipboard_on": lambda args: send_fcm_command("trackClipboard--1"),
    "track_clipboard_off": lambda args: send_fcm_command("trackClipboard--0"),
    "recording_calls_on": lambda args: send_fcm_command("recordingCalls--1"),
    "recording_calls_off": lambda args: send_fcm_command("recordingCalls--0"),
    
    # --- Live ---
    "live_start": lambda args: send_fcm_command(f"startLive--1----{next_id()}"),
    "live_stop": lambda args: send_fcm_command(f"startLive--0----{next_id()}"),
    "file_explorer": lambda args: send_fcm_command(f"startFileExplorer----{next_id()}"),
    
    # --- Admin ---
    "dashboard": lambda args: send_fcm_command("dashboardUpdate"),
    "settings": lambda args: send_fcm_command("settingsCheck"),
    "get_accessibility": lambda args: send_fcm_command("getAccessibility"),
    "get_notifications": lambda args: send_fcm_command("getNotifications"),
    "refresh_apps": lambda args: send_fcm_command("refreshApps"),
    "refresh_contacts": lambda args: send_fcm_command("refreshContacts"),
    "restart_app": lambda args: send_fcm_command("restartApp"),
    "sim_info": lambda args: send_fcm_command(f"getInfoSIM----{next_id()}"),
    
    # --- Commande brute ---
    "raw": lambda args: send_fcm_command("--".join(args) if args else "dashboardUpdate"),
}


def print_commands():
    """Affiche toutes les commandes disponibles."""
    categories = {
        "Localisation": ["location", "loc_live_on", "loc_live_off", "gps_on", "gps_off", "gps_status"],
        "Caméra": ["photo_front", "photo_front_flash", "photo_rear", "photo_rear_flash", "camera_off", "camera_on"],
        "Audio": ["audio"],
        "Screen": ["screenshot", "screenshot_mp"],
        "Stealth": ["hide", "show"],
        "Device": ["lock", "unlock", "vibrate", "ring", "tts", "message", "reboot"],
        "Réseau": ["wifi_on", "wifi_off", "data_on", "data_off"],
        "Data extraction": ["get_sms", "get_calls", "get_contacts", "get_history", "get_bookmarks"],
        "IM Root": ["get_facebook", "get_whatsapp", "get_telegram", "get_instagram", "get_viber", "get_gmail"],
        "Tracking": ["track_sms_on", "track_sms_off", "track_calls_on", "track_loc_on", "track_screenshot_on", "track_clipboard_on", "recording_calls_on"],
        "Live": ["live_start", "live_stop", "file_explorer"],
        "Admin": ["dashboard", "settings", "refresh_apps", "refresh_contacts", "restart_app", "sim_info"],
        "Raw": ["raw"],
    }
    
    print("\n=== MTF Command Trigger — Available Commands ===\n")
    for cat, cmds in categories.items():
        print(f"  {cat}:")
        for c in cmds:
            print(f"    {c}")
    print(f"\n  Total: {len(COMMANDS)} commands")
    print(f"\n  Usage: python {sys.argv[0]} <command> [args...]")
    print(f"  Example: python {sys.argv[0]} audio 60")
    print(f"  Example: python {sys.argv[0]} raw GetLocation----42")


def main():
    if len(sys.argv) < 2 or sys.argv[1] == "list":
        print_commands()
        return 0
    
    cmd_name = sys.argv[1]
    cmd_args = sys.argv[2:]
    
    if cmd_name not in COMMANDS:
        print(f"[!] Unknown command: {cmd_name}")
        print(f"    Use 'list' to see all commands, or 'raw' for custom commands.")
        return 1
    
    print("=" * 50)
    print("MTF FCM Command Trigger")
    print(f"Target: {PKG}")
    print(f"Command: {cmd_name}")
    if cmd_args:
        print(f"Args: {cmd_args}")
    print("=" * 50)
    
    COMMANDS[cmd_name](cmd_args)
    
    print(f"\n[*] Check mock server logs for the C2 callback")
    return 0


if __name__ == "__main__":
    sys.exit(main())
