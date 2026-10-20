#!/usr/bin/env python3
"""
Forge le fichier .device.data (XML) lu par l1.i.c() d'iKeyMonitor v19.1.

l1.i.c() parse le XML /sdcard/Android/.bak/.com.android.internet.service/.device.data
et pour chaque champ applique u.i.a(value, "&HOk-=&%") = DES/CBC/PKCS5 decrypt.
Résultat -> f6493c (lic) qui devient f6500c dans l1.j.g() -> débloque j.b().

Chiffrement (u.i.c) reproduit ici :
  DES/CBC/PKCS5Padding, clé "&HOk-=&%" (8 octets), IV fixe {1..8},
  puis Base64 DEFAULT (avec \n final, comme Android Base64.encodeToString(...,0)).

Format XML (u.i.b) :
  <body><lic>..</lic><mc>..</mc><ie>..</ie><keyT>..</keyT></body>

Champs (mappés dans l1.j.g via i.f6493c..f6496f) :
  lic  = licenseKey   -> f6500c  (LE champ qui débloque)
  mc   = savedMAC     -> f6502e
  ie   = unitID       -> f6501d  (via i.f6496f dans g(), à confirmer)
  keyT = extra

uv add pycryptodome  (si pas déjà là)
uv run python forge_device_data.py
adb push device.data /sdcard/Android/.bak/.com.android.internet.service/.device.data
"""

import base64
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad

KEY = b"&HOk-=&%"                 # 8 octets DES
IV = bytes([1, 2, 3, 4, 5, 6, 7, 8])

# Valeurs mock
LIC = "MOCK-LICENSE-2026"
MC = "020000000000"              # Client ID / MAC du device
IE = "MSIK-ONLINE-MOCK001"       # UnitID mock
KEYT = "1"


def enc(plaintext: str) -> str:
    """Reproduit u.i.c() : DES/CBC/PKCS5 -> Base64 DEFAULT (avec \\n final)."""
    cipher = DES.new(KEY, DES.MODE_CBC, IV)
    ct = cipher.encrypt(pad(plaintext.encode("utf-8"), DES.block_size))
    # Android Base64.encodeToString(..., 0) => DEFAULT, ajoute un '\n' terminal
    return base64.encodebytes(ct).decode("ascii")  # encodebytes met déjà le \n


lic_b64 = enc(LIC).strip("\n") + "\n"
mc_b64 = enc(MC).strip("\n") + "\n"
ie_b64 = enc(IE).strip("\n") + "\n"
keyt_b64 = enc(KEYT).strip("\n") + "\n"

# Format identique à u.i.b() (Xml.newSerializer)
xml = (
    "<?xml version='1.0' encoding='UTF-8' standalone='yes' ?>"
    "<body>"
    f"<lic>{lic_b64}</lic>"
    f"<mc>{mc_b64}</mc>"
    f"<ie>{ie_b64}</ie>"
    f"<keyT>{keyt_b64}</keyt>".replace("</keyt>", "</keyT>")
    + "</body>"
)

with open("device.data", "w", encoding="utf-8") as f:
    f.write(xml)

print("lic  clear:", LIC, "-> b64:", lic_b64.strip())
print("mc   clear:", MC, "-> b64:", mc_b64.strip())
print("ie   clear:", IE, "-> b64:", ie_b64.strip())
print()
print("written: device.data (%d bytes)" % len(xml))
print()
print("Push :")
print("  adb push device.data /sdcard/Android/.bak/.com.android.internet.service/.device.data")
