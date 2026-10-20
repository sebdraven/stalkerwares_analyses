#!/usr/bin/env python3
"""
Forge le fichier .device.dat lu par l1.e / l1.j.g() d'iKeyMonitor v19.1.

Chaîne de lecture côté APK :
  l1.e.b()  -> lit le fichier octet par octet (brut)
  l1.e.c()  -> applique a() = décalage +5 sur chaque char (César)
  l1.j.g()  -> split(",") sur le résultat, puis :
                 [1] = licenseKey (f6500c)   <-- le champ qui débloque j.b()
                 [2] = "true"/"false" activate (f6498a)
                 [6] = savedMAC (f6502e)
                 [7] = unitID (f6501d)
                 [8] = extra (f6503f)

Donc le fichier doit contenir le CSV clair décalé de -5 (pour qu'après +5 en
lecture on retombe sur le clair).

Usage :
  uv run python forge_device_dat.py            # écrit ./device.dat
  puis push : adb push device.dat /sdcard/Android/.bak/.com.android.internet.service/.device.dat
"""

# Valeurs mock (cohérentes avec le mock C2 et le device Corellium)
LICENSE = "MOCK-LICENSE-2026"
ACTIVATE = "true"
CLIENT_MAC = "020000000000"       # Client ID observé du device
UNIT_ID = "MSIK-ONLINE-MOCK001"   # notre UnitID mock
EXTRA = ""

# CSV à 9 champs : index 0..8. Seuls 1,2,6,7,8 sont lus par l1.j.g().
# Les autres champs (0,3,4,5) : valeurs neutres non lues.
fields = [
    "0",          # [0] inconnu / non lu
    LICENSE,      # [1] licenseKey  -> f6500c
    ACTIVATE,     # [2] activate    -> f6498a
    "",           # [3]
    "",           # [4]
    "",           # [5]
    CLIENT_MAC,   # [6] savedMAC    -> f6502e
    UNIT_ID,      # [7] unitID      -> f6501d
    EXTRA,        # [8] extra       -> f6503f
]

clear_csv = ",".join(fields)

# a() dans l'APK fait char + 5 à la lecture -> on stocke char - 5.
encoded = "".join(chr((ord(c) - 5) & 0xFF) for c in clear_csv)

with open("device.dat", "w", encoding="latin-1") as f:
    f.write(encoded)

print("clear CSV :", clear_csv)
print("written   : device.dat (%d bytes, César -5)" % len(encoded))
print()
print("Push :")
print("  adb push device.dat /sdcard/Android/.bak/.com.android.internet.service/.device.dat")
