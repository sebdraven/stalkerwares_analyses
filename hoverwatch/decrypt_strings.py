#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = [
#     "malduck",
#     "lief",
# ]
# ///
"""
Hoverwatch / Snoopza DES-encrypted strings - batch decryptor.

Famille Brainstack (Hoverwatch, Snoopza, ...). Crypto identifiee dans
p094hw.utils.C0877h.m6280e : DES/ECB/PKCS5, cle "val" paddee "vallength 8"
puis tronquee a 8 bytes par DESKeySpec -> b"vallengt" (76616c6c656e6774).
Identique au moins de 7.5.369 a 7.5.385.

Note crypto : malduck n'expose que des3, qui refuse les cles degenerees
en DES simple (check de securite pycryptodome). On tombe sur DES direct
via Cryptodome.Cipher.DES (deja dependance transitive de malduck) + on
garde malduck.unpkcs7 pour le depadding.

Usage:
    uv run decrypt_strings.py <APK> [-o OUT_DIR] [-n NAME]
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import tempfile
import zipfile
from base64 import b64decode
from pathlib import Path

import lief
from Cryptodome.Cipher import DES
from malduck import unpkcs7

# --- Crypto ------------------------------------------------------------------
DES_KEY = b"vallengt"


def is_printable_utf8(b: bytes) -> str | None:
    try:
        s = b.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if not s:
        return None
    good = sum(1 for c in s if c.isprintable() or c in "\t\n\r ")
    return s if good / len(s) >= 0.9 else None


_B64_STRICT = re.compile(r"^[A-Za-z0-9+/]+={0,2}$")


def try_decrypt(b64_str: str) -> str | None:
    """DES/ECB/PKCS5 + Base64(flag 0). Returns plaintext or None."""
    if len(b64_str) < 12:
        return None
    clean = b64_str.replace("\n", "").replace("\r", "")
    if len(clean) < 12 or len(clean) % 4 != 0 or not _B64_STRICT.match(clean):
        return None
    try:
        ct = b64decode(clean, validate=True)
    except Exception:
        return None
    if not ct or len(ct) % 8 != 0:
        return None
    try:
        pt_padded = DES.new(DES_KEY, DES.MODE_ECB).decrypt(ct)
    except Exception:
        return None
    pt = unpkcs7(pt_padded)
    if len(pt) == len(pt_padded):
        if not (len(pt_padded) == 8 and pt == b""):
            return None
    return is_printable_utf8(pt)


# --- DEX strings via LIEF ----------------------------------------------------
def extract_strings_from_apk(apk_path: Path) -> tuple[set[str], list[str]]:
    strings: set[str] = set()
    dex_names: list[str] = []
    with tempfile.TemporaryDirectory() as tmp:
        tmp_dir = Path(tmp)
        with zipfile.ZipFile(apk_path) as zf:
            for name in zf.namelist():
                if not re.fullmatch(r"classes\d*\.dex", name):
                    continue
                dex_names.append(name)
                out = tmp_dir / name
                out.write_bytes(zf.read(name))
                dex = lief.DEX.parse(str(out))
                if dex is None:
                    print(f"[!] LIEF failed on {name}", file=sys.stderr)
                    continue
                for s in dex.strings:
                    v = s if isinstance(s, str) else getattr(s, "value", str(s))
                    if v:
                        strings.add(v)
    return strings, dex_names


# --- Classification ----------------------------------------------------------
_URL       = re.compile(r"^https?://", re.I)
_DOMAIN    = re.compile(r"^([a-z0-9-]+\.)+[a-z]{2,}(:\d+)?(/.*)?$", re.I)
_API_PATH  = re.compile(r"^/?api/[a-z0-9_/-]+/?$", re.I)
_PKG_NAME  = re.compile(r"^(com|org|net|io|android|androidx)\.[a-z0-9._]+$")
_CONTENT   = re.compile(r"^content://", re.I)
_LOGCAT    = re.compile(r"^\s*(-[a-z]|logcat|[A-Z]/[A-Za-z]+)\b")
_REFLECT   = re.compile(r"^\s*m[A-Z][a-zA-Z]+\s*$")  # mCid, mLac, mTac
_CELL_CLS  = re.compile(r"^CellIdentity(Gsm|Lte|Wcdma|Cdma|Nr|Tdscdma)$")


def classify(pt: str) -> str:
    s = pt.strip()
    if _URL.match(s) or ";https://" in s or ";http://" in s:
        return "c2_url"
    if _API_PATH.match(s):
        return "api_path"
    if _CONTENT.match(s):
        return "content_uri"
    # package_name checked BEFORE domain (com.x.y matches both; pkg is more specific)
    if _PKG_NAME.match(s):
        return "targeted_app"
    if _DOMAIN.match(s):
        return "domain"
    if _CELL_CLS.match(s) or _REFLECT.match(pt):
        return "telephony_reflection"
    if _LOGCAT.match(pt):
        return "shell_cmd"
    if s.startswith("/") and " " not in s:
        return "path_or_intent"
    return "string"


# --- Main --------------------------------------------------------------------
def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("apk", type=Path, help="APK a analyser")
    ap.add_argument("-o", "--out-dir", type=Path, default=Path("."),
                    help="Dossier de sortie (def: cwd)")
    ap.add_argument("-n", "--name", default=None,
                    help="Nom d'analyse (def: nom de fichier APK)")
    args = ap.parse_args()

    if not args.apk.is_file():
        print(f"[!] Not a file: {args.apk}", file=sys.stderr)
        return 2

    name = args.name or args.apk.stem
    args.out_dir.mkdir(parents=True, exist_ok=True)

    print(f"[*] APK   : {args.apk}")
    print(f"[*] Key   : {DES_KEY.hex()} ({DES_KEY.decode()!r})")
    print(f"[*] Algo  : DES/ECB/PKCS5 + Base64(default)")
    print()

    strings, dex_names = extract_strings_from_apk(args.apk)
    print(f"[*] DEX   : {', '.join(dex_names) or 'none'}")
    print(f"[*] Total unique DEX strings : {len(strings)}")

    hits: dict[str, dict] = {}
    for raw in strings:
        pt = try_decrypt(raw)
        if pt is None:
            continue
        rec = hits.setdefault(pt, {"plaintext": pt,
                                   "kind": classify(pt),
                                   "ciphertexts": set()})
        rec["ciphertexts"].add(raw)
    print(f"[+] Decrypted plaintexts     : {len(hits)}")
    print()

    records = sorted(
        ({"plaintext": v["plaintext"],
          "kind": v["kind"],
          "ciphertexts": sorted(v["ciphertexts"])}
         for v in hits.values()),
        key=lambda r: (r["kind"], r["plaintext"]),
    )

    json_path = args.out_dir / f"{name}_strings.json"
    md_path   = args.out_dir / f"{name}_strings.md"

    json_path.write_text(json.dumps({
        "apk": str(args.apk),
        "dex_files": dex_names,
        "algorithm": "DES/ECB/PKCS5",
        "key_hex": DES_KEY.hex(),
        "key_utf8": DES_KEY.decode(),
        "count_total_strings": len(strings),
        "count_decrypted": len(records),
        "records": records,
    }, indent=2, ensure_ascii=False), encoding="utf-8")

    by_kind: dict[str, list[dict]] = {}
    for r in records:
        by_kind.setdefault(r["kind"], []).append(r)

    lines = [
        f"# {name} - DES-decrypted strings",
        "",
        f"- APK: `{args.apk}`",
        f"- DEX: {', '.join(f'`{d}`' for d in dex_names)}",
        f"- Algo: DES/ECB/PKCS5, cle `{DES_KEY.hex()}` (`{DES_KEY.decode()}`)",
        f"- Strings DEX totales : **{len(strings)}**",
        f"- Plaintexts retrouves : **{len(records)}**",
        "",
    ]
    for kind in sorted(by_kind):
        rows = by_kind[kind]
        lines += [f"## `{kind}` ({len(rows)})", "",
                  "| # | Plaintext | Ciphertext(s) Base64 |",
                  "|---|---|---|"]
        for i, r in enumerate(rows, 1):
            pt = r["plaintext"].replace("|", "\\|").replace("\n", " / ")
            cts = "<br>".join(
                f"`{c.replace(chr(10), chr(92) + 'n')}`"
                for c in r["ciphertexts"]
            )
            lines.append(f"| {i} | `{pt}` | {cts} |")
        lines.append("")
    md_path.write_text("\n".join(lines), encoding="utf-8")

    print(f"[+] {json_path}")
    print(f"[+] {md_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
