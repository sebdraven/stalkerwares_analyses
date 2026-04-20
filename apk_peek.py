#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# ///
"""
apk_peek - outil generique pour naviguer et extraire depuis un APK.

Sub-commands:
    info      Metadata et breakdown de l'APK (counts par top-dir)
    list      Liste les entrees de l'APK (avec filtre glob)
    cat       Affiche le contenu texte d'un fichier
    extract   Extrait un ou plusieurs fichiers vers dossier de sortie
    find      Cherche une chaine dans le contenu texte des fichiers

Zero dependance externe : stdlib only (zipfile, fnmatch, argparse).
Pas de dependance Android specifique : marche sur n'importe quel APK / ZIP.
AXML compiles (AndroidManifest, res/xml/*.xml post-aapt) sont detectes et
rediriges vers JADX-GUI pour decodage.

Examples:
    uv run apk_peek.py info hoverwatch.apk
    uv run apk_peek.py list hoverwatch.apk
    uv run apk_peek.py list hoverwatch.apk 'res/xml/*'
    uv run apk_peek.py list hoverwatch.apk '*.json'
    uv run apk_peek.py cat hoverwatch.apk assets/providers.json
    uv run apk_peek.py extract hoverwatch.apk 'assets/*' -o hw_assets/
    uv run apk_peek.py extract hoverwatch.apk '**/*.json' --flat -o jsons/
    uv run apk_peek.py find hoverwatch.apk 'syncvch' --in 'assets/*'
"""
from __future__ import annotations

import argparse
import fnmatch
import sys
import zipfile
from collections import defaultdict
from pathlib import Path


AXML_MAGIC = b"\x03\x00\x08\x00"
DEX_MAGIC = b"dex\n"
ARSC_MAGIC = b"\x02\x00\x0c\x00"


def open_apk(path: Path) -> zipfile.ZipFile:
    if not path.is_file():
        sys.exit(f"[!] Not a file: {path}")
    try:
        return zipfile.ZipFile(path)
    except zipfile.BadZipFile:
        sys.exit(f"[!] Not a valid APK/zip: {path}")


def glob_match(names: list[str], pattern: str | None) -> list[str]:
    """fnmatch + support '**' pour recursion (sur / implicite dans les zips)."""
    if not pattern:
        return names
    # fnmatch ne connait pas '**'. On transforme '**' en '*' repete sur les /.
    # En pratique dans un zip tout est ~ plat donc un seul * couvre deja bien.
    # On gere '**' en faisant 2 passes : '**' -> '*', puis on re-match en
    # autorisant '/' dans '*' via un pattern equivalent.
    if "**" in pattern:
        flat = pattern.replace("**/", "").replace("**", "*")
        return [n for n in names
                if fnmatch.fnmatch(n, pattern.replace("**", "*"))
                or fnmatch.fnmatch(n, flat)
                or fnmatch.fnmatch(Path(n).name, flat)]
    return [n for n in names if fnmatch.fnmatch(n, pattern)]


def fmt_size(n: float) -> str:
    for unit in ("B", "KB", "MB"):
        if n < 1024:
            return f"{n:.1f}{unit}" if unit != "B" else f"{int(n)}{unit}"
        n /= 1024
    return f"{n:.1f}GB"


def detect_binary_kind(data: bytes) -> str | None:
    if data[:4] == AXML_MAGIC:
        return "Binary AXML (compiled XML)"
    if data[:4] == ARSC_MAGIC:
        return "Binary ARSC (compiled resources)"
    if data[:4] == DEX_MAGIC:
        return "Dalvik DEX bytecode"
    if data[:4] == b"PK\x03\x04":
        return "Nested ZIP/APK"
    if data[:2] == b"\x1f\x8b":
        return "Gzip"
    if data[:4] == b"\x89PNG":
        return "PNG image"
    return None


# --- commands -----------------------------------------------------------------
def cmd_info(args):
    with open_apk(args.apk) as zf:
        names = zf.namelist()
        infos = [zf.getinfo(n) for n in names]
        files = [i for i in infos if not i.is_dir()]
        total_size = sum(i.file_size for i in files)
        total_compressed = sum(i.compress_size for i in files)

        by_top: dict[str, list[zipfile.ZipInfo]] = defaultdict(list)
        for i in files:
            top = i.filename.split("/")[0] if "/" in i.filename else "(root)"
            by_top[top].append(i)

    print(f"APK    : {args.apk}")
    print(f"Size   : {fmt_size(args.apk.stat().st_size)} on disk, "
          f"{fmt_size(total_size)} uncompressed "
          f"({(1 - total_compressed/total_size)*100 if total_size else 0:.0f}% saved)")
    print(f"Entries: {len(names)} ({len(files)} files)")
    print()
    print(f"{'Top dir':35s} {'Files':>6s}  {'Size':>12s}")
    for top in sorted(by_top):
        fls = by_top[top]
        total = sum(i.file_size for i in fls)
        print(f"{top:35s} {len(fls):>6d}  {fmt_size(total):>12s}")


def cmd_list(args):
    with open_apk(args.apk) as zf:
        names = glob_match(sorted(zf.namelist()), args.pattern)
        for n in names:
            info = zf.getinfo(n)
            flag = "D" if info.is_dir() else "F"
            print(f"{flag} {info.file_size:>10}  {n}")
    tag = f" matching '{args.pattern}'" if args.pattern else ""
    print(f"\n[*] {len(names)} entries{tag}", file=sys.stderr)


def cmd_cat(args):
    with open_apk(args.apk) as zf:
        try:
            data = zf.read(args.path)
        except KeyError:
            sys.exit(f"[!] Not in APK: {args.path}")

    kind = detect_binary_kind(data)
    if kind:
        print(f"[!] {kind} ({len(data)} bytes). "
              f"Use 'extract' then decode with a dedicated tool "
              f"(JADX-GUI for AXML/ARSC/DEX).", file=sys.stderr)
        sys.exit(3)

    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        try:
            text = data.decode("utf-16")
        except UnicodeDecodeError:
            print(f"[!] Non-text binary file ({len(data)} bytes). "
                  f"Use 'extract' instead.", file=sys.stderr)
            sys.exit(3)

    sys.stdout.write(text)
    if not text.endswith("\n"):
        sys.stdout.write("\n")


def cmd_extract(args):
    with open_apk(args.apk) as zf:
        names = glob_match(sorted(zf.namelist()), args.pattern)
        files = [n for n in names if not zf.getinfo(n).is_dir()]
        if not files:
            sys.exit(f"[!] No file matches '{args.pattern}'")

        out = args.out_dir
        out.mkdir(parents=True, exist_ok=True)

        for n in files:
            data = zf.read(n)
            if args.flat:
                dst = out / Path(n).name
                # si collision en mode flat, on prefixe avec le hash du path
                if dst.exists():
                    import hashlib
                    h = hashlib.md5(n.encode()).hexdigest()[:6]
                    dst = out / f"{h}_{Path(n).name}"
            else:
                dst = out / n
                dst.parent.mkdir(parents=True, exist_ok=True)
            dst.write_bytes(data)
            print(f"[+] {n:60s} -> {dst}  ({fmt_size(len(data))})")

    print(f"\n[*] {len(files)} file(s) extracted to {out}", file=sys.stderr)


def cmd_find(args):
    needle = args.needle.encode() if args.bytes else args.needle
    with open_apk(args.apk) as zf:
        names = glob_match(sorted(zf.namelist()), args.where)
        hits = 0
        for n in names:
            info = zf.getinfo(n)
            if info.is_dir():
                continue
            data = zf.read(n)
            if args.bytes:
                if needle in data:
                    hits += 1
                    print(f"[+] {n} (binary match, {len(data)} bytes)")
                continue
            # Mode texte : on skip les binaires
            if detect_binary_kind(data):
                continue
            try:
                text = data.decode("utf-8", errors="strict")
            except UnicodeDecodeError:
                continue
            matching_lines = [
                (i + 1, line)
                for i, line in enumerate(text.splitlines())
                if needle.lower() in line.lower()
            ] if not args.case_sensitive else [
                (i + 1, line)
                for i, line in enumerate(text.splitlines())
                if needle in line
            ]
            if matching_lines:
                hits += 1
                for lineno, line in matching_lines:
                    truncated = line.strip()[:200]
                    print(f"{n}:{lineno}: {truncated}")
    print(f"\n[*] {hits} file(s) with matches", file=sys.stderr)


# --- main ---------------------------------------------------------------------
def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    sub = ap.add_subparsers(dest="cmd", required=True)

    p_info = sub.add_parser("info", help="APK metadata summary")
    p_info.add_argument("apk", type=Path)
    p_info.set_defaults(func=cmd_info)

    p_list = sub.add_parser("list", help="List APK entries (glob filter)")
    p_list.add_argument("apk", type=Path)
    p_list.add_argument("pattern", nargs="?", default=None,
                        help="Glob pattern (e.g. 'res/xml/*', '*.json')")
    p_list.set_defaults(func=cmd_list)

    p_cat = sub.add_parser("cat", help="Print text content of a file")
    p_cat.add_argument("apk", type=Path)
    p_cat.add_argument("path", help="Exact path inside APK")
    p_cat.set_defaults(func=cmd_cat)

    p_ext = sub.add_parser("extract", help="Extract files by glob")
    p_ext.add_argument("apk", type=Path)
    p_ext.add_argument("pattern", help="Glob pattern (e.g. 'assets/*')")
    p_ext.add_argument("-o", "--out-dir", type=Path, default=Path("extracted"))
    p_ext.add_argument("--flat", action="store_true",
                       help="Put all files flat in out-dir (no nested paths)")
    p_ext.set_defaults(func=cmd_extract)

    p_find = sub.add_parser("find", help="Grep a string in text files")
    p_find.add_argument("apk", type=Path)
    p_find.add_argument("needle", help="String to search for")
    p_find.add_argument("--in", dest="where", default=None,
                        help="Glob of where to search (default: all files)")
    p_find.add_argument("--bytes", action="store_true",
                        help="Search in ALL files as raw bytes (slow)")
    p_find.add_argument("-s", "--case-sensitive", action="store_true")
    p_find.set_defaults(func=cmd_find)

    args = ap.parse_args()
    return args.func(args) or 0


if __name__ == "__main__":
    sys.exit(main())
