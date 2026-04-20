#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = [
#     "lief",
# ]
# ///
"""
Hoverwatch / Snoopza — targeted apps extractor (plaintext scan).

Complementaire de decrypt_strings.py : les apps ciblees par le reader a11y /
notifications sont probablement en CLAIR dans les DEX (seuls 3 packages se
retrouvent chiffres via DES). Ce script scanne les strings DEX, filtre les
candidats de forme "package Android", les classe par categorie (messaging,
social, dating, browser, banking, wallet, email, mail, tracker SDK, etc.)
et liste les assets/res/xml/raw de l'APK pour investigation complementaire
(ex: accessibility_service_config.xml peut contenir packageNames=).

Usage:
    uv run list_targets.py <APK> [-o OUT_DIR] [-n NAME]
"""
from __future__ import annotations

import argparse
import re
import sys
import tempfile
import zipfile
from pathlib import Path

import lief


# Prefixes Android / frameworks / SDKs / libs qu'on ignore.
# On garde "com.google.android.youtube" etc. intentionnellement.
_IGNORE = (
    "android.", "androidx.",
    "java.", "javax.", "kotlin.", "kotlinx.",
    "dalvik.", "sun.",
    "com.android.internal.", "com.android.server.", "com.android.vending.",
    "com.google.android.gms.",
    "com.google.android.material.",
    "com.google.common.", "com.google.gson.", "com.google.protobuf.",
    "com.fasterxml.", "com.squareup.", "com.bumptech.glide.",
    "okhttp3.", "okio.", "retrofit2.",
    "org.apache.", "org.json.", "org.xml.", "org.w3c.", "org.xmlpull.",
    "io.reactivex.", "reactor.",
    # Hoverwatch interne
    "com.android.core.mntau",
    "com.utils.", "com.activities.",
    "p053c.", "p082d.", "p092e.", "p094hw.", "hw.",
)

_PKG_RE = re.compile(r"^[a-z][a-z0-9]*(\.[a-z][a-z0-9_]*){1,6}$")


# Catalogue des apps d'intérêt (substring match pour tolerer les variantes).
_CATEGORIES: dict[str, list[str]] = {
    "messaging_im": [
        "whatsapp", "telegram", "org.thunderdog.challegram",
        "viber", "signal", "wire", "threema", "session", "wickr",
        "skype", "line", "kakao", "wechat",
        "tencent.mm", "tencent.mobileqq", "tencent.qqmini",
        "zalo", "kik", "tox", "riot", "element",
        "facebook.orca", "facebook.mlite", "facebook.workchat",
        "instagram.threadsapp", "instagram.barcelona",
        "google.android.apps.messaging", "google.android.talk",
        "google.android.apps.tachyon", "google.android.apps.meetings",
        "google.android.gm.lite",
        "microsoft.teams", "ms.msteams",
        "slack", "discord", "rocketchat", "mattermost",
    ],
    "social": [
        "facebook.katana", "facebook.lite",
        "instagram.android", "instagram.lite",
        "twitter.android", "twitter.lite", "twidere",
        "vkontakte", "reddit", "tiktok", "musically", "zhiliaoapp",
        "pinterest", "tumblr", "bereal", "threads.barcelona",
    ],
    "dating": [
        "tinder", "bumble", "happn", "hinge", "okcupid", "grindr",
        "badoo", "meetic", "pof", "jaumo", "adoptaunmec", "lovoo",
        "feeld", "her", "heybaby", "coffee", "match",
    ],
    "browser": [
        ".chrome", "firefox", "opera.browser", "brave", "duckduckgo",
        "ecosia", "microsoft.emmx", "samsung.android.sbrowser",
        "vivaldi", "kiwibrowser", "sec_browser", "yandex.browser",
        "uc.browser", "ucmobile", "mi.globalbrowser",
    ],
    "email": [
        "google.android.gm", "microsoft.office.outlook",
        "yahoo.mobile.client.android.mail", "proton.android",
        "protonmail", "ch.protonmail", "tutanota",
        "bluemail", "mobileiron.email", "nine.email",
        "k9mail", "fsck.k9", "fairemail",
    ],
    "banking_payment": [
        "paypal", "revolut", "n26", "wise", "lydia",
        "boursorama", "societegenerale", "bnpparibas", "creditagricole",
        "caissedepargne", "fortuneo", "hellobank", "lcl", "bred",
        "cic", "banquepopulaire", "orangebank", "monzo",
    ],
    "crypto_wallet": [
        "metamask", "trustwallet", "coinbase", "binance", "kraken",
        "kucoin", "bitpie", "rabby", "rainbow", "phantom", "solflare",
        "exodus", "mycelium", "bluewallet", "ledger", "safepal",
    ],
    "cloud_storage": [
        "dropbox", "microsoft.skydrive", "google.android.apps.docs",
        "mega.android", "pcloud",
    ],
    "dark": [
        "torproject", "orbot", "guardianproject", "tachiyomi",
    ],
    "vpn": [
        "protonvpn", "nordvpn", "expressvpn", "surfshark", "mullvad",
        "windscribe",
    ],
    "antivirus_security": [
        "kaspersky", "eset", "malwarebytes", "bitdefender", "norton",
        "avast", "avg", "mcafee", "trustlook", "quickheal",
    ],
    "notes_productivity": [
        "evernote", "notion", "onenote", "bear.app", "standardnotes",
        "joplin", "obsidian",
    ],
}


def is_pkg(s: str) -> bool:
    return bool(_PKG_RE.match(s)) and 7 <= len(s) <= 80


def is_ignored(pkg: str) -> bool:
    return any(pkg.startswith(p) or pkg == p.rstrip(".") for p in _IGNORE)


def classify_pkg(pkg: str) -> str | None:
    low = pkg.lower()
    for cat, needles in _CATEGORIES.items():
        for n in needles:
            if n in low:
                return cat
    return None


def extract_dex_strings(apk_path: Path) -> tuple[set[str], list[str]]:
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
                    continue
                for s in dex.strings:
                    v = s if isinstance(s, str) else getattr(s, "value", str(s))
                    if v:
                        strings.add(v)
    return strings, dex_names


def list_resources(apk_path: Path) -> list[tuple[str, int]]:
    items = []
    with zipfile.ZipFile(apk_path) as zf:
        for name in zf.namelist():
            if name.startswith(("assets/", "res/raw/", "res/xml/")):
                items.append((name, zf.getinfo(name).file_size))
    return sorted(items)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("apk", type=Path)
    ap.add_argument("-o", "--out-dir", type=Path, default=Path("."))
    ap.add_argument("-n", "--name", default=None)
    args = ap.parse_args()

    if not args.apk.is_file():
        print(f"[!] Not a file: {args.apk}", file=sys.stderr)
        return 2

    name = args.name or args.apk.stem
    args.out_dir.mkdir(parents=True, exist_ok=True)

    print(f"[*] APK   : {args.apk}")
    strings, dex_names = extract_dex_strings(args.apk)
    print(f"[*] DEX   : {', '.join(dex_names)}")
    print(f"[*] Total unique DEX strings : {len(strings)}")

    candidates = sorted({s for s in strings if is_pkg(s) and not is_ignored(s)})
    print(f"[*] Package candidates (post-filter) : {len(candidates)}")

    by_cat: dict[str, list[str]] = {}
    uncategorized: list[str] = []
    for p in candidates:
        cat = classify_pkg(p)
        if cat:
            by_cat.setdefault(cat, []).append(p)
        else:
            uncategorized.append(p)

    total_targeted = sum(len(v) for v in by_cat.values())
    print(f"[+] Known-category targets : {total_targeted}")
    print(f"[~] Uncategorized candidates : {len(uncategorized)}")

    res_files = list_resources(args.apk)
    print(f"[*] assets/res/raw/xml files : {len(res_files)}")

    md_path = args.out_dir / f"{name}_targets.md"
    lines: list[str] = [
        f"# {name} - Targeted apps (plaintext DEX scan)",
        "",
        f"- APK: `{args.apk}`",
        f"- DEX: {', '.join(f'`{d}`' for d in dex_names)}",
        f"- Total unique DEX strings : **{len(strings)}**",
        f"- Package candidates (filtered) : **{len(candidates)}**",
        f"- Known-category targets : **{total_targeted}**",
        "",
    ]

    for cat in sorted(by_cat):
        items = sorted(by_cat[cat])
        lines.append(f"## `{cat}` ({len(items)})")
        lines.append("")
        for p in items:
            lines.append(f"- `{p}`")
        lines.append("")

    lines += [
        f"## Uncategorized candidates ({len(uncategorized)})",
        "",
        "<details><summary>Click to expand</summary>",
        "",
    ]
    for p in uncategorized:
        lines.append(f"- `{p}`")
    lines += ["", "</details>", ""]

    lines.append(f"## APK assets / res/raw / res/xml ({len(res_files)})")
    lines.append("")
    lines.append("| Path | Size (bytes) |")
    lines.append("|---|---|")
    for path, size in res_files:
        lines.append(f"| `{path}` | {size} |")
    lines.append("")

    md_path.write_text("\n".join(lines), encoding="utf-8")
    print(f"[+] {md_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
