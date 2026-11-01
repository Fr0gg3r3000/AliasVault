#!/usr/bin/env python3
"""Copy aliasvault.html into the Android app's assets, pointing it at bundled copies of its two libraries.

    python3 android/prepare_assets.py --download     # fetch the libraries once if vendor/ doesn't have them

The libraries (three.js r128 and qrcode-generator 1.4.4, both MIT) are looked for in vendor/.
If vendor/SHA256SUMS exists, every file is checked against it - commit that file to pin the exact
versions you trust. The app never touches the network at runtime; this script is the only download.
"""
import argparse
import hashlib
import pathlib
import re
import sys
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parent.parent
LIBS = {
    "three.min.js": ("https://cdnjs.cloudflare.com/ajax/libs/three.js/r128/three.min.js", b"THREE"),
    "qrcode.min.js": ("https://cdnjs.cloudflare.com/ajax/libs/qrcode-generator/1.4.4/qrcode.min.js", b"qrcode"),
}
CSP_OLD = "script-src 'unsafe-inline' https://cdnjs.cloudflare.com;"
CSP_NEW = "script-src 'unsafe-inline' 'self';"
THIRD_PARTY = """AliasVault bundles two third-party libraries (both MIT licensed):

  three.js r128            https://threejs.org            (c) three.js authors
  qrcode-generator 1.4.4   https://github.com/kazuhikoarase/qrcode-generator   (c) Kazuhiko Arase

Their licence headers are kept at the top of the bundled files.
"""


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--download", action="store_true", help="download missing libraries from cdnjs")
    ap.add_argument("--vendor", default=str(ROOT / "vendor"))
    ap.add_argument("--html", default=str(ROOT / "aliasvault.html"))
    ap.add_argument("--out", default=str(ROOT / "android/app/src/main/assets"))
    a = ap.parse_args()
    vendor, out = pathlib.Path(a.vendor), pathlib.Path(a.out)
    vendor.mkdir(parents=True, exist_ok=True)

    for name, (url, marker) in LIBS.items():
        path = vendor / name
        if not path.exists():
            if not a.download:
                sys.exit(f"Missing {path}. Put the library there, or run again with --download.")
            print(f"Downloading {url}")
            req = urllib.request.Request(url, headers={"User-Agent": "AliasVault-build"})
            with urllib.request.urlopen(req, timeout=60) as r:
                data = r.read()
            if len(data) < 5000 or marker not in data:
                sys.exit(f"{url} did not return the expected JavaScript.")
            path.write_bytes(data)
        print(f"  {name}  sha256 {sha256(path.read_bytes())}")

    sums = vendor / "SHA256SUMS"
    if sums.exists():
        want = {}
        for line in sums.read_text().splitlines():
            if line.strip() and not line.startswith("#"):
                digest, fname = line.split(None, 1)
                want[fname.strip().lstrip("*")] = digest.lower()
        for name in LIBS:
            if name not in want:
                sys.exit(f"{name} is not listed in {sums}.")
            if sha256((vendor / name).read_bytes()) != want[name]:
                sys.exit(f"{name} does not match {sums} - refusing to build.")
        print("Library checksums match vendor/SHA256SUMS.")
    else:
        print("Note: vendor/SHA256SUMS not found, so the libraries are not pinned.")

    html = pathlib.Path(a.html).read_text(encoding="utf-8")
    for name, (url, _) in LIBS.items():
        tag = f'<script src="{url}"></script>'
        if html.count(tag) != 1:
            sys.exit(f"Expected exactly one {tag} in {a.html}.")
        html = html.replace(tag, f'<script src="lib/{name}"></script>')
    if html.count(CSP_OLD) != 1:
        sys.exit("Could not find the Content-Security-Policy script-src to tighten.")
    html = html.replace(CSP_OLD, CSP_NEW)
    leftovers = re.findall(r"https?://[^\s\"'<>)]+", html)
    if leftovers:
        sys.exit("The page still refers to outside addresses: " + ", ".join(sorted(set(leftovers))))

    (out / "lib").mkdir(parents=True, exist_ok=True)
    (out / "index.html").write_text(html, encoding="utf-8")
    for name in LIBS:
        (out / "lib" / name).write_bytes((vendor / name).read_bytes())
    (out / "THIRD_PARTY.txt").write_text(THIRD_PARTY, encoding="utf-8")
    print(f"Wrote {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
