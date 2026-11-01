#!/usr/bin/env python3
"""
AliasVault - a local, account-free organiser for privacy aliases.

* Everything is kept in an encrypted vault (scrypt + AES-256-GCM) behind a master passphrase
* Locks itself after a period of inactivity (default 5 minutes)
* Random alias generator, full-body 3D pixel character, copy/paste export string, QR codes
* No accounts, no server, nothing leaves your computer

Needs Python 3.8+ with Tkinter, plus: pip install -r requirements.txt (cryptography, segno).
Set ALIASVAULT_HOME to keep the vault somewhere else (e.g. a USB stick).
Licence: use it, change it, share it (MIT-style).
"""
import base64
import hashlib
import json
import math
import os
import random
import re
import secrets
import shutil
import tempfile
import time
import tkinter as tk
import unicodedata
import uuid
import zlib
from datetime import date, timedelta
from tkinter import colorchooser, filedialog, messagebox, simpledialog, ttk

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

APP_DIR = os.environ.get("ALIASVAULT_HOME") or os.path.join(os.path.expanduser("~"), ".aliasvault")
VAULT_PATH = os.path.join(APP_DIR, "vault.avault")
LEGACY_PATH = os.path.join(APP_DIR, "aliases.json")  # unencrypted file from versions before the vault
PREFIX = "AV1"
PREFIX_ENC = "AV2"
MAX_IMPORT_BYTES = 5 * 1024 * 1024
KDF_ITERS = 600_000  # PBKDF2 rounds for export strings (same as the web version)

# --------------------------------------------------------------------------
# Field definitions: (key, label, widget kind, tab)
# --------------------------------------------------------------------------
GENDERS = ["", "Male", "Female", "Non-binary"]
SKIN_NAMES = ["Very light", "Light", "Medium", "Tan", "Brown", "Dark"]
OS_LIST = ["Windows 11", "Windows 10", "macOS", "Ubuntu Linux", "Fedora Linux", "Debian Linux",
           "Arch Linux", "ChromeOS", "Other"]
PHONE_LIST = ["iPhone 15", "iPhone 13", "Samsung Galaxy S23", "Samsung Galaxy A54", "Google Pixel 8",
              "Xiaomi 13", "OnePlus 11", "Motorola Moto G", "Fairphone 5", "Other"]
COMBOS = {"gender": GENDERS, "os": OS_LIST, "phone_model": PHONE_LIST, "skin": SKIN_NAMES}

FIELDS = [
    ("alias_label", "Alias label", "entry", "Identity"),
    ("first_name", "First name", "entry", "Identity"),
    ("middle_names", "Middle name(s)", "entry", "Identity"),
    ("last_name", "Last name", "entry", "Identity"),
    ("gender", "Gender", "combo", "Identity"),
    ("dob", "Date of birth (YYYY-MM-DD)", "entry", "Identity"),
    ("country_birth", "Country of birth", "entry", "Identity"),
    ("country_residence", "Country of residence", "entry", "Identity"),
    ("email", "Email", "entry", "Contact"),
    ("password", "Password", "password", "Contact"),
    ("phone", "Phone number", "entry", "Contact"),
    ("os", "Desktop OS", "combo", "Contact"),
    ("phone_model", "Mobile phone", "combo", "Contact"),
    ("hair", "Hair colour", "entry", "Appearance"),
    ("eyes", "Eye colour", "entry", "Appearance"),
    ("skin", "Skin colour", "combo", "Appearance"),
    ("accent", "Accent", "entry", "Appearance"),
    ("languages", "Spoken languages (comma-separated)", "entry", "Background"),
    ("hobbies", "Hobbies (comma-separated)", "entry", "Background"),
    ("certifications", "Certifications (one per line)", "text", "Background"),
    ("employment", "Employment history (one per line)", "text", "Background"),
    ("notes", "Notes (where / why you use this alias)", "text", "Notes"),
]
FIELD_BY_KEY = {k: (label, kind, tab) for k, label, kind, tab in FIELDS}
GEN_FIELDS = [f for f in FIELDS if f[0] not in ("alias_label", "notes")]
TABS = ["Identity", "Contact", "Appearance", "Background", "Notes"]
SIMPLE_KEYS = ["first_name", "last_name", "country_residence", "email", "password"]

DEFAULT_SETTINGS = {"no_passwords": False, "lock_minutes": 5, "email_domain": "example.com",
                    "bg": "#d0143c", "mode": "simple"}

PW_ALPHABET = "abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#$%^&*-_=+?"


def gen_password(n=18):
    return "".join(secrets.choice(PW_ALPHABET) for _ in range(n))


# --------------------------------------------------------------------------
# Encrypted vault
# --------------------------------------------------------------------------
VAULT_AAD = b"AliasVault vault v2"
SCRYPT_N, SCRYPT_R, SCRYPT_P = 2 ** 16, 8, 1  # ~64 MB of memory, a fraction of a second
MIN_PASSPHRASE = 10


class VaultError(Exception):
    pass


def shred(path):
    """Best effort: overwrite with zeros, then delete. (Cannot beat SSD wear levelling or backups.)"""
    try:
        size = os.path.getsize(path)
        with open(path, "r+b") as f:
            f.write(b"\0" * size)
            f.flush()
            os.fsync(f.fileno())
    except OSError:
        pass
    try:
        os.remove(path)
    except OSError:
        pass


class Vault:
    """scrypt-derived key + AES-256-GCM. The key lives only in memory while unlocked."""

    def __init__(self, path=None):
        self.path = path or VAULT_PATH
        self.key = None
        self.salt = None
        self.params = (SCRYPT_N, SCRYPT_R, SCRYPT_P)

    @property
    def unlocked(self):
        return self.key is not None

    def exists(self):
        return os.path.isfile(self.path)

    @staticmethod
    def _derive(passphrase, salt, params):
        n, r, p = params
        return Scrypt(salt=salt, length=32, n=n, r=r, p=p).derive(passphrase.encode("utf-8"))

    def _read(self, passphrase):
        try:
            with open(self.path, encoding="utf-8") as f:
                rec = json.load(f)
            if rec.get("v") != 2 or rec.get("kdf") != "scrypt":
                raise ValueError("format")
            n, r, p = int(rec["n"]), int(rec["r"]), int(rec["p"])
            salt, nonce, ct = (base64.b64decode(rec[k]) for k in ("salt", "nonce", "ct"))
        except (OSError, ValueError, KeyError, TypeError, AttributeError):
            raise VaultError("The vault file is damaged or is not an AliasVault vault.")
        safe = (2 ** 14 <= n <= 2 ** 20 and n & (n - 1) == 0 and 1 <= r <= 16 and 1 <= p <= 4
                and 128 * n * r <= 512 * 1024 * 1024 and len(salt) >= 16 and len(nonce) == 12)
        if not safe:
            raise VaultError("The vault file has unsafe or damaged settings.")
        key = self._derive(passphrase, salt, (n, r, p))
        try:
            plain = AESGCM(key).decrypt(nonce, ct, VAULT_AAD)
        except InvalidTag:
            raise VaultError("Wrong passphrase.")
        try:
            data = json.loads(plain.decode("utf-8"))
        except ValueError:
            raise VaultError("The vault contents are damaged.")
        return key, salt, (n, r, p), data

    def unlock(self, passphrase):
        key, salt, params, data = self._read(passphrase)
        self.key, self.salt, self.params = key, salt, params
        return data

    def create(self, passphrase, data):
        self.salt = os.urandom(16)
        self.params = (SCRYPT_N, SCRYPT_R, SCRYPT_P)
        self.key = self._derive(passphrase, self.salt, self.params)
        self.save(data)

    def save(self, data):
        if self.key is None:
            raise VaultError("The vault is locked.")
        nonce = os.urandom(12)
        ct = AESGCM(self.key).encrypt(nonce, json.dumps(data, ensure_ascii=False).encode("utf-8"), VAULT_AAD)
        n, r, p = self.params
        rec = {"v": 2, "kdf": "scrypt", "n": n, "r": r, "p": p, "salt": base64.b64encode(self.salt).decode(),
               "nonce": base64.b64encode(nonce).decode(), "ct": base64.b64encode(ct).decode()}
        folder = os.path.dirname(self.path)
        os.makedirs(folder, exist_ok=True)
        try:
            os.chmod(folder, 0o700)
        except OSError:
            pass
        fd, tmp = tempfile.mkstemp(dir=folder, suffix=".tmp")  # created 0600
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(rec, f)
                f.flush()
                os.fsync(f.fileno())
            if os.path.exists(self.path):  # keep the last good copy in case something goes wrong
                shutil.copy2(self.path, self.path + ".bak")
                try:
                    os.chmod(self.path + ".bak", 0o600)
                except OSError:
                    pass
            os.replace(tmp, self.path)
        except BaseException:
            try:
                os.remove(tmp)
            except OSError:
                pass
            raise

    def change_passphrase(self, old, new, data):
        try:
            self._read(old)
        except VaultError:
            raise VaultError("Current passphrase is wrong.")
        self.create(new, data)
        shred(self.path + ".bak")  # the backup is still locked with the old passphrase

    def lock(self):
        self.key = None
        self.salt = None

    def erase(self):
        for p in (self.path, self.path + ".bak", LEGACY_PATH):
            shred(p)
        self.lock()


def load_legacy():
    """Read the unencrypted aliases.json from older versions (if any)."""
    try:
        with open(LEGACY_PATH, encoding="utf-8") as f:
            d = json.load(f)
        aliases = [a for a in d.get("aliases", []) if isinstance(a, dict) and a.get("id")]
        return aliases, d.get("settings", {})
    except (OSError, ValueError, AttributeError):
        return None


# --------------------------------------------------------------------------
# Export / import string (same format as the web version)
# --------------------------------------------------------------------------

class _R:
    """Tiny deterministic generator driven by SHA-256 bytes (mirrored in aliasvault.html)."""
    def __init__(self, seed):
        self.d, self.i = hashlib.sha256(seed.encode()).digest(), 0

    def random(self):
        v = self.d[self.i % 32] / 256
        self.i += 1
        return v

    def choice(self, seq):
        return seq[int(self.random() * len(seq))]


def _key(pw, salt):
    return PBKDF2HMAC(hashes.SHA256(), 32, salt, KDF_ITERS).derive(pw.encode("utf-8"))


def encode_aliases(aliases, password=None):
    raw = json.dumps({"v": 1, "aliases": aliases}, separators=(",", ":"),
                     ensure_ascii=False).encode("utf-8")
    data, prefix = zlib.compress(raw, 9), PREFIX
    if password:
        salt, nonce = os.urandom(16), os.urandom(12)
        data = salt + nonce + AESGCM(_key(password, salt)).encrypt(nonce, data, PREFIX_ENC.encode())
        prefix = PREFIX_ENC
    body = base64.urlsafe_b64encode(data).decode("ascii")
    return f"{prefix}-{body}-{zlib.crc32(data) & 0xFFFFFFFF:08x}"


def decode_aliases(text, password=None):
    m = re.fullmatch(r"(AV[12])-(.+)-([0-9a-fA-F]{8})", "".join(text.split()))
    if not m:
        raise ValueError("This doesn't look like an AliasVault export string.")
    prefix, body, crc = m.groups()
    try:
        data = base64.urlsafe_b64decode(body.encode("ascii") + b"=" * (-len(body) % 4))
    except Exception:
        raise ValueError("The string is damaged (bad encoding).")
    if f"{zlib.crc32(data) & 0xFFFFFFFF:08x}" != crc.lower():
        raise ValueError("Checksum mismatch - the string was truncated or altered.")
    if prefix.upper() == PREFIX_ENC:
        if not password:
            raise ValueError("This export is password-protected.")
        try:
            data = AESGCM(_key(password, data[:16])).decrypt(data[16:28], data[28:], PREFIX_ENC.encode())
        except Exception:
            raise ValueError("Wrong password, or the string was altered.")
    d = zlib.decompressobj()
    try:
        raw = d.decompress(data, MAX_IMPORT_BYTES)
    except zlib.error:
        raise ValueError("The string is damaged (bad compression).")
    if d.unconsumed_tail:
        raise ValueError("Export is unreasonably large; refusing to import.")
    out = []
    for a in json.loads(raw.decode("utf-8")).get("aliases", [])[:500]:
        if isinstance(a, dict) and a.get("id"):
            clean = {"id": str(a["id"])[:64]}
            if a.get("look"):
                clean["look"] = str(a["look"])[:64]
            for key, *_ in FIELDS:
                clean[key] = str(a.get(key, ""))[:5000]
            out.append(clean)
    return out


# --------------------------------------------------------------------------
# Random alias generator
# --------------------------------------------------------------------------
COUNTRIES = {
    "United Kingdom": {
        "m": ["Oliver", "George", "Harry", "Jack", "Arthur", "Oscar", "Leo", "Theo"],
        "f": ["Olivia", "Amelia", "Isla", "Grace", "Poppy", "Freya", "Ruby", "Ivy"],
        "l": ["Smith", "Jones", "Taylor", "Brown", "Evans", "Walker", "Hughes", "Wright", "Clarke"],
        "lang": ["English"],
        "acc": ["Southern English", "Northern English", "Scottish", "Welsh", "Midlands", "West Country"]},
    "United States": {
        "m": ["James", "Michael", "Ethan", "Logan", "Mason", "Caleb", "Wyatt", "Owen"],
        "f": ["Emma", "Harper", "Ella", "Chloe", "Lily", "Hannah", "Riley", "Avery"],
        "l": ["Miller", "Davis", "Anderson", "Thompson", "Moore", "Martin", "Jackson", "White", "Lewis"],
        "lang": ["English"],
        "acc": ["General American", "Southern American", "New York", "Midwestern", "Californian"]},
    "Ireland": {
        "m": ["Conor", "Cian", "Seán", "Darragh", "Eoin", "Fionn", "Niall", "Oisín"],
        "f": ["Aoife", "Niamh", "Saoirse", "Roisin", "Ciara", "Orla", "Sinead", "Maeve"],
        "l": ["Murphy", "Kelly", "O'Brien", "Byrne", "Ryan", "Doyle", "Walsh", "Gallagher"],
        "lang": ["English", "Irish"],
        "acc": ["Dublin", "Cork", "Galway", "Northern Irish"]},
    "Canada": {
        "m": ["Liam", "Lucas", "Ethan", "Nathan", "Jacob", "Felix", "Gabriel", "Tyler"],
        "f": ["Emma", "Chloe", "Sophie", "Charlotte", "Zoe", "Léa", "Madison", "Abigail"],
        "l": ["Tremblay", "Roy", "Campbell", "MacDonald", "Gagnon", "Stewart", "Bouchard", "Clark"],
        "lang": ["English", "French"],
        "acc": ["Canadian", "Quebecois", "Maritime"]},
    "Australia": {
        "m": ["Jack", "Noah", "Lachlan", "Cooper", "Mitchell", "Riley", "Hunter", "Flynn"],
        "f": ["Charlotte", "Matilda", "Imogen", "Georgia", "Mia", "Tahlia", "Evie", "Sienna"],
        "l": ["Wilson", "Kelly", "Nguyen", "Campbell", "Murray", "Stewart", "Fraser", "Reid"],
        "lang": ["English"],
        "acc": ["Australian", "Broad Australian", "Cultivated Australian"]},
    "Germany": {
        "m": ["Lukas", "Jonas", "Felix", "Leon", "Maximilian", "Tobias", "Niklas", "Jan"],
        "f": ["Hannah", "Lena", "Mia", "Anna", "Clara", "Johanna", "Laura", "Marie"],
        "l": ["Müller", "Schmidt", "Schneider", "Fischer", "Weber", "Wagner", "Becker", "Hoffmann"],
        "lang": ["German"],
        "acc": ["Standard German", "Bavarian", "Berlin", "Swabian"]},
    "France": {
        "m": ["Louis", "Hugo", "Arthur", "Jules", "Mathis", "Théo", "Lucas", "Antoine"],
        "f": ["Camille", "Chloé", "Manon", "Inès", "Louise", "Juliette", "Élodie", "Margaux"],
        "l": ["Martin", "Bernard", "Dubois", "Moreau", "Laurent", "Lefebvre", "Girard", "Fontaine"],
        "lang": ["French"],
        "acc": ["Parisian", "Southern French", "Lyonnais", "Alsatian"]},
    "Spain": {
        "m": ["Mateo", "Pablo", "Álvaro", "Diego", "Javier", "Adrián", "Hugo", "Iván"],
        "f": ["Lucía", "Paula", "Carmen", "Marta", "Elena", "Sofía", "Irene", "Alba"],
        "l": ["García", "Fernández", "López", "Martínez", "Sánchez", "Romero", "Navarro", "Ortega"],
        "lang": ["Spanish"],
        "acc": ["Castilian", "Andalusian", "Catalan-influenced", "Galician-influenced"]},
    "Italy": {
        "m": ["Leonardo", "Matteo", "Lorenzo", "Alessandro", "Gabriele", "Riccardo", "Tommaso", "Luca"],
        "f": ["Giulia", "Sofia", "Aurora", "Chiara", "Martina", "Alice", "Elisa", "Francesca"],
        "l": ["Rossi", "Russo", "Ferrari", "Esposito", "Bianchi", "Romano", "Colombo", "Ricci"],
        "lang": ["Italian"],
        "acc": ["Roman", "Milanese", "Neapolitan", "Tuscan"]},
    "Netherlands": {
        "m": ["Daan", "Sem", "Finn", "Bram", "Thijs", "Luuk", "Jesse", "Stijn"],
        "f": ["Emma", "Sanne", "Fleur", "Lotte", "Anouk", "Eva", "Femke", "Iris"],
        "l": ["de Jong", "Jansen", "de Vries", "van den Berg", "Bakker", "Visser", "Smit", "Meijer"],
        "lang": ["Dutch"],
        "acc": ["Randstad", "Limburgish", "Frisian-influenced"]},
}
HAIR_COLOURS = ["Black", "Dark brown", "Brown", "Light brown", "Blonde", "Ginger",
                "Auburn", "Grey", "Salt and pepper", "Black", "Brown", "Dark brown"]
EYE_COLOURS = ["Brown", "Brown", "Blue", "Green", "Hazel", "Grey", "Amber", "Dark brown"]
EXTRA_LANGS = ["Spanish", "French", "German", "Italian", "Portuguese", "Polish",
               "Mandarin", "Hindi", "Arabic", "Welsh", "Swedish", "Dutch"]
HOBBIES = ["Hiking", "Photography", "Chess", "Baking", "Cycling", "Gardening", "Reading",
           "Pottery", "Climbing", "Birdwatching", "Board games", "Running", "Fishing",
           "Painting", "Cooking", "Knitting", "Football", "Tennis", "Woodworking",
           "Video games", "Sailing", "Yoga", "Astronomy", "Film club"]
CERTS = ["First Aid at Work", "Food Hygiene Level 2", "PRINCE2 Foundation", "CompTIA A+",
         "Scrum Master (PSM I)", "TEFL Certificate", "AWS Cloud Practitioner",
         "Google Analytics Certification", "Manual Handling", "Level 2 Fitness Instructor"]
JOBS = ["Administrator", "Customer Service Advisor", "Barista", "Warehouse Operative",
        "Junior Analyst", "Sales Assistant", "Delivery Driver", "Receptionist",
        "Project Coordinator", "IT Support Technician", "Content Writer", "Bookkeeper"]
CO_A = ["Harbour", "Northgate", "Bluebell", "Ashford", "Kestrel", "Linden", "Redwood",
        "Summit", "Willow", "Granite", "Foxglove", "Meridian"]
CO_B = ["Logistics", "Solutions", "Foods", "Digital", "Supplies", "Services", "Media",
        "Consulting", "Retail", "Trading"]
CO_C = ["Ltd", "Group", "& Co", "Partners"]


def ascii_slug(s):
    s = unicodedata.normalize("NFKD", s).encode("ascii", "ignore").decode()
    return re.sub(r"[^a-z0-9]", "", s.lower())


def fictional_phone(country, rng):
    if country == "United Kingdom":
        return f"+44 7700 900{rng.randint(100, 999)}"
    if country == "United States":
        return f"+1 202-555-01{rng.randint(0, 99):02d}"
    if country == "Canada":
        return f"+1 613-555-01{rng.randint(0, 99):02d}"
    if country == "Australia":
        return "+61 " + rng.choice(["491 570 156", "491 570 157", "491 570 158", "491 570 159"])
    return ""  # no safe reserved range known; leave blank


def generate_alias(email_domain="example.com"):
    rng = random.SystemRandom()
    born = rng.choice(list(COUNTRIES))
    lives = born if rng.random() < 0.6 else rng.choice(list(COUNTRIES))
    c = COUNTRIES[born]
    gender = rng.choices(GENDERS[1:], [47, 47, 6])[0]
    pool = c["m"] if gender == "Male" else c["f"] if gender == "Female" else c["m"] + c["f"]
    first = rng.choice(pool)
    middles = [m for m in rng.sample(pool, rng.randint(0, 2)) if m != first]
    last = rng.choice(c["l"])

    age_days = rng.randint(21 * 365, 65 * 365)
    dob = date.today() - timedelta(days=age_days)

    langs = [c["lang"][0]]
    if len(c["lang"]) > 1 and rng.random() < 0.4:
        langs.append(c["lang"][1])
    if rng.random() < 0.5:
        langs.append(rng.choice(EXTRA_LANGS))
    langs = list(dict.fromkeys(langs))

    y = dob.year + rng.randint(18, 24)
    now = date.today().year
    jobs = []
    for _ in range(rng.randint(0, 3)):
        if y >= now:
            break
        end = min(now, y + rng.randint(1, 6))
        co = f"{rng.choice(CO_A)} {rng.choice(CO_B)} {rng.choice(CO_C)}"
        jobs.append(f"{rng.choice(JOBS)}, {co} ({y}-{'present' if end == now else end})")
        y = end
    jobs.reverse()

    local = f"{ascii_slug(first)}.{ascii_slug(last)}{rng.randint(10, 99)}"
    return {
        "first_name": first,
        "middle_names": " ".join(middles),
        "last_name": last,
        "gender": gender,
        "dob": dob.isoformat(),
        "country_birth": born,
        "country_residence": lives,
        "email": f"{local}@{email_domain}",
        "phone": fictional_phone(lives, rng),
        "password": gen_password(),
        "os": rng.choice(OS_LIST),
        "phone_model": rng.choice(PHONE_LIST),
        "skin": rng.choice(SKIN_NAMES),
        "hair": rng.choice(HAIR_COLOURS),
        "eyes": rng.choice(EYE_COLOURS),
        "accent": rng.choice(c["acc"]),
        "languages": ", ".join(langs),
        "hobbies": ", ".join(rng.sample(HOBBIES, rng.randint(2, 4))),
        "certifications": "\n".join(rng.sample(CERTS, rng.randint(0, 2))),
        "employment": "\n".join(jobs),
    }



# --------------------------------------------------------------------------
# Pixel character (16x34 grid; same recipe as the web version)
# --------------------------------------------------------------------------
HAIR = {"black": "#1b1b1b", "dark brown": "#3b2417", "light brown": "#8a5a33",
        "brown": "#5a3a22", "blond": "#e0c068", "ginger": "#b5472a", "red": "#a63a22",
        "auburn": "#7a2e1c", "salt": "#7d7d7d", "grey": "#9a9a9a", "gray": "#9a9a9a",
        "silver": "#c4c4c4", "white": "#ececec", "blue": "#3a6fd8", "pink": "#e86fb0",
        "green": "#3fae5a", "purple": "#8a4fd0"}
EYES = {"dark brown": "#2b1a10", "brown": "#5b3a1e", "blue": "#3b82d6", "green": "#3f9d5a",
        "hazel": "#8a6b2f", "grey": "#8b97a3", "gray": "#8b97a3", "amber": "#c98a1b",
        "black": "#0d0d0d"}
SKINS = ["#f6d5b8", "#eebf97", "#d9a273", "#b97c52", "#8d5a3a", "#5e3b26"]
BGS = ["#cfe8ef", "#e6d9f2", "#d9efd3", "#f7e3c4", "#f2d0d0", "#d0d8f2"]
SHIRTS = ["#2f5d8a", "#8a2f4a", "#2f8a5d", "#c47a1e", "#4a4a4a", "#6b3fa0", "#b5372f"]
PANTS = ["#222a44", "#3a3a3a", "#1f4a7a", "#5a3a22", "#6b2f4a"]
SHOES = ["#111111", "#e8e8e8", "#7a1f1f", "#2b2b2b"]
STY = {
    "short": [(5, 2, 10, 2), (4, 3, 11, 3), (4, 4, 4, 5), (11, 4, 11, 5), (5, 4, 10, 4)],
    "buzz": [(5, 2, 10, 2), (4, 3, 11, 3)],
    "bob": [(5, 2, 10, 2), (4, 3, 11, 3), (5, 4, 10, 4), (3, 3, 3, 8), (12, 3, 12, 8), (4, 4, 4, 7), (11, 4, 11, 7)],
    "long": [(5, 2, 10, 2), (4, 3, 11, 3), (5, 4, 10, 4), (3, 3, 3, 12), (12, 3, 12, 12), (4, 4, 4, 10), (11, 4, 11, 10)],
    "curly": [(4, 1, 11, 1), (3, 2, 12, 3), (3, 4, 3, 6), (12, 4, 12, 6), (5, 4, 10, 4)],
    "bald": [],
}
GLASSES = [(5, 5, 7, 5), (8, 5, 10, 5), (5, 7, 7, 7), (8, 7, 10, 7), (5, 6, 5, 6), (7, 6, 8, 6), (10, 6, 10, 6)]


def _colour_from_text(text, table, r):
    t = (text or "").lower()
    for k in sorted(table, key=len, reverse=True):
        if k in t:
            return table[k]
    if t.strip():
        return f"#{zlib.crc32(t.encode()) & 0xFFFFFFFF:08x}"[:7]
    return r.choice(list(table.values()))


def _mix(h, target, f):
    return "#%02x%02x%02x" % tuple(int(int(h[i:i + 2], 16) * (1 - f) + target * f) for i in (1, 3, 5))


def _darken(hexcol, f=0.6):
    h = hexcol.lstrip("#")
    return "#%02x%02x%02x" % tuple(int(int(h[i:i + 2], 16) * f) for i in (0, 2, 4))


def avatar_model(a):
    """Deterministic character from the alias (and its 'look' seed). Returns the pixel grid plus colours."""
    r = _R(str(a.get("look") or a.get("id") or "x"))
    bg, shirt, sk0 = r.choice(BGS), r.choice(SHIRTS), r.choice(SKINS)
    style_roll, beard_roll, glasses_roll = r.random(), r.random(), r.random()
    skin = SKINS[SKIN_NAMES.index(a["skin"])] if a.get("skin") in SKIN_NAMES else sk0
    hair_text = (a.get("hair") or "").lower()
    hair_c = _colour_from_text(hair_text, HAIR, r)
    eye_c = _colour_from_text(a.get("eyes"), EYES, r)

    g = (a.get("gender") or "").strip().lower()
    fem = g.startswith("f") or "woman" in g or "girl" in g
    masc = (g.startswith("m") or "man" in g or "boy" in g) and not fem
    pool = (["long", "bob", "short"] if fem else
            ["short", "short", "buzz", "curly"] if masc else
            ["short", "bob", "buzz", "curly", "long"])
    style = pool[int(style_roll * len(pool))]
    if "bald" in hair_text or "shaved" in hair_text:
        style = "bald"
    pants, shoe = r.choice(PANTS), r.choice(SHOES)

    grid = [[bg] * 16 for _ in range(34)]

    def rect(x0, y0, x1, y1, c):
        for y in range(y0, y1 + 1):
            for x in range(x0, x1 + 1):
                grid[y][x] = c

    rect(4, 12, 11, 12, shirt)                       # shoulders
    rect(3, 13, 12, 21, shirt)                       # torso
    rect(1, 13, 2, 21, shirt); rect(13, 13, 14, 21, shirt)   # sleeves
    rect(1, 22, 2, 23, skin); rect(13, 22, 14, 23, skin)     # hands
    rect(4, 22, 7, 31, pants); rect(8, 22, 11, 31, pants)    # legs
    rect(3, 32, 7, 33, shoe); rect(8, 32, 12, 33, shoe)      # shoes
    rect(6, 11, 9, 11, skin)                         # neck
    rect(4, 4, 11, 9, skin); rect(5, 3, 10, 3, skin); rect(5, 10, 10, 10, skin)   # head
    for box in STY[style]:
        rect(*box, hair_c)
    if masc and beard_roll < 0.3:
        rect(5, 9, 10, 10, hair_c)
    brow = "#555555" if style == "bald" else _darken(hair_c)
    rect(5, 5, 6, 5, brow); rect(9, 5, 10, 5, brow)
    rect(6, 6, 6, 6, eye_c); rect(9, 6, 9, 6, eye_c)
    rect(7, 9, 8, 9, "#8a3b3b")                      # mouth
    if glasses_roll < 0.3:
        for box in GLASSES:
            rect(*box, "#222222")
    return {"G": grid, "bg": bg, "hc": hair_c, "skin": skin, "bald": style == "bald"}


def _photo_from_rows(rows, scale):
    img = tk.PhotoImage(width=len(rows[0]), height=len(rows))
    for y, row in enumerate(rows):
        img.put("{" + " ".join(row) + "}", to=(0, y))
    return img.zoom(scale, scale)


def make_head_photo(m, scale=12):
    return _photo_from_rows([row[2:14] for row in m["G"][:13]], scale)


def make_full_photo(m, scale=12):
    return _photo_from_rows(m["G"], scale)


# --------------------------------------------------------------------------
# 3D voxel model (software renderer on a Tk canvas - no extra libraries)
# --------------------------------------------------------------------------
def _quad_faces():
    out = []
    for ax in range(3):
        for sg in (-1, 1):
            d = [0, 0, 0]
            d[ax] = sg
            u, v = [i for i in range(3) if i != ax]
            quad = []
            for p_, q_ in ((-1, -1), (1, -1), (1, 1), (-1, 1)):
                p = [0, 0, 0]
                p[ax], p[u], p[v] = sg * .5, p_ * .5, q_ * .5
                quad.append(tuple(p))
            out.append((tuple(d), quad))
    return out


FACE_DIRS = _quad_faces()


def build_faces(m):
    """Extrude the 16x34 character into a voxel figure; return its visible surface faces."""
    grid, bg = m["G"], m["bg"]
    back = m["skin"] if m["bald"] else m["hc"]
    vox = {}
    for y, row in enumerate(grid):
        for x, c in enumerate(row):
            if c == bg:
                continue
            for z in range(6 if y <= 10 else 3 if (x < 3 or x > 12) else 4):
                col = back if (z >= 2 and y <= 10) else c
                vox[(x, -y, -z)] = tuple(int(col[i:i + 2], 16) for i in (1, 3, 5))
    faces = []
    for (X, Y, Z), c in vox.items():
        for d, quad in FACE_DIRS:
            if (X + d[0], Y + d[1], Z + d[2]) not in vox:
                faces.append((d, [(X - 7.5 + p[0], Y + 16.5 + p[1], Z + 3 + p[2]) for p in quad], c))
    return faces


CW, CH, SC = 260, 340, 9  # 3D canvas size and pixels per voxel


def display_name(a):
    return (a.get("alias_label")
            or " ".join(x for x in (a.get("first_name"), a.get("last_name")) if x)
            or "(unnamed)")


def strength_hint(p):
    n = len(p)
    return ("Too short - use at least %d characters." % MIN_PASSPHRASE if n < MIN_PASSPHRASE else
            "OK - longer is better." if n < 14 else "Good." if n < 20 else "Strong.")


# --------------------------------------------------------------------------
# GUI
# --------------------------------------------------------------------------
class GenDialog(tk.Toplevel):
    def __init__(self, parent, domain, bg):
        super().__init__(parent)
        self.title("Generate alias")
        self.configure(bg=bg)
        self.transient(parent)
        self.result = None
        pad = ttk.Frame(self, padding=14)
        pad.pack(fill="both", expand=True)
        ttk.Label(pad, text="Tick the fields to fill with random data.\n"
                            "Unticked fields keep their current value.").grid(
            row=0, column=0, columnspan=2, pady=(0, 8), sticky="w")
        self.vars = {}
        for i, (key, label, *_) in enumerate(GEN_FIELDS):
            v = tk.BooleanVar(value=True)
            self.vars[key] = v
            ttk.Checkbutton(pad, text=label.split(" (")[0], variable=v).grid(
                row=1 + i // 2, column=i % 2, sticky="w", padx=(0, 16), pady=1)
        row = 2 + (len(GEN_FIELDS) + 1) // 2
        ttk.Label(pad, text="Email domain:").grid(row=row, column=0, sticky="e", pady=8)
        self.domain = tk.StringVar(value=domain)
        ttk.Entry(pad, textvariable=self.domain, width=26).grid(row=row, column=1, sticky="w")
        bf = ttk.Frame(pad)
        bf.grid(row=row + 1, column=0, columnspan=2, pady=(10, 0))
        ttk.Button(bf, text="Generate", command=self.ok).pack(side="left", padx=6)
        ttk.Button(bf, text="Cancel", command=self.destroy).pack(side="left", padx=6)
        self.grab_set()

    def ok(self):
        self.result = ({k for k, v in self.vars.items() if v.get()},
                       self.domain.get().strip() or "example.com")
        self.destroy()


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("AliasVault")
        self.minsize(980, 660)
        self.vault = Vault()
        self.db = None
        self.current = None
        self.locked = True
        self.settings = dict(DEFAULT_SETTINGS)
        self.mode = "simple"
        self.faces = []
        self.ry, self.rx, self.spin, self._last, self.dirty = 0.5, 0.15, True, None, True
        self.fields_adv, self.fields_simple = {}, {}
        self.fields = self.fields_simple
        self.pw_entries, self.text_widgets = [], []
        self.head_img = None
        self.model = None
        self.last_active = time.time()
        self.fails = 0
        self.lmode = "create"
        self._job = self._clip_job = self._reveal_job = self._flash_job = self._cool_job = None
        self._clip = None
        self._c = {}
        self._style = ttk.Style(self)
        try:
            self._style.theme_use("clam")
        except tk.TclError:
            pass
        self._build_main()
        self._build_lock()
        self.apply_theme()
        self.protocol("WM_DELETE_WINDOW", self.on_close)
        for seq in ("<Motion>", "<Key>", "<Button>", "<MouseWheel>"):
            self.bind_all(seq, self.touch, add="+")
        self.after(5000, self.check_idle)
        self.after(60, self.tick)
        self.show_lock()

    # ------------------------------------------------------------ layout
    def _build_main(self):
        self.main = ttk.Frame(self, padding=10)
        head = ttk.Frame(self.main)
        head.pack(fill="x", pady=(0, 8))
        ttk.Label(head, text="✦ AliasVault ✦", style="Title.TLabel").pack(side="left")
        self.mode_var = tk.StringVar(value="simple")
        for text, val in (("Simple", "simple"), ("Advanced", "adv")):
            ttk.Radiobutton(head, text=text, value=val, variable=self.mode_var, style="Toolbutton",
                            command=lambda: self.set_mode(self.mode_var.get())).pack(side="left", padx=(12, 0))
        ttk.Button(head, text="🔒 Lock now", command=lambda: self.lock("Locked.")).pack(side="right")
        ttk.Button(head, text="🛡 Security", command=self.show_security).pack(side="right", padx=6)

        body = ttk.Frame(self.main)
        body.pack(fill="both", expand=True)
        body.columnconfigure(1, weight=1)
        body.rowconfigure(0, weight=1)

        left = ttk.Frame(body)
        left.grid(row=0, column=0, sticky="ns", padx=(0, 10))
        self.lb = tk.Listbox(left, width=24, exportselection=False, relief="flat", highlightthickness=1)
        self.lb.pack(fill="both", expand=True)
        self.lb.bind("<<ListboxSelect>>", self.on_select)
        ttk.Button(left, text="New alias", command=self.new_alias).pack(fill="x", pady=(6, 0))
        ttk.Button(left, text="Delete alias", command=self.delete_alias).pack(fill="x", pady=(4, 0))

        self.center = ttk.Frame(body)
        self.center.grid(row=0, column=1, sticky="nsew")
        self.center.columnconfigure(0, weight=1)
        self.center.rowconfigure(0, weight=1)

        self.nb = ttk.Notebook(self.center)           # advanced: every field
        frames = {}
        for t in TABS:
            f = ttk.Frame(self.nb, padding=10)
            f.columnconfigure(1, weight=1)
            self.nb.add(f, text=t)
            frames[t] = f
        rows = {t: 0 for t in TABS}
        for key, label, kind, tab in FIELDS:
            self._field(frames[tab], rows[tab], key, label, kind, self.fields_adv)
            rows[tab] += 1

        self.simple = ttk.Frame(self.center, padding=14)  # simple: just the essentials
        self.simple.columnconfigure(1, weight=1)
        ttk.Label(self.simple, text="Quick alias", style="Head.TLabel").grid(row=0, column=0, columnspan=2,
                                                                          sticky="w", pady=(0, 8))
        for i, key in enumerate(SIMPLE_KEYS):
            label, kind, _ = FIELD_BY_KEY[key]
            self._field(self.simple, i + 1, key, label, kind, self.fields_simple)

        right = ttk.Frame(body)
        right.grid(row=0, column=2, sticky="n", padx=(10, 0))
        common = ttk.Frame(right)
        common.pack(side="bottom", fill="x", pady=(8, 0))
        ttk.Button(common, text="Re-roll look", command=self.reroll_look).pack(fill="x")

        self.adv_right = ttk.Frame(right)
        self.cv3 = tk.Canvas(self.adv_right, width=CW, height=CH, highlightthickness=2)
        self.cv3.pack()
        self.cv3.bind("<ButtonPress-1>", self._drag_start)
        self.cv3.bind("<B1-Motion>", self._drag)
        self.cv3.bind("<ButtonRelease-1>", lambda e: setattr(self, "_last", None))
        ttk.Button(self.adv_right, text="Auto-spin on/off", command=self.toggle_spin).pack(fill="x", pady=(8, 0))
        ttk.Button(self.adv_right, text="Background colour…", command=self.pick_bg).pack(fill="x", pady=(4, 0))
        ttk.Button(self.adv_right, text="Save character PNG…", command=self.save_png).pack(fill="x", pady=(4, 0))

        self.simple_right = ttk.Frame(right)
        self.head_lbl = ttk.Label(self.simple_right)
        self.head_lbl.pack(padx=4, pady=4)

        bar = ttk.Frame(self.main)
        bar.pack(fill="x", pady=(10, 0))
        for text, cmd in [("Generate…", self.generate), ("Save", self.commit_and_refresh_list),
                          ("Export selected", lambda: self.show_export("one")),
                          ("Export all", lambda: self.show_export("all")),
                          ("Import…", self.show_import)]:
            ttk.Button(bar, text=text, command=cmd).pack(side="left", padx=(0, 6))
        self.status = ttk.Label(bar, text="", style="Small.TLabel")
        self.status.pack(side="right")

        self.simple.grid(row=0, column=0, sticky="nsew")   # start in simple mode
        self.simple_right.pack(side="top")

    def _field(self, parent, row, key, label, kind, store):
        ttk.Label(parent, text=label).grid(row=row, column=0, sticky="nw", pady=4, padx=(0, 10))
        if kind == "text":
            w = tk.Text(parent, height=6, width=40, wrap="word", relief="flat")
            self.text_widgets.append(w)
            w.grid(row=row, column=1, sticky="ew", pady=4)
        elif kind == "combo":
            w = ttk.Combobox(parent, values=COMBOS[key])
            w.grid(row=row, column=1, sticky="ew", pady=4)
            w.bind("<<ComboboxSelected>>", self.on_edit)
        elif kind == "password":
            holder = ttk.Frame(parent)
            holder.columnconfigure(0, weight=1)
            holder.grid(row=row, column=1, sticky="ew", pady=4)
            w = ttk.Entry(holder, show="•")
            w.grid(row=0, column=0, sticky="ew")
            show_btn = ttk.Button(holder, text="Show", width=6)
            show_btn.configure(command=lambda e=w, b=show_btn: self.toggle_reveal(e, b))
            show_btn.grid(row=0, column=1, padx=(6, 0))
            ttk.Button(holder, text="Copy", width=6,
                       command=lambda e=w: self.copy_password(e)).grid(row=0, column=2, padx=(4, 0))
            ttk.Button(holder, text="🎲 New", width=7,
                       command=lambda e=w: self.new_password(e)).grid(row=0, column=3, padx=(4, 0))
            self.pw_entries.append((w, show_btn))
        else:
            w = ttk.Entry(parent)
            w.grid(row=row, column=1, sticky="ew", pady=4)
        w.bind("<KeyRelease>", self.on_edit)
        store[key] = (w, kind)

    def _build_lock(self):
        self.lockf = ttk.Frame(self)
        box = ttk.Frame(self.lockf, padding=24)
        box.place(relx=0.5, rely=0.5, anchor="center")
        ttk.Label(box, text="✦ AliasVault ✦", style="Title.TLabel").pack()
        self.lock_msg = ttk.Label(box, wraplength=360, style="Small.TLabel", justify="center")
        self.lock_msg.pack(pady=10)
        ttk.Label(box, text="Passphrase").pack(anchor="w")
        self.e1 = ttk.Entry(box, show="•", width=40)
        self.e1.pack(fill="x")
        self.e2_box = ttk.Frame(box)
        ttk.Label(self.e2_box, text="Confirm passphrase").pack(anchor="w")
        self.e2 = ttk.Entry(self.e2_box, show="•", width=40)
        self.e2.pack(fill="x")
        self.lock_strength = ttk.Label(box, style="Small.TLabel")
        self.lock_strength.pack(anchor="w", pady=(6, 0))
        self.lock_err = ttk.Label(box, style="Err.TLabel", wraplength=360)
        self.lock_err.pack(anchor="w", pady=4)
        btns = ttk.Frame(box)
        btns.pack(pady=(4, 0))
        self.lock_btn = ttk.Button(btns, text="Unlock", command=self.submit_lock)
        self.lock_btn.pack(side="left")
        self.erase_btn = ttk.Button(btns, text="Erase vault…", command=self.erase_from_lock)
        for e in (self.e1, self.e2):
            e.bind("<Return>", lambda ev: self.submit_lock())
        self.e1.bind("<KeyRelease>", lambda ev: self.lock_strength.configure(
            text=strength_hint(self.e1.get()) if self.lmode == "create" else ""))

    # ------------------------------------------------------------ theme
    def apply_theme(self):
        base = self.settings.get("bg", "#d0143c")
        try:
            c = {"base": base, "bg": _mix(base, 0, .93), "panel": _mix(base, 0, .84),
                 "glow": _mix(base, 255, .3), "fg": "#ffe9ee", "btn": _mix(base, 0, .25),
                 "btn2": _mix(base, 255, .1), "field": "#f4f4f4"}
        except ValueError:
            c = {"base": "#d0143c", "bg": "#0e0206", "panel": "#220610", "glow": "#e06a85",
                 "fg": "#ffe9ee", "btn": "#9e0f2d", "btn2": "#d63a5c", "field": "#f4f4f4"}
        self._c = c
        self.configure(bg=c["bg"])
        s = self._style
        s.configure(".", background=c["bg"], foreground=c["fg"], bordercolor=c["glow"],
                    lightcolor=c["panel"], darkcolor=c["panel"], troughcolor=c["panel"],
                    fieldbackground=c["field"], selectbackground=c["base"])
        s.configure("TFrame", background=c["bg"])
        s.configure("TLabel", background=c["bg"], foreground=c["fg"])
        s.configure("Title.TLabel", font=("Georgia", 22, "italic bold"), foreground=c["glow"])
        s.configure("Head.TLabel", font=("TkDefaultFont", 13, "bold"), foreground=c["glow"])
        s.configure("Small.TLabel", font=("TkDefaultFont", 9), foreground=c["fg"])
        s.configure("Err.TLabel", foreground="#ffb3c1")
        s.configure("TButton", background=c["btn"], foreground="white", bordercolor=c["glow"],
                    padding=(10, 4), focuscolor=c["glow"])
        s.map("TButton", background=[("active", c["btn2"]), ("disabled", "#444444")],
              foreground=[("disabled", "#999999")])
        s.configure("Toolbutton", background=c["panel"], foreground=c["fg"], bordercolor=c["glow"], padding=(10, 4))
        s.map("Toolbutton", background=[("selected", c["base"]), ("active", c["btn2"])],
              foreground=[("selected", "white")])
        s.configure("TNotebook", background=c["bg"], bordercolor=c["glow"])
        s.configure("TNotebook.Tab", background=c["panel"], foreground=c["fg"], padding=(12, 5))
        s.map("TNotebook.Tab", background=[("selected", c["base"])], foreground=[("selected", "white")])
        s.configure("TCheckbutton", background=c["bg"], foreground=c["fg"])
        s.configure("TRadiobutton", background=c["bg"], foreground=c["fg"])
        s.configure("TEntry", fieldbackground=c["field"], foreground="#111111")
        s.configure("TCombobox", fieldbackground=c["field"], foreground="#111111", background=c["btn"])
        s.configure("TSeparator", background=c["glow"])
        self.lb.configure(bg=c["panel"], fg=c["fg"], selectbackground=c["base"], selectforeground="white",
                          highlightbackground=c["glow"], highlightcolor=c["glow"])
        for t in self.text_widgets:
            t.configure(bg=c["field"], fg="#111111", insertbackground="#111111")
        self.draw_bg()
        self.dirty = True

    def draw_bg(self):
        cv, c = self.cv3, self._c
        cv.delete("bg")
        cv.configure(highlightbackground=c["glow"], highlightcolor=c["glow"], bg=c["bg"])
        for i in range(34):
            cv.create_rectangle(0, i * 10, CW, i * 10 + 10, outline="", tags="bg",
                                fill=_mix(_mix(c["base"], 255, .2), 0, .85 * i / 33))
        dot = _mix(c["base"], 255, .25)
        for gx in range(7, CW, 14):                       # halftone dots, like the wallpapers
            for gy in range(7, CH // 2, 14):
                cv.create_oval(gx - 1.5, gy - 1.5, gx + 1.5, gy + 1.5, fill=dot, outline="", tags="bg")
        for x, y, s in ((40, 52, 10), (214, 96, 7), (205, 300, 9), (52, 268, 6), (130, 22, 5)):   # sparkles
            cv.create_polygon(x, y - s, x + s * .25, y - s * .25, x + s, y, x + s * .25, y + s * .25,
                              x, y + s, x - s * .25, y + s * .25, x - s, y, x - s * .25, y - s * .25,
                              fill="white", outline="", tags="bg")
        cv.tag_lower("bg")

    def pick_bg(self):
        col = colorchooser.askcolor(color=self.settings.get("bg", "#d0143c"), parent=self)[1]
        if col and self.db is not None:
            self.settings["bg"] = col
            self.apply_theme()
            self.persist()

    def _toplevel(self, title):
        win = tk.Toplevel(self)
        win.title(title)
        win.configure(bg=self._c.get("bg", "#0e0206"))
        win.transient(self)
        return win

    def flash(self, msg):
        self.status.configure(text=msg)
        if self._flash_job:
            self.after_cancel(self._flash_job)
        self._flash_job = self.after(4000, lambda: self.status.configure(text=""))

    # ------------------------------------------------------------ vault / persistence
    def _vault_data(self):
        aliases = []
        for a in self.db["aliases"]:
            b = dict(a)
            if self.settings.get("no_passwords"):
                b.pop("password", None)
            aliases.append(b)
        return {"aliases": aliases, "settings": self.settings}

    def persist(self):
        if self.db is None or not self.vault.unlocked:
            return
        try:
            self.vault.save(self._vault_data())
        except (OSError, VaultError) as e:
            self.flash("Could not save: %s" % e)

    def show_lock(self, msg=""):
        self.locked = True
        self.main.pack_forget()
        self.lmode = "unlock" if self.vault.exists() else "create"
        for e in (self.e1, self.e2):
            e.delete(0, "end")
        self.lock_err.configure(text="")
        self.lock_strength.configure(text="")
        if self.lmode == "create":
            self.e2_box.pack(before=self.lock_strength, fill="x", pady=(6, 0))
            self.erase_btn.pack_forget()
            default = ("Found unencrypted aliases from an earlier version. Choose a passphrase to encrypt them."
                       if load_legacy() else
                       "Choose a master passphrase. It encrypts everything AliasVault stores. There is no "
                       "recovery: if you forget it, the data is gone. Four or five random words make a good passphrase.")
        else:
            self.e2_box.pack_forget()
            self.erase_btn.pack(side="left", padx=(8, 0))
            default = "Enter your passphrase to unlock."
        self.lock_msg.configure(text=msg or default)
        self.lock_btn.configure(text="Create vault" if self.lmode == "create" else "Unlock",
                                state="disabled" if self._cool_job else "normal")
        self.lockf.pack(fill="both", expand=True)
        self.e1.focus_set()

    def submit_lock(self):
        if self._cool_job:
            return
        pw = self.e1.get()
        self.lock_err.configure(text="")
        self.lock_btn.configure(state="disabled", text="Working…")
        self.update_idletasks()
        try:
            if self.lmode == "create":
                if len(pw) < MIN_PASSPHRASE:
                    raise VaultError("Use at least %d characters." % MIN_PASSPHRASE)
                if pw != self.e2.get():
                    raise VaultError("The two passphrases do not match.")
                legacy = load_legacy()
                data = {"aliases": legacy[0] if legacy else [],
                        "settings": {**DEFAULT_SETTINGS, **{k: v for k, v in (legacy[1] if legacy else {}).items()
                                                            if k in DEFAULT_SETTINGS}}}
                self.vault.create(pw, data)
                if legacy:
                    shred(LEGACY_PATH)       # the unencrypted copy is no longer needed
            else:
                if not pw:
                    raise VaultError("Enter your passphrase.")
                data = self.vault.unlock(pw)
        except (VaultError, OSError) as e:
            self.vault.lock()
            self.lock_err.configure(text=str(e))
            if self.lmode == "unlock":
                self.fails += 1
                self._cooldown(min(2 ** (self.fails - 1), 30))
            else:
                self.lock_btn.configure(state="normal", text="Create vault")
            return
        self.fails = 0
        self.e1.delete(0, "end")
        self.e2.delete(0, "end")
        self.start_session(data)

    def _cooldown(self, n):
        if n <= 0:
            self._cool_job = None
            self.lock_btn.configure(text="Unlock", state="normal")
            return
        self.lock_btn.configure(text="Try again in %ds" % n, state="disabled")
        self._cool_job = self.after(1000, lambda: self._cooldown(n - 1))

    def start_session(self, data):
        aliases = [dict(a) for a in data.get("aliases", []) if isinstance(a, dict) and a.get("id")]
        settings = {**DEFAULT_SETTINGS, **{k: v for k, v in data.get("settings", {}).items() if k in DEFAULT_SETTINGS}}
        self.db = {"aliases": aliases, "settings": settings}
        self.settings = settings
        self.locked = False
        self.lockf.pack_forget()
        self.main.pack(fill="both", expand=True)
        self.apply_theme()
        self.set_mode(settings["mode"] if settings["mode"] in ("simple", "adv") else "simple", save=False)
        self.current = aliases[0] if aliases else None
        self.last_active = time.time()
        if self.current is None:
            self.new_alias()
        else:
            self.refresh_list()
            self.load_form()
        self.persist()   # also encrypts a migrated legacy file straight away

    def lock(self, msg="Locked."):
        if self.locked:
            return
        try:
            self.commit()
        except Exception:
            pass
        if self._job:
            self.after_cancel(self._job)
            self._job = None
        for w in list(self.winfo_children()):
            if isinstance(w, tk.Toplevel):
                w.destroy()
        self.clear_clip()
        self.vault.lock()
        self.db, self.current, self.faces = None, None, []
        self.settings = dict(DEFAULT_SETTINGS)
        self._wipe()
        self.apply_theme()
        self.show_lock(msg)

    def _wipe(self):
        for store in (self.fields_adv, self.fields_simple):
            self._set_store(store, {})
        for entry, btn in self.pw_entries:
            entry.configure(show="•")
            btn.configure(text="Show")
        self.lb.delete(0, "end")
        self.cv3.delete("fg")
        self.head_img = None
        self.head_lbl.configure(image="")

    def erase_from_lock(self):
        if messagebox.askyesno("Erase vault", "Erase the vault and ALL aliases on this computer? "
                                              "This cannot be undone.", parent=self):
            self.vault.erase()
            self.fails = 0
            self.show_lock("Vault erased. Choose a new passphrase to start again.")

    def erase_everything(self):
        self.vault.erase()
        self.db, self.current, self.faces = None, None, []
        for w in list(self.winfo_children()):
            if isinstance(w, tk.Toplevel):
                w.destroy()
        self._wipe()
        self.show_lock("Vault erased. Choose a new passphrase to start again.")

    def touch(self, _e=None):
        self.last_active = time.time()

    def check_idle(self):
        mins = self.settings.get("lock_minutes", 5)
        if not self.locked and time.time() - self.last_active > mins * 60:
            self.lock("Locked after %d minute%s of inactivity." % (mins, "" if mins == 1 else "s"))
        self.after(5000, self.check_idle)

    # ------------------------------------------------------------ form helpers
    def _read_store(self, store):
        out = {}
        for key, (w, kind) in store.items():
            v = w.get("1.0", "end-1c") if kind == "text" else w.get()
            out[key] = v if key == "password" else v.strip()
        return out

    def _set_store(self, store, data):
        for key, (w, kind) in store.items():
            v = data.get(key, "")
            if kind == "text":
                w.delete("1.0", "end")
                w.insert("1.0", v)
            else:
                w.delete(0, "end")
                w.insert(0, v)

    def get_form(self):
        return self._read_store(self.fields)

    def set_form(self, data):
        self._set_store(self.fields, data)

    def load_form(self):
        if self.current is not None:
            self.set_form(self.current)
            self.hide_passwords()
            self.refresh_avatar()

    def commit(self):
        if self.db is None or self.current is None:
            return
        self.current.update(self.get_form())
        self.persist()

    def commit_and_refresh_list(self):
        self._job = None
        if self.db is None:
            return
        self.commit()
        self.refresh_list()

    def cur_index(self):
        for i, a in enumerate(self.db["aliases"] if self.db else []):
            if a is self.current:
                return i
        return None

    def refresh_list(self):
        idx = self.cur_index()
        self.lb.delete(0, "end")
        for a in self.db["aliases"]:
            self.lb.insert("end", display_name(a))
        if idx is not None:
            self.lb.selection_set(idx)
            self.lb.see(idx)

    def refresh_avatar(self):
        if self.current is None:
            return
        data = dict(self.current)
        data.update(self.get_form())
        m = avatar_model(data)
        self.model = m
        self.head_img = make_head_photo(m, 12)
        self.head_lbl.configure(image=self.head_img)
        if self.mode == "adv":
            self.faces = build_faces(m)
            self.dirty = True

    # ------------------------------------------------------------ password helpers
    def toggle_reveal(self, entry, btn):
        self.set_reveal(entry.cget("show") != "")

    def set_reveal(self, on):
        for entry, btn in self.pw_entries:
            entry.configure(show="" if on else "•")
            btn.configure(text="Hide" if on else "Show")
        if self._reveal_job:
            self.after_cancel(self._reveal_job)
            self._reveal_job = None
        if on:
            self._reveal_job = self.after(15000, lambda: self.set_reveal(False))

    def hide_passwords(self):
        self.set_reveal(False)

    def new_password(self, entry):
        entry.delete(0, "end")
        entry.insert(0, gen_password())
        self.on_edit()
        self.set_reveal(True)

    def copy_password(self, entry):
        v = entry.get()
        if not v:
            self.flash("No password to copy")
            return
        self.clipboard_clear()
        self.clipboard_append(v)
        self._clip = v
        if self._clip_job:
            self.after_cancel(self._clip_job)
        self._clip_job = self.after(30000, self.clear_clip)
        self.flash("Copied - the clipboard clears in 30 seconds")

    def clear_clip(self):
        if self._clip_job:
            self.after_cancel(self._clip_job)
            self._clip_job = None
        if self._clip is None:
            return
        v, self._clip = self._clip, None
        try:
            now = self.clipboard_get()
        except tk.TclError:
            now = None
        if now == v:
            self.clipboard_clear()

    # ------------------------------------------------------------ events
    def set_mode(self, mode, save=True):
        if self.db is not None:
            self.commit()
        self.mode = mode
        self.mode_var.set(mode)
        if mode == "adv":
            self.simple.grid_remove()
            self.nb.grid(row=0, column=0, sticky="nsew")
            self.simple_right.pack_forget()
            self.adv_right.pack(side="top")
            self.fields = self.fields_adv
        else:
            self.nb.grid_remove()
            self.simple.grid(row=0, column=0, sticky="nsew")
            self.adv_right.pack_forget()
            self.simple_right.pack(side="top")
            self.fields = self.fields_simple
        if self.db is not None:
            self.settings["mode"] = mode
            self.load_form()
            if save:
                self.persist()

    def on_edit(self, _=None):
        if self.db is None:
            return
        self.refresh_avatar()
        if self._job:
            self.after_cancel(self._job)
        self._job = self.after(1000, self.commit_and_refresh_list)

    def on_select(self, _=None):
        sel = self.lb.curselection()
        if not sel or self.db is None:
            return
        self.commit()
        self.current = self.db["aliases"][sel[0]]
        self.load_form()
        self.refresh_list()

    def on_close(self):
        try:
            self.commit()
        except Exception:
            pass
        self.clear_clip()
        self.destroy()

    # ------------------------------------------------------------ 3D view
    def toggle_spin(self):
        self.spin = not self.spin

    def _drag_start(self, e):
        self._last = (e.x, e.y)

    def _drag(self, e):
        if self._last:
            self.ry += (e.x - self._last[0]) * 0.02
            self.rx = max(-1.2, min(1.2, self.rx + (e.y - self._last[1]) * 0.02))
            self._last = (e.x, e.y)
            self.dirty = True

    def tick(self):
        if not self.locked and self.mode == "adv":
            if self.spin and not self._last:
                self.ry += 0.04
                self.dirty = True
            if self.dirty:
                self.dirty = False
                self.draw3d()
        self.after(60, self.tick)

    def draw3d(self):
        cv = self.cv3
        cv.delete("fg")
        cy, sy, cx, sx = math.cos(self.ry), math.sin(self.ry), math.cos(self.rx), math.sin(self.rx)

        def rot(v):
            x, y, z = v
            x, z = x * cy + z * sy, -x * sy + z * cy
            return x, y * cx - z * sx, y * sx + z * cx

        items = []
        for d, quad, c in self.faces:
            n = rot(d)
            if n[2] > 0:  # facing the viewer
                pts = [rot(p) for p in quad]
                items.append((sum(p[2] for p in pts), n, pts, c))
        items.sort(key=lambda t: t[0])
        for _, n, pts, c in items:
            k = 0.45 + 0.55 * max(0.0, -0.3 * n[0] + 0.5 * n[1] + 0.8 * n[2])
            col = "#%02x%02x%02x" % tuple(min(255, int(v * k)) for v in c)
            cv.create_polygon([v for p in pts for v in (CW / 2 + p[0] * SC, CH / 2 - p[1] * SC)],
                              fill=col, outline=col, tags="fg")

    # ------------------------------------------------------------ actions
    def new_alias(self):
        self.commit()
        a = {"id": uuid.uuid4().hex}
        self.db["aliases"].append(a)
        self.current = a
        self.persist()
        self.set_form({})
        self.hide_passwords()
        self.refresh_list()
        self.refresh_avatar()

    def delete_alias(self):
        idx = self.cur_index()
        if idx is None or not messagebox.askyesno("Delete", "Delete '%s'?" % display_name(self.current)):
            return
        del self.db["aliases"][idx]
        if not self.db["aliases"]:
            self.current = None
            self.new_alias()
            return
        self.current = self.db["aliases"][max(0, idx - 1)]
        self.persist()
        self.load_form()
        self.refresh_list()

    def reroll_look(self):
        if self.current is None:
            return
        self.current["look"] = uuid.uuid4().hex
        self.refresh_avatar()
        self.persist()

    def save_png(self):
        if self.current is None:
            return
        path = filedialog.asksaveasfilename(defaultextension=".png", filetypes=[("PNG image", "*.png")],
                                            initialfile=f"{ascii_slug(display_name(self.current)) or 'alias'}.png")
        if not path:
            return
        data = dict(self.current)
        data.update(self.get_form())
        try:
            make_full_photo(avatar_model(data), 16).write(path, format="png")
        except tk.TclError:
            messagebox.showerror("Error", "Your Tk version can't write PNG files (needs Tk 8.6+).")

    def generate(self):
        if self.current is None:
            return
        dlg = GenDialog(self, self.settings.get("email_domain", "example.com"), self._c["bg"])
        self.wait_window(dlg)
        if not dlg.result:
            return
        keys, domain = dlg.result
        self.settings["email_domain"] = domain
        gen = generate_alias(domain)
        data = dict(self.current)
        data.update(self.get_form())
        for k in keys:
            data[k] = gen.get(k, "")
        self.current.update(data)
        self.load_form()
        self.commit_and_refresh_list()
        if "password" in keys:
            self.set_reveal(True)

    # ------------------------------------------------------------ dialogs
    def show_security(self):
        win = self._toplevel("Security")
        pad = ttk.Frame(win, padding=16)
        pad.pack(fill="both", expand=True)
        row = ttk.Frame(pad)
        row.pack(anchor="w")
        ttk.Label(row, text="Lock automatically after").pack(side="left")
        lm = ttk.Combobox(row, values=["1", "5", "15", "30"], width=4, state="readonly")
        lm.set(str(self.settings.get("lock_minutes", 5)))
        lm.pack(side="left", padx=6)
        ttk.Label(row, text="minutes of inactivity").pack(side="left")
        lm.bind("<<ComboboxSelected>>", lambda e: self._set_setting("lock_minutes", int(lm.get())))
        nv = tk.BooleanVar(value=bool(self.settings.get("no_passwords")))
        ttk.Checkbutton(pad, variable=nv, text="Don't save passwords (kept in memory only, gone once the vault locks)",
                        command=lambda: self._set_setting("no_passwords", bool(nv.get()))).pack(anchor="w", pady=10)
        ttk.Separator(pad).pack(fill="x", pady=6)
        ttk.Label(pad, text="Change passphrase", style="Head.TLabel").pack(anchor="w")
        ents = []
        for ph in ("Current passphrase", "New passphrase (%d+ characters)" % MIN_PASSPHRASE, "Repeat new passphrase"):
            ttk.Label(pad, text=ph).pack(anchor="w", pady=(4, 0))
            e = ttk.Entry(pad, show="•", width=40)
            e.pack(fill="x")
            ents.append(e)

        def do_change():
            old, new, rep = (e.get() for e in ents)
            try:
                if len(new) < MIN_PASSPHRASE:
                    raise VaultError("Use at least %d characters." % MIN_PASSPHRASE)
                if new != rep:
                    raise VaultError("The new passphrases do not match.")
                self.commit()
                self.vault.change_passphrase(old, new, self._vault_data())
            except (VaultError, OSError) as e:
                messagebox.showerror("Change passphrase", str(e), parent=win)
                return
            win.destroy()
            self.flash("Passphrase changed")

        ttk.Button(pad, text="Change passphrase", command=do_change).pack(anchor="w", pady=8)
        ttk.Separator(pad).pack(fill="x", pady=6)

        def do_erase():
            if messagebox.askyesno("Erase all data", "Erase the vault and ALL aliases on this computer? "
                                                     "This cannot be undone.", parent=win):
                self.erase_everything()

        ttk.Button(pad, text="Erase all data…", command=do_erase).pack(anchor="w")
        ttk.Label(pad, wraplength=420, style="Small.TLabel", justify="left", text=(
            "What this protects: the vault file is encrypted (AES-256-GCM, key from scrypt), so someone who "
            "copies your files cannot read it without the passphrase. What it can't: malware or a keylogger on "
            "your computer, or someone using the app while it is unlocked. Python can't reliably wipe memory, "
            "so lock the app when you step away. A forgotten passphrase cannot be recovered.")).pack(anchor="w", pady=(12, 0))
        ttk.Button(pad, text="Close", command=win.destroy).pack(anchor="e", pady=(10, 0))

    def _set_setting(self, key, value):
        self.settings[key] = value
        self.persist()
        self.flash("Saved")

    def show_export(self, which):
        self.commit()
        aliases = list(self.db["aliases"]) if which == "all" else ([self.current] if self.current else [])
        if not aliases:
            return
        win = self._toplevel("Export")
        pad = ttk.Frame(win, padding=14)
        pad.pack(fill="both", expand=True)
        ttk.Label(pad, wraplength=560, justify="left", text=(
            "%d alias(es). An export password encrypts the string (AES-256-GCM). Passwords are left out "
            "unless you tick the box below, and that needs an export password." % len(aliases))).pack(anchor="w")
        inc = tk.BooleanVar(value=False)
        ttk.Checkbutton(pad, text="Include passwords (needs an export password)", variable=inc).pack(anchor="w", pady=6)
        pw = ttk.Entry(pad, show="•")
        pw.pack(fill="x")
        txt = tk.Text(pad, width=80, height=9, wrap="char", bg=self._c["field"], fg="#111111")
        txt.pack(pady=8, fill="both", expand=True)

        def create():
            p = pw.get()
            if inc.get() and not p:
                messagebox.showwarning("Export", "Set an export password to include passwords - otherwise "
                                                 "they would be readable in the string.", parent=win)
                return
            if not p and not messagebox.askyesno("No export password", "Anyone who sees this string can read "
                                                                       "it. Continue without a password?", parent=win):
                return
            out = []
            for a in aliases:
                b = dict(a)
                if not inc.get():
                    b.pop("password", None)
                out.append(b)
            win.config(cursor="watch")
            win.update()
            txt.delete("1.0", "end")
            txt.insert("1.0", encode_aliases(out, p or None))
            win.config(cursor="")

        def copy():
            self.clipboard_clear()
            self.clipboard_append(txt.get("1.0", "end").strip())

        bf = ttk.Frame(pad)
        bf.pack()
        for t, c in [("Create string", create), ("Copy", copy),
                     ("Show QR code", lambda: self.show_qr(txt.get("1.0", "end").strip())),
                     ("Close", win.destroy)]:
            ttk.Button(bf, text=t, command=c).pack(side="left", padx=5)

    def show_qr(self, s):
        if not s:
            return
        try:
            import segno
        except ImportError:
            messagebox.showerror("QR code", "The 'segno' package is missing. Run: pip install segno")
            return
        try:
            q = segno.make(s, error="l", micro=False)
        except Exception:
            messagebox.showerror("QR code", "Too much data for one QR code. Export fewer aliases, or use the text string.")
            return
        m = q.matrix
        n = len(m) + 8
        px = max(2, 520 // n)
        win = self._toplevel("QR code")
        cv = tk.Canvas(win, width=n * px, height=n * px, bg="white", highlightthickness=0)
        cv.pack(padx=10, pady=10)
        for y, row in enumerate(m):
            for x, v in enumerate(row):
                if v:
                    cv.create_rectangle((x + 4) * px, (y + 4) * px, (x + 5) * px, (y + 5) * px,
                                        fill="black", width=0)

        def save():
            p = filedialog.asksaveasfilename(defaultextension=".png",
                                             filetypes=[("PNG image", "*.png"), ("SVG image", "*.svg")])
            if p:
                q.save(p, scale=8, border=4)

        ttk.Button(win, text="Save image…", command=save).pack(pady=(0, 10))

    def merge_import(self, incoming):
        by_id = {a["id"]: i for i, a in enumerate(self.db["aliases"])}
        added = updated = 0
        for a in incoming:
            if a["id"] in by_id:
                old = self.db["aliases"][by_id[a["id"]]]
                if not a.get("password"):
                    a["password"] = old.get("password", "")   # exports usually leave passwords out
                self.db["aliases"][by_id[a["id"]]] = a
                if old is self.current:
                    self.current = a
                updated += 1
            else:
                self.db["aliases"].append(a)
                by_id[a["id"]] = len(self.db["aliases"]) - 1
                added += 1
        return added, updated

    def show_import(self):
        win = self._toplevel("Import")
        pad = ttk.Frame(win, padding=14)
        pad.pack(fill="both", expand=True)
        ttk.Label(pad, text="Paste an AliasVault export string below.").pack(anchor="w")
        txt = tk.Text(pad, width=80, height=9, wrap="char", bg=self._c["field"], fg="#111111")
        txt.pack(pady=8, fill="both", expand=True)

        def do_import():
            raw = txt.get("1.0", "end")
            try:
                pw = None
                if "".join(raw.split()).upper().startswith(PREFIX_ENC + "-"):
                    pw = simpledialog.askstring("Password", "Export password:", show="•", parent=win)
                incoming = decode_aliases(raw, pw)
            except (ValueError, json.JSONDecodeError) as e:
                messagebox.showerror("Import failed", str(e), parent=win)
                return
            added, updated = self.merge_import(incoming)
            self.persist()
            self.load_form()
            self.refresh_list()
            self.flash("%d added, %d updated" % (added, updated))
            win.destroy()

        bf = ttk.Frame(pad)
        bf.pack()
        ttk.Button(bf, text="Import", command=do_import).pack(side="left", padx=5)
        ttk.Button(bf, text="Close", command=win.destroy).pack(side="left", padx=5)


if __name__ == "__main__":
    App().mainloop()
