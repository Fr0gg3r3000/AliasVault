# ✦ AliasVault ✦

A free, open-source organiser for the aliases you use to stay private online. Keep a "file" for each
fake persona — name, date of birth, email, password, phone, background, devices and more — generate
convincing random ones, and see each as a pixel-art character you can spin around in 3D.

No accounts. No server. Nothing leaves your device.

| Version | What it is |
|---|---|
| **Android app** | A small locked-down wrapper around the web version. It has **no internet permission**. |
| **Web** (`aliasvault.html`) | One file. Open it in any browser. Works offline. |
| **Desktop** (`aliasvault.py`) | Python/Tkinter app, also packaged as a single-file Windows/macOS/Linux program. |

All three share the same export format, so you can move aliases between them by copying a string of text
(or scanning a QR code).

## Install on Android (GrapheneOS, or any Android 8+)

1. Install [Obtainium](https://github.com/ImranR98/Obtainium).
2. In Obtainium choose **Add app** and paste `https://github.com/Fr0gg3r3000/AliasVault`.
3. Install the APK it finds. Obtainium will tell you when a new release is out.

Or download the `.apk` from the [Releases](../../releases) page and install it yourself. Releases are
signed with one key, so updates install over the top of the old version.

To check the app really can't use the network, look at its permissions in Android settings (there should be
none), or run `aapt2 dump permissions AliasVault-*.apk`.

## Security — what it does and doesn't do

- Everything is stored **encrypted** behind a master passphrase you choose
  (AES-256-GCM; key from PBKDF2-SHA256 with 600,000 rounds on web/Android, scrypt on desktop).
- It **locks itself after 5 minutes** of inactivity (1/5/15/30 selectable), wiping the screen, character and
  clipboard. On Android it also locks when you've been away from the app for a minute, and blocks screenshots and
  the recent-apps preview.
- Passwords are **masked**, can be copied with one tap, and the clipboard is cleared 30 seconds later. On
  Android, copied passwords are flagged "sensitive" so the system hides them from clipboard previews.
- Exports leave passwords **out** unless you tick the box, which then requires an export password.
- You can choose **not to save passwords at all** (kept in memory only while unlocked).

What it can't protect against: malware or a keylogger on your device, someone using the app while it is
unlocked, or a weak passphrase (use 4–5 random words). **There is no recovery** — if you forget the passphrase,
the data is gone. No program can reliably wipe its own memory, so lock the app when you step away.

Generated phone numbers use ranges reserved for fiction (UK Ofcom drama numbers, US 555-01xx, Australian ACMA
reserved numbers) so they never ring a real person. Aliases are for privacy, pseudonymity, testing and fiction —
not for impersonating real people or for official documents and identity checks.



MIT — see [LICENSE](LICENSE). Bundled libraries keep their own MIT licences (see `THIRD_PARTY.txt` inside the app).
