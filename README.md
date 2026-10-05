<p align="center">
  <img src="https://files.catbox.moe/1ga50l.jpg" alt="V4Z User Finder banner" width="100%">
</p>

<h1 align="center">🔍 V4Z User Finder</h1>

<p align="center">
  <b>Original</b> username &amp; email public-profile checker for Termux — by <b>V4Z RASHD</b>.<br>
  One username → checked across <b>168 platforms</b>. Pure Python, no pip installs.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.x-00ff9d?style=flat-square" alt="Python 3">
  <img src="https://img.shields.io/badge/Platform-Termux-00ff9d?style=flat-square" alt="Termux">
  <img src="https://img.shields.io/badge/Platforms-168-00ff9d?style=flat-square" alt="168 platforms">
  <img src="https://img.shields.io/badge/Version-1.2-00ff9d?style=flat-square" alt="v1.1">
</p>

## ✨ What it does

- `v4zfind --user <name>` — checks **168 platforms** (GitHub, YouTube, TikTok, Instagram, Telegram, Reddit and many more) and shows where a **public profile with that username exists**, with direct links.
- Honest three-state verdicts — no fake results:
  - ✅ **FOUND** — strong "profile exists" signal
  - ❌ **NOT FOUND** — strong "no such profile" signal
  - ❓ **UNKNOWN** — the site blocked the check; open the link and verify manually
- `v4zfind --email <address>` — checks the public **Gravatar** profile **and whether the email appears in known data breaches** (via the free XposedOrNot + LeakCheck public APIs; only breach names/dates/exposed data types — never passwords). No Gravatar profile or no known leak is reported honestly, never dressed up as "complete info".
- `--save` writes a TXT + JSON report to `~/v4zfind-reports/`.
- ⚡ Fast parallel checks, pure Python standard library — **zero pip installs**.

## 📦 Install (Termux)

```bash
curl -fsSL https://raw.githubusercontent.com/v4zrashd/RASHDUserFinderTermuxx/main/install.sh | bash
```

## 🚀 Usage

```bash
v4zfind                        # interactive menu
v4zfind --user v4zrashd        # username search
v4zfind --email someone@example.com
v4zfind --user v4zrashd --save # + save report
```

## 🗂️ Platform coverage (168)

| Category | Count |
| --- | --- |
| Developer | 45 |
| Social | 20 |
| Writing | 20 |
| Work | 18 |
| Gaming | 17 |
| Links | 13 |
| Music | 12 |
| Video | 11 |
| Photo | 7 |
| Art | 5 |

## 🗑️ Uninstall

```bash
curl -fsSL https://raw.githubusercontent.com/v4zrashd/RASHDUserFinderTermuxx/main/uninstall.sh | bash
```

## ⚠️ Disclaimer

Educational use only. This tool reads only publicly visible profile pages.
Check your own accounts, or accounts you have permission to check, and
respect every platform's terms of service.

---

<p align="center">Made with 💚 by <b>V4Z RASHD</b> • <a href="https://t.me/rashdteem">Telegram channel</a> • <a href="https://www.youtube.com/@V4Zteem">YouTube</a></p>
