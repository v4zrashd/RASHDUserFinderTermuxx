# V4Z User Finder

**Original** username & email public-profile checker for Termux — by **V4Z RASHD**.
Written from scratch (code, platform list and detection rules are all original
work). Not a copy or rebrand of any other tool.

## What it does

- `v4zfind --user <name>` — checks 165+ platforms (Facebook, Instagram,
  TikTok, YouTube, GitHub, Telegram and many more) and reports where a
  **public profile with that username exists**, with direct links.
- Verdicts are honest three-state: ✅ FOUND, ❌ NOT FOUND, ❓ UNKNOWN
  (site blocked the check — verify manually). No fake "complete info".
- `v4zfind --email <address>` — checks the public **Gravatar** profile for
  that email only. Email search is limited by nature; the tool says so.
- `--save` writes a TXT + JSON report to `~/v4zfind-reports/`.
- No pip installs: pure Python standard library.

## Install (Termux)

```bash
curl -fsSL https://raw.githubusercontent.com/v4zrashd/RASHDUserFinderTermuxx/main/install.sh | bash
```

Then run:

```bash
v4zfind
v4zfind --user v4zrashd
v4zfind --email someone@example.com
```

## Uninstall

```bash
curl -fsSL https://raw.githubusercontent.com/v4zrashd/RASHDUserFinderTermuxx/main/uninstall.sh | bash
```

## Disclaimer

Educational use only. This tool reads only publicly visible profile pages.
Check your own accounts, or accounts you have permission to check, and
respect every platform's terms of service.
