#!/data/data/com.termux/files/usr/bin/bash
# V4Z User Finder — Termux installer (original tool by V4Z RASHD)
set -e
REPO_RAW="https://raw.githubusercontent.com/v4zrashd/RASHDUserFinderTermuxx/main"
BIN="$PREFIX/bin/v4zfind"

echo "== V4Z User Finder installer =="
command -v python >/dev/null 2>&1 || { echo "Installing python..."; pkg install -y python; }

echo "Downloading v4zfind..."
curl -fsSL "$REPO_RAW/v4zfind.py" -o "$BIN"
chmod +x "$BIN"

echo ""
echo "✅ Installed! Run:  v4zfind"
echo "   v4zfind --user <username> [--save]"
echo "   v4zfind --email <address>"
