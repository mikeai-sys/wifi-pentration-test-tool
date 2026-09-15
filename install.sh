#!/bin/bash
# install.sh - install wa9 + wifi-audit globally (Linux, apt-based)
set -e
HERE="$(cd "$(dirname "$0")" && pwd)"
LIBDIR="/usr/local/lib/wa9"
NEED_ROOT=""

if [ "$(id -u)" -ne 0 ]; then
  if command -v sudo >/dev/null 2>&1; then
    SUDO="sudo"
  else
    echo "[!] Run as root (no sudo found)." >&2
    exit 1
  fi
else
  SUDO=""
fi

echo "[*] Installing system deps (aircrack, hashcat, nmcli, tkinter)..."
$SUDO apt-get update
$SUDO apt-get install -y python3 aircrack-ng hashcat hcxtools network-manager wireless-tools iw python3-tk || {
  echo "[!] apt had issues, continuing (auditor still works in CPU lab mode)..."
}

echo "[*] Installing to $LIBDIR + /usr/local/bin ..."
$SUDO mkdir -p "$LIBDIR" /usr/local/bin
$SUDO cp "$HERE/wifi_audit.py" "$HERE/wa9_gui.py" "$LIBDIR/"
$SUDO cp "$HERE/wifi-audit" /usr/local/bin/wifi-audit
$SUDO cp "$HERE/wa9" /usr/local/bin/wa9
$SUDO chmod +x "$LIBDIR/wifi_audit.py" "$LIBDIR/wa9_gui.py" /usr/local/bin/wifi-audit /usr/local/bin/wa9

echo "[+] Done. Try:"
echo "    wa9 --help"
echo "    wa9 wifilist"
echo "    wa9 test 'MyHome'"
echo "    wa9 'MyHome' /usr/share/wordlists/rockyou.txt --target-password 'MyOwnPass' --i-own-this-network"
echo "    wa9 auto"
