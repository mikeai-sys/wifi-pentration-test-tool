#!/bin/bash
# install.sh - install wa9 + wifi-audit globally (Linux, apt-based)
# Verifies Python + libs, auto-installs anything missing.
#
# Usage:
#   ./install.sh              # full install (apt + files + verify)
#   ./install.sh --check      # verify only, no changes
#   ./install.sh --no-apt     # install files + pip libs, skip apt
#   ./install.sh --yes        # non-interactive (assume yes)
set -e
HERE="$(cd "$(dirname "$0")" && pwd)"
LIBDIR="/usr/local/lib/wa9"
CHECK_ONLY=0
NO_APT=0
ASSUME_YES=0
for a in "$@"; do
  case "$a" in
    --check) CHECK_ONLY=1 ;;
    --no-apt) NO_APT=1 ;;
    --yes|-y) ASSUME_YES=1 ;;
    -h|--help) echo "Usage: ./install.sh [--check] [--no-apt] [--yes]"; exit 0 ;;
    *) echo "[!] Unknown flag: $a" >&2; exit 2 ;;
  esac
done

if [ "$(id -u)" -ne 0 ]; then
  if command -v sudo >/dev/null 2>&1; then SUDO="sudo"; else echo "[!] Run as root (no sudo found)." >&2; exit 1; fi
else
  SUDO=""
fi

msg() { echo "[*] $*"; }
ok() { echo "[+] $*"; }
warn() { echo "[!] $*" >&2; }
have() { command -v "$1" >/dev/null 2>&1; }

APT_MISSING=""
need_apt() { # need_apt <pkg> [pkg...] — queue pkgs whose key command is missing
  for pkg in "$@"; do
    case "$APT_MISSING" in *"$pkg"*) ;; *) APT_MISSING="$APT_MISSING $pkg";; esac
  done
}

# ---------- 1. Python interpreter ----------
msg "Verifying Python..."
if ! have python3; then
  warn "python3 not found -> will install."
  need_apt python3
else
  PYVER="$(python3 -c 'import sys; print(f"{sys.version_info[0]}.{sys.version_info[1]}")')"
  PYMAJ="${PYVER%%.*}"; PYMIN="${PYVER#*.}"
  msg "Found python3 $PYVER ($(python3 --version 2>&1))"
  if [ "$PYMAJ" -lt 3 ] || { [ "$PYMAJ" -eq 3 ] && [ "$PYMIN" -lt 8 ]; }; then
    warn "python3 >= 3.8 required (found $PYVER) -> will try to install newer python3."
    need_apt python3
  else
    ok "Python $PYVER OK (>= 3.8)."
  fi
fi

# ---------- 2. pip ----------
msg "Verifying pip..."
if have python3 && python3 -m pip --version >/dev/null 2>&1; then
  ok "pip OK ($(python3 -m pip --version 2>&1 | head -1))."
else
  warn "pip missing -> will install python3-pip."
  need_apt python3-pip
fi

# ---------- 3. Python stdlib / libs used by wa9 ----------
# wa9 core is stdlib-only; tkinter is a separate apt package (python3-tk).
msg "Verifying Python modules..."
PY_MODS="argparse concurrent.futures hashlib multiprocessing shlex shutil subprocess queue threading"
TK_OK=0
if have python3; then
  for m in $PY_MODS; do
    if python3 -c "import importlib,sys; importlib.import_module(sys.argv[1])" "$m" 2>/dev/null; then
      : # ok
    else
      warn "Python module '$m' missing -> broken python3 install, will reinstall python3."
      need_apt python3
    fi
  done
  if python3 -c "import tkinter" 2>/dev/null; then
    ok "tkinter OK (wa9 auto GUI will work)."
    TK_OK=1
  else
    warn "tkinter missing -> will install python3-tk (needed for 'wa9 auto' GUI)."
    need_apt python3-tk
  fi
  ok "Core modules checked."
else
  warn "Skipping module check (no python3 yet)."
fi

# ---------- 4. requirements.txt (pip libs, if any) ----------
if [ -f "$HERE/requirements.txt" ]; then
  msg "Found requirements.txt:"
  sed 's/^/    /' "$HERE/requirements.txt"
else
  msg "No requirements.txt (core is stdlib-only) — nothing extra needed."
fi

# ---------- 5. System wifi tools (optional but recommended) ----------
msg "Verifying wifi backend tools..."
have aircrack-ng || { warn "aircrack-ng missing."; need_apt aircrack-ng; }
have hashcat || { warn "hashcat missing (CPU+GPU engine)."; need_apt hashcat; }
have hcxpcapngtool || { warn "hcxtools missing (.cap -> .hc22000 converter)."; need_apt hcxtools; }
have nmcli || { warn "nmcli missing (wa9 wifilist scanner)."; need_apt network-manager; }
{ have iwlist || have iw; } || { warn "iw/iwlist missing (fallback scanner)."; need_apt "wireless-tools iw"; }
ok "Backend tool check done."

# ---------- 6. Install missing apt packages automatically ----------
if [ "$CHECK_ONLY" -eq 1 ]; then
  if [ -n "$APT_MISSING" ]; then warn "CHECK: would install:$APT_MISSING"; exit 1
  else ok "CHECK: all dependencies present."; fi
  if have python3 && [ -f "$HERE/requirements.txt" ] && ! python3 -m pip check >/dev/null 2>&1; then
    warn "CHECK: pip check reports issues."
  fi
  exit 0
fi

if [ "$NO_APT" -eq 0 ] && [ -n "$APT_MISSING" ]; then
  # shellcheck disable=SC2086
  msg "Auto-installing missing packages:$APT_MISSING"
  $SUDO apt-get update
  # shellcheck disable=SC2086
  $SUDO apt-get install -y $APT_MISSING || warn "apt had issues, continuing (lab CPU mode still works)."
else
  msg "No apt installs needed (or --no-apt)."
fi

# ---------- 7. Re-verify Python + tkinter after auto-install ----------
if ! have python3; then warn "python3 STILL missing after install. Aborting."; exit 1; fi
if ! python3 -c "import tkinter" 2>/dev/null; then
  warn "tkinter still missing — 'wa9 auto' GUI will not start until: sudo apt install -y python3-tk"
else
  ok "tkinter verified."
fi

# ---------- 8. pip libs (auto-create/upgrade) ----------
if [ -f "$HERE/requirements.txt" ] && grep -qvE '^\s*(#|$)' "$HERE/requirements.txt"; then
  msg "Installing pip requirements..."
  if ! python3 -m pip --version >/dev/null 2>&1; then warn "pip still missing, skipping pip install."; else
    python3 -m pip install --upgrade pip || warn "pip self-upgrade failed, continuing."
    if grep -qi debian /etc/os-release 2>/dev/null && python3 -m pip install --help 2>&1 | grep -q break-system-packages; then
      python3 -m pip install -r "$HERE/requirements.txt" --break-system-packages || warn "pip install failed."
    else
      python3 -m pip install -r "$HERE/requirements.txt" || warn "pip install failed."
    fi
  fi
else
  msg "No pip packages to install (stdlib-only)."
fi

# ---------- 9. Install wa9 files globally ----------
msg "Installing to $LIBDIR + /usr/local/bin ..."
$SUDO mkdir -p "$LIBDIR" /usr/local/bin
for f in wifi_audit.py wa9_gui.py; do
  [ -f "$HERE/$f" ] || { warn "Missing $HERE/$f. Aborting."; exit 1; }
done
$SUDO cp "$HERE/wifi_audit.py" "$HERE/wa9_gui.py" "$LIBDIR/"
$SUDO cp "$HERE/wifi-audit" /usr/local/bin/wifi-audit
$SUDO cp "$HERE/wa9" /usr/local/bin/wa9
$SUDO chmod +x "$LIBDIR/wifi_audit.py" "$LIBDIR/wa9_gui.py" /usr/local/bin/wifi-audit /usr/local/bin/wa9
[ -f "$HERE/requirements.txt" ] && $SUDO cp "$HERE/requirements.txt" "$LIBDIR/" || true

# ---------- 10. Post-install verification ----------
msg "Post-install verification..."
python3 -c 'import ast,sys; [ast.parse(open(f).read()) for f in sys.argv[1:]]' "$LIBDIR/wifi_audit.py" "$LIBDIR/wa9_gui.py" && ok "syntax OK."
command -v wa9 >/dev/null && ok "wa9 on PATH ($(command -v wa9))." || warn "wa9 not on PATH."
wa9 --help >/dev/null 2>&1 && ok "wa9 --help OK." || warn "wa9 --help failed."
wa9 wifilist >/dev/null 2>&1 && ok "wa9 wifilist smoke OK." || warn "wa9 wifilist smoke failed (ok if no WiFi HW)."
python3 -c "import tkinter" 2>/dev/null && ok "GUI backend (tkinter) ready." || warn "GUI backend missing: sudo apt install -y python3-tk"

ok "Done. Try:"
echo "    wa9 --help"
echo "    wa9 wifilist"
echo "    wa9 test 'MyHome'"
echo "    wa9 'MyHome' /usr/share/wordlists/rockyou.txt --target-password 'MyOwnPass' --i-own-this-network"
echo "    wa9 auto"
