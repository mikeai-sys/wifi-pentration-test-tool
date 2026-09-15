# wifi-pentration-test-tool (own network only)

Passive scan + persistent offline WPA2 auditor. No deauth / injection code.

## Install globally
```bash
git clone https://github.com/mikeai-sys/wifi-pentration-test-tool.git
cd wifi-pentration-test-tool
chmod +x install.sh
./install.sh
```

## Commands (`wa9`)
```bash
wa9 --help
wa9 wifilist
wa9 test 'MyHome'
wa9 test 'MyHome' --wordlist rockyou.txt --target-password 'MyOwnPass'
  wa9 audit --hc22000 myown.hc22000 --wordlist rockyou.txt --use-gpu auto --i-own-this-network
  wa9 'MyHome' rockyou.txt --cap myown.cap --i-own-this-network
  # watch every try (line/password -> WRONG, stops on CORRECT):
  wa9 'MyHome' rockyou.txt --target-password 'MyOwnPass' --show-each --i-own-this-network
  wa9 auto        # GUI: pick WiFi, choose wordlist + handshake file, start
```

`wa9 auto` needs GUI deps: `sudo apt install -y python3-tk` (done by install.sh),
plus a display. Headless? Use the terminal commands above instead.

## IMPORTANT: two modes — read this first
- **REAL test (`audit`, GUI "Real" mode): actually tests the WiFi password.**
  Needs a handshake capture from YOUR OWN AP (WPA2 can't be tested from the
  SSID alone — the SSID is not secret). Capture it semi-automatically
  (needs sudo + a monitor-mode-capable adapter; passive listen, NO deauth —
  you toggle one of your own devices when asked):
  ```bash
  sudo wa9 capture --bssid <your_AP_MAC> --channel <ch> --iface wlan0 --i-own-this-network
  wa9 audit --hc22000 wa9_capture.hc22000 --wordlist rockyou.txt --use-gpu auto --i-own-this-network
  ```
  In the GUI (`wa9 auto`) the same flow is a button: **Capture...** asks for
  your AP's MAC + channel and opens a terminal (pkexec/sudo) running the
  wizard; afterwards pick the `.hc22000` with Browse and press Start.
  Manual fallback: `sudo airmon-ng start wlan0`, then
  `sudo airodump-ng -c <ch> --bssid <MAC> -w myown wlan0mon`,
  reconnect your own device, `hcxpcapngtool -o myown.hc22000 myown-01.cap`.
  The tool validates the file first and aborts with capture help if the
  handshake is missing/invalid — instead of burning CPU hours on garbage.
- **LAB demo (`crack`, GUI "Lab" mode): speed/persistence test only.**
  Takes YOUR OWN *known* password (`--target-password`) and replays it through
  the engine. It proves thousands-of-passwords throughput, but it does NOT
  recover an unknown password. If you ran this expecting the WiFi password,
  switch to REAL mode above.
- **GUI "show each password"** is OFF by default to protect RAM: the log shows
  a light `tried N wrong...` counter plus the final CORRECT password, and the
  log widget is capped at 3000 lines. Tick the box only for small lists if you
  want every `[line/total] 'password' -> WRONG` line (same as `--show-each`).

## About speed (is "too fast" a bug?)
WPA2 passwords are PBKDF2-SHA1 x4096 — roughly 1–3 ms per password per CPU
core. So ~1,000+ keys/s on an 8–16 core machine is REAL, and a 10k wordlist
finishing in seconds is normal, not a bug. GPUs do 100k+/s. What IS a bug:
exiting instantly with no FOUND and no progress lines — that means it aborted
(check the error above the prompt, e.g. missing `--target-password`,
missing `--i-own-this-network`, or wordlist not found). With `--show-each`
you can see literally every line it tests, so nothing is hidden.

## Legacy commands
`wifi-audit detect|benchmark|check-weak|crack|audit|shell|wifilist|test` still work.

## Legal
Only networks you own or have explicit written permission to test.
`crack`/`audit` require `--i-own-this-network`. Scan/test are passive only.
