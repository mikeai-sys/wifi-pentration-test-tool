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
wa9 'MyHome' rockyou.txt --target-password 'MyOwnPass' --i-own-this-network
wa9 'MyHome' rockyou.txt --cap myown.cap --i-own-this-network
wa9 auto        # GUI: pick WiFi, choose wordlist file, start
```

`wa9 auto` needs GUI deps: `sudo apt install -y python3-tk` (done by install.sh).

## Legacy commands
`wifi-audit detect|benchmark|check-weak|crack|audit|shell|wifilist|test` still work.

## Legal
Only networks you own or have explicit written permission to test.
`crack`/`audit` require `--i-own-this-network`. Scan/test are passive only.
