#!/usr/bin/env python3
"""
wifi-audit - terminal offline WPA2 auditor for YOUR OWN network.

ONLY for networks you own / have written permission to test.
No live deauth / monitor-mode / neighbor attack code.

Commands (terminal tool):
  wifi-audit detect
  wifi-audit benchmark [--num-passwords N] [--jobs N]
  wifi-audit check-weak --current-password X --wordlist f.txt
  wifi-audit crack --ssid S --wordlist f.txt --target-password Y [--jobs N] [--resume-from N]
  wifi-audit audit --ssid S --cap own.cap --wordlist f.txt --i-own-this-network
  wifi-audit audit --hc22000 own.hc22000 --wordlist f.txt --use-gpu auto --i-own-this-network
  wifi-audit shell   # interactive terminal: set/start/status/stop

Persistent engine: streams wordlist in batches, uses all CPU cores,
NEVER stops early — only stops on: password FOUND, wordlist exhausted, or Ctrl+C.
Checkpoint file allows resume after Ctrl+C.
"""
import argparse
import concurrent.futures
import hashlib
import multiprocessing
import os
import shlex
import shutil
import subprocess
import sys
import time

LEGAL_ACK = "--i-own-this-network"
CHECKPOINT = "/tmp/opencode/wifi_audit_checkpoint.txt"

def fail(msg, code=1):
    print(f"[!] {msg}", file=sys.stderr)
    sys.exit(code)

def which(n):
    return shutil.which(n)

def detect_tools():
    tools = {"aircrack-ng": which("aircrack-ng"), "hashcat": which("hashcat"),
             "hcxpcapngtool": which("hcxpcapngtool")}
    gpu = "not checked"
    if tools["hashcat"]:
        try:
            r = subprocess.run([tools["hashcat"], "-I", "--quiet"],
                               capture_output=True, text=True, timeout=20)
            out = (r.stdout + r.stderr)[:2000]
            gpu = out.strip() or "hashcat present, no GPU backend (CPU only)"
        except Exception as e:
            gpu = f"detect failed: {e}"
    return tools, gpu

def cmd_detect(_a=None):
    tools, gpu = detect_tools()
    print(f"CPU cores : {multiprocessing.cpu_count()}")
    print(f"Tools     : {tools}")
    print(f"GPU       :\n{gpu}")
    if not tools["hashcat"]:
        print("Tip: sudo apt install hashcat aircrack-ng  # unlocks GPU + real handshake audit")

# --- passive WiFi scan (no injection / no deauth) ---
def scan_networks(rescan=True, timeout=20):
    """Passive nearby-AP list via nmcli, fallback iwlist. Returns [dict]. Own-network auditing only."""
    nets = []
    nm = which("nmcli")
    if nm:
        try:
            cmd = [nm, "-t", "-f", "SSID,SIGNAL,SECURITY", "dev", "wifi", "list"]
            if rescan:
                cmd += ["--rescan", "yes"]
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            for line in (r.stdout or "").splitlines():
                line = line.strip()
                if not line:
                    continue
                parts = line.split(":")
                if len(parts) < 3:
                    continue
                security = parts[-1]
                try:
                    signal = int(parts[-2])
                except ValueError:
                    signal = 0
                ssid = ":".join(parts[:-2])  # SSID may contain colons
                if not ssid:
                    ssid = "<hidden>"
                nets.append({"ssid": ssid, "signal": signal, "security": security or "--"})
            if nets:
                return nets
        except Exception as e:
            print(f"[!] nmcli scan failed: {e}", file=sys.stderr)
    iw = which("iwlist")
    if iw:
        try:
            iface = "wlan0"
            try:
                r = subprocess.run(["iw", "dev"], capture_output=True, text=True, timeout=5)
                import re as _re
                m = _re.search(r"Interface\s+(\w+)", r.stdout or "")
                if m:
                    iface = m.group(1)
            except Exception:
                pass
            r = subprocess.run([iw, iface, "scanning"], capture_output=True, text=True, timeout=timeout)
            import re
            cells = re.split(r"Cell \d+ - ", r.stdout or "")
            for c in cells:
                m_ssid = re.search(r'ESSID:"([^"]*)"', c)
                m_sig = re.search(r"Signal level=(-?\d+)", c)
                m_enc = re.search(r"Encryption key:(on|off)", c)
                if not m_ssid:
                    continue
                ssid = m_ssid.group(1) or "<hidden>"
                signal = int(m_sig.group(1)) if m_sig else 0
                enc = m_enc.group(1) if m_enc else "unknown"
                sec = "OPEN" if enc == "off" else "WPA/WPA2 (see IE)"
                nets.append({"ssid": ssid, "signal": signal, "security": sec})
            if nets:
                return nets
        except Exception as e:
            print(f"[!] iwlist scan failed: {e}", file=sys.stderr)
    return nets

def cmd_wifilist():
    print("[*] Scanning nearby APs (passive, no deauth)...")
    nets = scan_networks()
    if not nets:
        print("[-] No networks found (no WiFi hardware? container? try: nmcli dev wifi list).")
        return []
    print(f"{'SSID':32} {'SIGNAL':>6}  SECURITY")
    print("-" * 70)
    for n in sorted(nets, key=lambda x: -x["signal"]):
        print(f"{n['ssid'][:32]:32} {n['signal']:>6}  {n['security']}")
    return nets

COMMON_DEFAULT_SSIDS = {"TP-Link", "TP-LINK", "Huawei", "HUAWEI", "ZTE", "D-Link", "DLink",
                        "Linksys", "Netgear", "NETGEAR", "xfinitywifi", "FreeWifi", "default"}

def assess_target(ssid, wordlist=None, target_password=None):
    """Advanced passive vulnerability assessment for YOUR OWN ssid. No attacks."""
    nets = scan_networks(rescan=False)
    match = next((n for n in nets if n["ssid"] == ssid), None)
    findings = []
    score = 0  # 0=safe-ish, 100=critical
    if match is None:
        findings.append(("INFO", f"SSID '{ssid}' not seen in current scan (out of range / hidden / typo)."))
    else:
        sec = (match["security"] or "").upper()
        sig = match["signal"]
        findings.append(("INFO", f"Observed: SSID='{ssid}' signal={sig} security='{match['security']}'"))
        if sec in ("", "--", "OPEN", "NONE", "OPEN "):
            findings.append(("CRITICAL", "OPEN network: no encryption. Anyone can sniff all traffic. Enable WPA2-AES or WPA3 immediately."))
            score = max(score, 100)
        elif "WEP" in sec:
            findings.append(("CRITICAL", "WEP is broken in minutes (Fluhrer-Mantin-Shamir). Migrate to WPA2-AES/WPA3."))
            score = max(score, 95)
        elif sec.startswith("WPA1") or sec == "WPA" or ("WPA " in sec and "WPA2" not in sec):
            findings.append(("HIGH", "WPA-TKIP (v1) is deprecated and crackable. Use WPA2-AES (CCMP) or WPA3-SAE."))
            score = max(score, 80)
        elif "WPA3" in sec:
            findings.append(("OK", "WPA3-SAE observed: strongest personal option. Keep firmware updated, long random passphrase."))
        elif "WPA2" in sec:
            if "TKIP" in sec:
                findings.append(("MEDIUM", "WPA2-TKIP: switch cipher to AES/CCMP only."))
                score = max(score, 55)
            else:
                findings.append(("OK", "WPA2-AES observed. Security now depends on passphrase strength + WPS/PMF settings."))
                score = max(score, 20)
            findings.append(("INFO", "PMF (802.11w): enable 'PMF Required' on your own AP if clients support it (anti-deauth)."))
        else:
            findings.append(("INFO", f"Unrecognized security string '{match['security']}': verify on your AP admin page (want WPA2-AES or WPA3)."))
            score = max(score, 30)
        if isinstance(sig, int) and sig < 45:
            findings.append(("INFO", "Weak signal: you are far — attacker nearby the AP still has strong signal. Don't rely on distance."))
    if any(ssid.lower().startswith(d.lower().split()[0]) or ssid == d for d in COMMON_DEFAULT_SSIDS):
        findings.append(("INFO", "Default-looking SSID: rename + change admin credentials; default SSIDs enable precomputed tables."))
        score = max(score, 25)
    findings.append(("INFO", "WPS: check YOUR AP admin page — disable WPS PIN (reaver-vulnerable on many routers). Verify with: wash -i wlan0 (own lab only)."))
    findings.append(("INFO", "Admin page: change default admin password, update firmware, disable remote management."))
    if wordlist and target_password:
        if os.path.isfile(wordlist):
            t0 = time.time(); hit, n = False, 0
            with open(wordlist, errors="ignore") as f:
                for line in f:
                    n += 1
                    if line.rstrip("\r\n") == target_password:
                        hit = True
                        break
            if hit:
                findings.append(("CRITICAL", f"Your passphrase is IN {wordlist} (line {n}): change to 20+ random chars NOW."))
                score = max(score, 90)
            else:
                findings.append(("OK", f"Passphrase not in {wordlist} ({n} lines, {time.time()-t0:.1f}s). Still use 20+ random chars."))
        else:
            findings.append(("INFO", f"Wordlist not found: {wordlist}"))
    elif wordlist or target_password:
        findings.append(("INFO", "Passphrase check needs BOTH --wordlist and --target-password (your own password)."))
    grade = "CRITICAL" if score >= 90 else "HIGH" if score >= 70 else "MEDIUM" if score >= 40 else "LOW" if score >= 10 else "STRONG"
    return {"ssid": ssid, "score": score, "grade": grade, "findings": findings, "observed": match}

def cmd_vuln_test(ssid, wordlist=None, target_password=None):
    print(f"[*] Advanced passive vulnerability test for YOUR OWN network '{ssid}' (no attacks)...")
    rep = assess_target(ssid, wordlist, target_password)
    print(f"\n== {rep['ssid']} : {rep['grade']} (risk {rep['score']}/100) ==")
    for sev, msg in rep["findings"]:
        print(f"[{sev:8}] {msg}")
    print("\nRemediation order: WPA3/WPA2-AES > 20+ char random passphrase > WPS PIN off > PMF on > firmware+admin pw.")
    return rep

# --- persistent CPU worker ---
def _pmk_batch(batch_ssid):
    """Top-level worker: batch=[passwords], ssid -> list[(pw, pmk_hex)]. Keeps IPC low."""
    batch, ssid = batch_ssid
    out = []
    s = ssid.encode()
    for pw in batch:
        dk = hashlib.pbkdf2_hmac("sha1", pw.encode(errors="ignore"), s, 4096, 32)
        out.append((pw, dk.hex()))
    return out

def count_lines(path):
    with open(path, "rb") as f:
        return sum(1 for _ in f)

def cmd_benchmark(num=2000, jobs=None, ssid="TestSSID"):
    jobs = jobs or multiprocessing.cpu_count()
    print(f"[*] benchmark: {num} x PBKDF2-SHA1(4096), jobs={jobs}")
    t0 = time.time()
    batches = [[f"Bench{i:07d}!" for i in range(j*250, min((j+1)*250, num))] for j in range((num+249)//250)]
    with concurrent.futures.ProcessPoolExecutor(max_workers=jobs) as ex:
        list(ex.map(_pmk_batch, [(b, ssid) for b in batches if b]))
    dt = time.time() - t0
    rate = num / dt
    print(f"[+] {rate:.0f} keys/sec ({dt:.2f}s). 1M pw ~ {1000000/rate/3600:.2f}h CPU. GPU hashcat is 10-100x.")
    return rate

def cmd_check_weak(current_password, wordlist):
    if not os.path.isfile(wordlist):
        fail(f"wordlist not found: {wordlist}")
    t0 = time.time(); n = 0
    with open(wordlist, errors="ignore") as f:
        for line in f:
            n += 1
            if line.rstrip("\r\n") == current_password:
                print(f"[!] WEAK: found at line {n}. Change it now (20+ random chars).")
                return True
    print(f"[+] OK: not in list after {n} lines / {time.time()-t0:.1f}s (only means not in THIS list).")
    return False

def cmd_crack(ssid, wordlist, target_password=None, target_pmk=None,
              jobs=None, resume_from=0, batch_size=400, ack=False, show_each=False):
    """
    LAB DEMO: persistent CPU engine proving speed/persistence using YOUR OWN
    known password. It does NOT touch the real AP and does NOT recover an
    unknown password — for that use 'audit' with a handshake capture
    (--cap/--hc22000) from your own router. Computes the target PMK from the
    given known password, then streams the wordlist until that entry is FOUND.
    Never stops after 'a few attempts' — only on FOUND / exhausted / Ctrl+C.
    show_each=True logs every candidate: [line/total] 'password' -> WRONG,
    and -> CORRECT on the hit (slower due to I/O, but fully transparent).
    """
    if not ack:
        fail(f"Confirm ownership: pass {LEGAL_ACK} (your own network/lab only).")
    if not os.path.isfile(wordlist):
        fail(f"wordlist not found: {wordlist}")
    if target_pmk is None:
        if not target_password:
            fail("Provide --target-password (your own AP password for lab test) or --target-pmk.")
        target_pmk = hashlib.pbkdf2_hmac("sha1", target_password.encode(),
                                         ssid.encode(), 4096, 32).hex()
    jobs = jobs or multiprocessing.cpu_count()
    total = count_lines(wordlist)
    print(f"[*] crack start: ssid={ssid} total={total} jobs={jobs} batch={batch_size} resume={resume_from} show_each={show_each}")
    print(f"[*] target_pmk={target_pmk[:16]}... | runs until FOUND or EOF. Ctrl+C to pause (checkpoint saved).")
    if show_each:
        print("[*] show_each ON: every candidate is logged as [line/total] 'password' -> WRONG/CORRECT.")
    t0 = time.time()

    def save_ckpt(n):
        os.makedirs(os.path.dirname(CHECKPOINT), exist_ok=True)
        with open(CHECKPOINT, "w") as f:
            f.write(str(n))

    # Build batch list streaming (start_line, batch). Memory: one batch at a time for submit,
    # futures hold data while in flight (bounded by jobs*2 via ordered submit+check).
    try:
        with concurrent.futures.ProcessPoolExecutor(max_workers=jobs) as ex:
            inflight = []  # [(future, start_line, batch_len)]
            next_line = resume_from + 1  # 1-indexed line number of next unread password
            tested = resume_from
            found = None

            def check_ordered_blocking():
                """Check oldest futures in order; return password if found."""
                nonlocal tested, found
                buf = []  # per-candidate lines for show_each (flushed per batch)
                # wait in submission order so line numbers / resume stay correct
                for fut, start, blen in list(inflight):
                    try:
                        res = fut.result()  # blocks in order -> guarantees full scan, no early stop
                    except Exception as e:
                        print(f"\n[!] worker error at line {start}: {e}")
                        tested = start + blen - 1
                        save_ckpt(tested)
                        continue
                    for i, (pw, pmk) in enumerate(res):
                        lineno = start + i
                        if pmk == target_pmk:
                            dt = time.time() - t0
                            wrong = lineno - 1 - resume_from  # wrong tries this run
                            if show_each and buf:
                                print("\n".join(buf), flush=True)
                                buf.clear()
                            if show_each:
                                print(f"[{lineno}/{total}] '{pw}' -> CORRECT", flush=True)
                            print(f"\n[+] CORRECT after {wrong} wrong tries: '{pw}'  (line {lineno}/{total}, {dt:.1f}s)")
                            save_ckpt(lineno)
                            for f2, _, _ in inflight:
                                f2.cancel()
                            ex.shutdown(wait=False, cancel_futures=True)
                            return pw
                        elif show_each:
                            buf.append(f"[{lineno}/{total}] '{pw}' -> WRONG")
                    if show_each and buf:
                        print("\n".join(buf), flush=True)
                        buf.clear()
                    tested = start + blen - 1
                    save_ckpt(tested)
                    el = time.time() - t0
                    rate = (tested - resume_from) / el if el > 0 else 0
                    eta = (total - tested) / rate if rate > 0 else 0
                    if show_each:
                        print(f"[*] tried {tested} wrong... ({tested}/{total}, {100*tested/max(total,1):.1f}%) {rate:.0f} keys/s ETA {eta/60:.1f}m", flush=True)
                    else:
                        # light single-line counter: no per-password spam, ~zero memory
                        print(f"\r[*] tried {tested} wrong... ({tested}/{total}, {100*tested/max(total,1):.1f}%) {rate:.0f} keys/s", end="", flush=True)
                inflight.clear()
                return None

            batch, start = [], next_line
            skipped = 0
            with open(wordlist, errors="ignore") as f:
                for line in f:
                    if skipped < resume_from:
                        skipped += 1; continue
                    if not batch:
                        start = next_line
                    batch.append(line.rstrip("\r\n"))
                    next_line += 1
                    if len(batch) >= batch_size:
                        fut = ex.submit(_pmk_batch, (list(batch), ssid))
                        inflight.append((fut, start, len(batch)))
                        batch = []
                        if len(inflight) >= jobs * 2:
                            # wait for this window in order before reading more;
                            # workers keep running in parallel, main just checks in order
                            hit = check_ordered_blocking()
                            if hit:
                                return hit
            if batch:
                fut = ex.submit(_pmk_batch, (list(batch), ssid))
                inflight.append((fut, start, len(batch)))
            if inflight:
                hit = check_ordered_blocking()
                if hit:
                    return hit
    except KeyboardInterrupt:
        save_ckpt(tested)
        print(f"\n[!] Paused at {tested}/{total}. Resume with --resume-from {tested}")
        return None
    print(f"\n[-] Exhausted {total} passwords, not found. Try bigger wordlist / rules. Checkpoint={tested}")
    return None

CAPTURE_HELP = """No usable handshake found. To REALLY test your OWN WiFi password you need
a handshake capture from YOUR OWN access point first (WPA2 cannot be tested
from SSID alone — the SSID is not secret):
  1. sudo airmon-ng start wlan0
  2. sudo airodump-ng -c <channel> --bssid <your_AP_MAC> -w myown wlan0mon
     (reconnect one of YOUR OWN devices so the 4-way handshake is captured;
      never deauth other people's devices)
  3. Convert: hcxpcapngtool -o myown.hc22000 myown-01.cap
  4. Audit:  wa9 audit --hc22000 myown.hc22000 --wordlist rockyou.txt --use-gpu auto --i-own-this-network
Lab shortcut (no WiFi hardware): 'crack' with --target-password replays YOUR OWN
known password through the engine to prove speed/persistence."""

def validate_handshake(path, kind=None):
    """Check an offline capture is usable before burning CPU/GPU hours.

    Returns (ok: bool, msg: str). Never runs attacks; only reads file headers.
    kind: 'cap' | 'hc22000' | None (auto-detect by extension/content).
    """
    if not path:
        return False, "no file given. " + CAPTURE_HELP
    if not os.path.isfile(path):
        return False, f"file not found: {path}. " + CAPTURE_HELP
    try:
        size = os.path.getsize(path)
    except OSError as e:
        return False, f"cannot stat {path}: {e}"
    if size == 0:
        return False, f"{path} is empty (0 bytes). Re-capture from YOUR OWN AP. " + CAPTURE_HELP
    ext = os.path.splitext(path)[1].lower()
    if kind is None:
        kind = "hc22000" if ext == ".hc22000" else "cap"
    try:
        with open(path, "rb") as f:
            head = f.read(4096)
    except OSError as e:
        return False, f"cannot read {path}: {e}"
    if kind == "hc22000":
        try:
            text = head.decode(errors="strict")
        except UnicodeDecodeError:
            return False, f"{path} is binary, not a hashcat 22000 text file. Convert YOUR OWN .cap with: hcxpcapngtool -o out.hc22000 in.cap"
        first = text.splitlines()[0] if text.splitlines() else ""
        if "WPA*" not in first and first.count("*") < 3:
            return False, (f"{path} does not look like hashcat mode 22000 (first line should contain WPA* fields). "
                           f"Convert YOUR OWN .cap with: hcxpcapngtool -o out.hc22000 in.cap")
        return True, f"{path}: looks like hashcat 22000 ({size} bytes)."
    # .cap / .pcap / .pcapng: check magic bytes (classic pcap or pcapng)
    magics = (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x0a\x0d\x0d\x0a")
    if not any(head.startswith(m) for m in magics):
        return False, (f"{path} is not a pcap/pcapng capture (bad magic). "
                       f"Capture YOUR OWN AP with airodump-ng, or convert to .hc22000 first.")
    if size < 1000:
        return False, (f"{path} is suspiciously small ({size} bytes) — probably no handshake inside. "
                       f"Re-capture while one of YOUR OWN devices (re)connects. " + CAPTURE_HELP)
    return True, f"{path}: pcap magic OK ({size} bytes). NOTE: magic alone can't prove a full 4-way handshake is inside — aircrack/hashcat will report 'no handshake' if missing."

def build_audit_command(ssid, cap, hc22000, wordlist, use_gpu, show, tools=None):
    """Shared command builder for CLI + GUI. Returns (cmd, note) or raises SystemExit via fail()."""
    tools = tools or dict(detect_tools()[0])
    if hc22000:
        ok, msg = validate_handshake(hc22000, "hc22000")
        if not ok:
            fail(msg)
        if not tools.get("hashcat"):
            fail("hashcat not found. Install: sudo apt install hashcat")
        dev = "1,2" if use_gpu == "auto" else ("2" if use_gpu == "yes" else "1")
        cmd = [tools["hashcat"], "-m", "22000", "-a", "0", "-D", dev,
               "--status", "--status-timer", "5", hc22000, wordlist]
        if show:
            cmd.append("--show")
        return cmd, "hashcat runs until cracked/exhausted (persistent, Ctrl+C to quit)."
    if cap:
        ok, msg = validate_handshake(cap, "cap")
        if not ok:
            fail(msg)
        if not tools.get("aircrack-ng"):
            fail("aircrack-ng not found. Install: sudo apt install aircrack-ng (or use --hc22000 + hashcat)")
        if not ssid:
            fail("--ssid required for .cap")
        cmd = [tools["aircrack-ng"], cap, "-w", wordlist, "-e", ssid]
        return cmd, "aircrack runs full wordlist until KEY FOUND (persistent)."
    fail("Provide --cap OWN.cap or --hc22000 OWN.hc22000 from your own router.")

def cmd_audit(ssid, cap, hc22000, wordlist, jobs, use_gpu, show, ack):
    if not ack:
        fail(f"You must pass {LEGAL_ACK}.")
    if not wordlist or not os.path.isfile(wordlist):
        fail(f"wordlist not found: {wordlist}")
    tools, gpu = detect_tools()
    print(f"[*] tools={tools}\n[*] gpu:\n{gpu[:1500]}")
    cmd, note = build_audit_command(ssid, cap, hc22000, wordlist, use_gpu, show, tools)
    print(f"[*] {note}: {' '.join(cmd)}")
    if hc22000:
        print("[*] Get .hc22000 from YOUR OWN capture: hcxpcapngtool -o out.hc22000 in.cap")
    subprocess.run(cmd)  # hashcat/aircrack themselves are persistent; no early stop
    return

# --- interactive terminal shell ---
SHELL_HELP = """commands:
  help                          show this
  detect                        cpu/gpu/tools
  wifilist                      scan nearby APs (passive)
  test                          vuln assessment for set ssid (advanced, passive)
  benchmark [N]                 speed test (default 2000)
  set ssid NAME | wordlist F | jobs N | target PASS | cap F | hc22000 F | gpu auto|yes|no | showeach on|off
  show                          current settings
  check                         is target in wordlist? (fast, no crypto)
  start                         persistent crack until FOUND (CPU, lab simulation)
  audit                         real handshake audit via aircrack/hashcat until done
  exit
notes: start/audit never stop after a few tries — only FOUND / exhausted / Ctrl+C / 'exit'.
"""

def cmd_shell():
    cfg = {"ssid": "MyHome", "wordlist": "", "jobs": multiprocessing.cpu_count(),
           "target": "", "cap": "", "hc22000": "", "gpu": "auto", "showeach": "off"}
    print("wifi-audit shell — type 'help'. Your own network only.")
    while True:
        try:
            raw = input("wifi-audit> ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nbye."); break
        if not raw: continue
        try:
            p = shlex.split(raw)
        except ValueError as e:
            print(f"[!] {e}"); continue
        c, a = p[0].lower(), p[1:]
        if c in ("exit", "quit"): print("bye."); break
        elif c == "help": print(SHELL_HELP)
        elif c == "detect": cmd_detect()
        elif c == "show": print(cfg)
        elif c == "benchmark": cmd_benchmark(int(a[0]) if a else 2000, cfg["jobs"], cfg["ssid"])
        elif c == "set" and len(a) >= 2:
            k, v = a[0].lower(), " ".join(a[1:])
            if k in ("ssid", "wordlist", "target", "cap", "hc22000", "gpu"): cfg[k] = v; print(f"[=] {k}={v}")
            elif k == "jobs": cfg["jobs"] = int(v); print(f"[=] jobs={v}")
            elif k == "showeach" and v.lower() in ("on", "off"): cfg["showeach"] = v.lower(); print(f"[=] showeach={v.lower()}")
            else: print("[!] set ssid|wordlist|jobs|target|cap|hc22000|gpu|showeach(on|off)")
        elif c == "check":
            if not cfg["wordlist"] or not cfg["target"]: print("[!] set wordlist + target first")
            else: cmd_check_weak(cfg["target"], cfg["wordlist"])
        elif c == "start":
            if not cfg["wordlist"] or not cfg["target"]: print("[!] set wordlist + target first"); continue
            cmd_crack(cfg["ssid"], cfg["wordlist"], target_password=cfg["target"],
                      jobs=int(cfg["jobs"]), ack=True, show_each=(cfg["showeach"] == "on"))
        elif c == "audit":
            cmd_audit(cfg["ssid"] or None, cfg["cap"] or None, cfg["hc22000"] or None,
                      cfg["wordlist"], int(cfg["jobs"]), cfg["gpu"], False, True)
        elif c == "status":
            ck = open(CHECKPOINT).read().strip() if os.path.isfile(CHECKPOINT) else "none"
            print(f"cfg={cfg} checkpoint={ck}")
        elif c == "wifilist":
            cmd_wifilist()
        elif c == "test":
            if not cfg["ssid"]:
                print("[!] set ssid first (e.g. set ssid MyHome)")
            else:
                cmd_vuln_test(cfg["ssid"], cfg["wordlist"] or None, cfg["target"] or None)
        else: print("[!] unknown. type help")

def main():
    ap = argparse.ArgumentParser(prog="wifi-audit", description="Terminal offline WPA2 auditor (YOUR OWN network). Persistent until FOUND.")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("detect", help="cpu/gpu/tools")
    b = sub.add_parser("benchmark", help="speed test"); b.add_argument("--num-passwords", type=int, default=2000); b.add_argument("--jobs", type=int, default=None); b.add_argument("--ssid", default="TestSSID")
    c = sub.add_parser("check-weak", help="fast list check"); c.add_argument("--current-password", required=True); c.add_argument("--wordlist", required=True)
    k = sub.add_parser("crack", help="persistent CPU crack until FOUND (lab: your own known password)"); k.add_argument("--ssid", required=True); k.add_argument("--wordlist", required=True); k.add_argument("--target-password", default=None); k.add_argument("--target-pmk", default=None); k.add_argument("--jobs", type=int, default=None); k.add_argument("--resume-from", type=int, default=0); k.add_argument("--batch-size", type=int, default=400); k.add_argument("--show-each", action="store_true", help="log every candidate as [line/total] 'pw' -> WRONG/CORRECT"); k.add_argument(LEGAL_ACK, dest="i_own", action="store_true")
    a = sub.add_parser("audit", help="real handshake audit (persistent)"); a.add_argument("--ssid", default=None); a.add_argument("--cap", default=None); a.add_argument("--hc22000", default=None); a.add_argument("--wordlist", required=True); a.add_argument("--jobs", type=int, default=None); a.add_argument("--use-gpu", choices=["auto", "yes", "no"], default="auto"); a.add_argument("--show", action="store_true"); a.add_argument(LEGAL_ACK, dest="i_own", action="store_true")
    sub.add_parser("shell", help="interactive terminal with commands")
    w = sub.add_parser("wifilist", help="scan nearby APs (passive, no attacks)")
    t = sub.add_parser("test", help="advanced passive vuln assessment of YOUR OWN ssid"); t.add_argument("ssid"); t.add_argument("--wordlist", default=None); t.add_argument("--target-password", default=None)
    args = ap.parse_args()
    if args.cmd == "detect": cmd_detect()
    elif args.cmd == "wifilist": cmd_wifilist()
    elif args.cmd == "test": cmd_vuln_test(args.ssid, args.wordlist, args.target_password)
    elif args.cmd == "benchmark": cmd_benchmark(args.num_passwords, args.jobs, args.ssid)
    elif args.cmd == "check-weak": cmd_check_weak(args.current_password, args.wordlist)
    elif args.cmd == "crack": cmd_crack(args.ssid, args.wordlist, args.target_password, args.target_pmk, args.jobs, args.resume_from, args.batch_size, args.i_own, args.show_each)
    elif args.cmd == "audit": cmd_audit(args.ssid, args.cap, args.hc22000, args.wordlist, args.jobs or multiprocessing.cpu_count(), args.use_gpu, args.show, args.i_own)
    elif args.cmd == "shell": cmd_shell()

if __name__ == "__main__":
    main()
