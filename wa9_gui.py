#!/usr/bin/env python3
"""wa9 auto - GUI picker (YOUR OWN network only).

Two modes:
  REAL handshake audit (.cap/.hc22000 from YOUR OWN AP + wordlist)
      -> actually tests the WiFi password via aircrack-ng / hashcat.
  LAB demo (your own KNOWN password + wordlist)
      -> proves engine speed/persistence; does NOT recover unknown passwords.

Needs: python3-tk. Needs a display ($DISPLAY on Linux).
Real audit additionally needs aircrack-ng and/or hashcat (see backend line).
"""
import os
import queue
import signal
import subprocess
import sys
import threading

HERE = os.path.dirname(os.path.realpath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, "/usr/local/lib/wa9")

if sys.platform.startswith("linux") and not os.environ.get("DISPLAY"):
    print("[!] No display found ($DISPLAY is unset). 'wa9 auto' needs a graphical "
          "session.\n"
          "    Options: run on a desktop, or use the terminal instead:\n"
          "      wa9 wifilist\n"
          "      wa9 test 'MyHome'\n"
          "      wa9 audit --hc22000 myown.hc22000 --wordlist rockyou.txt --use-gpu auto --i-own-this-network",
          file=sys.stderr)
    sys.exit(2)

try:
    import tkinter as tk
    from tkinter import ttk, filedialog, messagebox
except ImportError:
    print("[!] tkinter missing. Install: sudo apt install -y python3-tk", file=sys.stderr)
    sys.exit(1)

import wifi_audit as A


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("wa9 auto - own network only")
        self.geometry("680x600")
        self.proc = None
        frm = ttk.Frame(self, padding=10)
        frm.pack(fill="both", expand=True)

        # mode
        ttk.Label(frm, text="Mode:").grid(row=0, column=0, sticky="w")
        self.mode = tk.StringVar(value="real")
        modes = ttk.Frame(frm)
        modes.grid(row=0, column=1, columnspan=2, sticky="w")
        ttk.Radiobutton(modes, text="Real: handshake file + wordlist (tests the WiFi password)",
                        variable=self.mode, value="real", command=self._mode_ui).pack(anchor="w")
        ttk.Radiobutton(modes, text="Lab demo: known password + wordlist (speed test only)",
                        variable=self.mode, value="lab", command=self._mode_ui).pack(anchor="w")

        ttk.Label(frm, text="WiFi (your own):").grid(row=1, column=0, sticky="w")
        self.ssid = tk.StringVar(value="MyHome")
        self.box = ttk.Combobox(frm, textvariable=self.ssid, width=34)
        self.box.grid(row=1, column=1, sticky="ew")
        ttk.Button(frm, text="Refresh", command=self.refresh).grid(row=1, column=2, padx=5)

        ttk.Label(frm, text="Wordlist path:").grid(row=2, column=0, sticky="w")
        self.wl = tk.StringVar()
        ttk.Entry(frm, textvariable=self.wl, width=42).grid(row=2, column=1, sticky="ew")
        ttk.Button(frm, text="Browse...", command=lambda: self._pick(self.wl, "Choose wordlist")).grid(row=2, column=2, padx=5)

        ttk.Label(frm, text="Handshake file:").grid(row=3, column=0, sticky="w")
        self.hs = tk.StringVar()
        self.hs_entry = ttk.Entry(frm, textvariable=self.hs, width=42)
        self.hs_entry.grid(row=3, column=1, sticky="ew")
        self.hs_btn = ttk.Button(frm, text="Browse...",
                                 command=lambda: self._pick(self.hs, "Choose .cap / .hc22000",
                                                            [("Captures", "*.cap *.pcap *.pcapng *.hc22000"), ("All", "*")]))
        self.hs_btn.grid(row=3, column=2, padx=5)

        ttk.Label(frm, text="Target (lab only):").grid(row=4, column=0, sticky="w")
        self.target = tk.StringVar()
        self.target_entry = ttk.Entry(frm, textvariable=self.target, show="*", width=42)
        self.target_entry.grid(row=4, column=1, sticky="ew")

        opt = ttk.Frame(frm)
        opt.grid(row=5, column=0, columnspan=3, sticky="w", pady=2)
        ttk.Label(opt, text="Jobs:").pack(side="left")
        self.jobs = tk.StringVar(value=str(os.cpu_count() or 4))
        ttk.Entry(opt, textvariable=self.jobs, width=6).pack(side="left", padx=4)
        ttk.Label(opt, text="GPU:").pack(side="left", padx=(10, 0))
        self.gpu = tk.StringVar(value="auto")
        ttk.Combobox(opt, textvariable=self.gpu, values=["auto", "yes", "no"], width=6).pack(side="left", padx=4)
        self.show_each = tk.BooleanVar(value=False)
        ttk.Checkbutton(opt, text="show each password (verbose, more memory)", variable=self.show_each).pack(side="left", padx=(10, 0))

        self.backend = tk.StringVar(value="backends: checking...")
        ttk.Label(frm, textvariable=self.backend, foreground="gray").grid(row=6, column=0, columnspan=3, sticky="w")

        self.own = tk.BooleanVar(value=True)
        ttk.Checkbutton(frm, text="I own this network / have written permission",
                        variable=self.own).grid(row=7, column=0, columnspan=3, sticky="w")

        btns = ttk.Frame(frm)
        btns.grid(row=8, column=0, columnspan=3, pady=8, sticky="ew")
        ttk.Button(btns, text="Test vulns", command=self.test).pack(side="left", padx=4)
        ttk.Button(btns, text="Start (until FOUND)", command=self.start).pack(side="left", padx=4)
        ttk.Button(btns, text="Stop", command=self.stop).pack(side="left", padx=4)

        self.log = tk.Text(frm, height=16, wrap="word")
        self.log.grid(row=9, column=0, columnspan=3, sticky="nsew")
        frm.rowconfigure(9, weight=1)
        frm.columnconfigure(1, weight=1)
        self.q = queue.Queue()
        self.after(200, self.pump)
        self._mode_ui()
        self.refresh()
        self._backend_status()

    # ----- ui helpers -----
    def _mode_ui(self):
        real = self.mode.get() == "real"
        self.hs_entry.configure(state="normal" if real else "disabled")
        self.hs_btn.configure(state="normal" if real else "disabled")
        self.target_entry.configure(state="disabled" if real else "normal")

    def _pick(self, var, title, types=None):
        p = filedialog.askopenfilename(title=title, filetypes=types or [("All", "*")])
        if p:
            var.set(p)

    def emit(self, s):
        self.q.put(s)

    def pump(self):
        while not self.q.empty():
            self.log.insert("end", self.q.get())
        # RAM guard: keep the log widget bounded (verbose mode can flood it)
        try:
            lines = int(self.log.index("end-1c").split(".")[0])
            if lines > 3000:
                self.log.delete("1.0", f"{lines - 3000}.0")
        except tk.TclError:
            pass
        self.log.see("end")
        self.after(200, self.pump)

    def _backend_status(self):
        def work():
            try:
                tools, _ = A.detect_tools()
                have = [k for k, v in tools.items() if v]
                miss = [k for k, v in tools.items() if not v]
                msg = f"backends: have [{', '.join(have) or 'none'}]"
                if miss:
                    msg += f" | missing [{', '.join(miss)}] -> ./install.sh"
                if not tools.get("hashcat") and not tools.get("aircrack-ng"):
                    msg += " | REAL audit unavailable, lab demo only"
                self.emit(f"[*] {msg}\n")
                self.after(0, lambda: self.backend.set(msg))
            except Exception as e:
                self.emit(f"[!] backend check failed: {e}\n")
        threading.Thread(target=work, daemon=True).start()

    def refresh(self):
        def work():
            try:
                nets = A.scan_networks()
                ssids = [n["ssid"] for n in sorted(nets, key=lambda x: x["signal"], reverse=True)]
                self.emit(f"[*] scan: found {len(ssids)} APs\n")
                self.after(0, lambda: self.box.configure(values=ssids))
                if ssids and not self.ssid.get():
                    self.after(0, lambda: self.ssid.set(ssids[0]))
            except Exception as e:
                self.emit(f"[!] scan failed: {e}\n")
        threading.Thread(target=work, daemon=True).start()

    def test(self):
        ssid = self.ssid.get().strip()
        if not ssid:
            messagebox.showwarning("wa9", "Choose a WiFi SSID first.")
            return
        wl = self.wl.get().strip() or None
        tp = self.target.get() or None
        if wl and not os.path.isfile(wl):
            messagebox.showwarning("wa9", f"Wordlist not found:\n{wl}")
            return

        def work():
            import io, contextlib
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                try:
                    A.cmd_vuln_test(ssid, wl, tp)
                except SystemExit as e:
                    # fail() prints its own message to stderr; mirror the code only
                    buf.write(f"(aborted, exit {e.code})\n")
                except Exception as e:
                    buf.write(f"[!] {e}\n")
            self.emit(buf.getvalue())
        threading.Thread(target=work, daemon=True).start()

    def _base_script(self):
        base = os.path.join(HERE, "wifi_audit.py")
        if not os.path.isfile(base):
            base = "/usr/local/lib/wa9/wifi_audit.py"
        return base

    def start(self):
        if self.proc and self.proc.poll() is None:
            messagebox.showinfo("wa9", "Already running.")
            return
        if not self.own.get():
            messagebox.showwarning("wa9", "Confirm you own this network first.")
            return
        ssid = self.ssid.get().strip()
        wl = self.wl.get().strip()
        if not ssid:
            messagebox.showwarning("wa9", "Set the SSID of YOUR OWN network.")
            return
        if not wl or not os.path.isfile(wl):
            messagebox.showwarning("wa9", "Set a valid wordlist path.")
            return
        try:
            jobs = int((self.jobs.get() or "4").strip())
            if jobs < 1:
                raise ValueError
        except ValueError:
            messagebox.showwarning("wa9", "Jobs must be a positive integer.")
            return
        base = self._base_script()
        if self.mode.get() == "real":
            hs = self.hs.get().strip()
            if not hs or not os.path.isfile(hs):
                messagebox.showwarning("wa9", "REAL mode needs your handshake file (.cap or .hc22000).")
                return
            kind = "hc22000" if hs.lower().endswith(".hc22000") else "cap"
            ok, msg = A.validate_handshake(hs, kind)
            if not ok:
                messagebox.showwarning("wa9", msg[:800])
                self.emit(f"[!] {msg}\n")
                return
            self.emit(f"[*] {msg}\n")
            cmd = [sys.executable, base, "audit", "--ssid", ssid, "--wordlist", wl,
                   "--use-gpu", self.gpu.get().strip() or "auto", "--i-own-this-network"]
            cmd += ["--hc22000", hs] if kind == "hc22000" else ["--cap", hs]
        else:
            tp = self.target.get()
            if not tp:
                messagebox.showwarning("wa9", "LAB demo needs your KNOWN password in 'Target'.\n"
                                              "To test an UNKNOWN WiFi password, use REAL mode with a handshake file.")
                return
            cmd = [sys.executable, base, "crack", "--ssid", ssid, "--wordlist", wl,
                   "--jobs", str(jobs), "--target-password", tp, "--i-own-this-network"]
            if self.show_each.get():
                cmd.append("--show-each")
        self.emit(f"[*] running: {' '.join(cmd[:7])} ...\n")
        try:
            self.proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                         text=True, bufsize=1, start_new_session=True)
        except Exception as e:
            messagebox.showwarning("wa9", f"Could not start backend:\n{e}")
            return

        def reader():
            try:
                for line in self.proc.stdout:
                    self.emit(line)
            except Exception as e:
                self.emit(f"[!] reader error: {e}\n")
            try:
                rc = self.proc.wait()
            except Exception:
                rc = "?"
            self.emit(f"\n[*] done (rc={rc})\n")
        threading.Thread(target=reader, daemon=True).start()

    def stop(self):
        p = self.proc
        if p and p.poll() is None:
            try:
                os.killpg(os.getpgid(p.pid), signal.SIGTERM)
            except Exception:
                try:
                    p.terminate()
                except Exception as e:
                    self.emit(f"[!] stop failed: {e}\n")
                    return
            self.emit("[*] stop requested.\n")
        else:
            self.emit("[*] nothing running.\n")


if __name__ == "__main__":
    try:
        App().mainloop()
    except KeyboardInterrupt:
        # Ctrl+C in the terminal: close quietly, no traceback
        print("\nbye.")
        sys.exit(130)
    except tk.TclError as e:
        print(f"[!] Cannot open GUI ({e}).\n"
              "    'wa9 auto' needs a display. Alternatives:\n"
              "      wa9 wifilist\n"
              "      wa9 test 'MyHome'\n"
              "      wa9 audit --hc22000 myown.hc22000 --wordlist rockyou.txt --use-gpu auto --i-own-this-network",
              file=sys.stderr)
        sys.exit(2)
