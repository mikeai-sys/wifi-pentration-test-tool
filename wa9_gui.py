#!/usr/bin/env python3
"""wa9 auto - GUI picker (YOUR OWN network only). Choose WiFi + wordlist path, start audit."""
import os
import queue
import subprocess
import sys
import threading

HERE = os.path.dirname(os.path.realpath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, "/usr/local/lib/wa9")

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
        self.geometry("640x520")
        self.proc = None
        frm = ttk.Frame(self, padding=10)
        frm.pack(fill="both", expand=True)

        ttk.Label(frm, text="WiFi (your own):").grid(row=0, column=0, sticky="w")
        self.ssid = tk.StringVar(value="MyHome")
        self.box = ttk.Combobox(frm, textvariable=self.ssid, width=32)
        self.box.grid(row=0, column=1, sticky="ew")
        ttk.Button(frm, text="Refresh", command=self.refresh).grid(row=0, column=2, padx=5)

        ttk.Label(frm, text="Wordlist path:").grid(row=1, column=0, sticky="w")
        self.wl = tk.StringVar()
        ttk.Entry(frm, textvariable=self.wl, width=40).grid(row=1, column=1, sticky="ew")
        ttk.Button(frm, text="Browse...", command=self.browse).grid(row=1, column=2, padx=5)

        ttk.Label(frm, text="Target (own pw, lab):").grid(row=2, column=0, sticky="w")
        self.target = tk.StringVar()
        ttk.Entry(frm, textvariable=self.target, show="*", width=40).grid(row=2, column=1, sticky="ew")

        ttk.Label(frm, text="Jobs:").grid(row=3, column=0, sticky="w")
        self.jobs = tk.StringVar(value=str(os.cpu_count() or 4))
        ttk.Entry(frm, textvariable=self.jobs, width=10).grid(row=3, column=1, sticky="w")

        self.own = tk.BooleanVar(value=True)
        ttk.Checkbutton(frm, text="I own this network / have written permission", variable=self.own).grid(row=4, column=0, columnspan=3, sticky="w")

        btns = ttk.Frame(frm)
        btns.grid(row=5, column=0, columnspan=3, pady=8, sticky="ew")
        ttk.Button(btns, text="Test vulns", command=self.test).pack(side="left", padx=4)
        ttk.Button(btns, text="Start (until FOUND)", command=self.start).pack(side="left", padx=4)
        ttk.Button(btns, text="Stop", command=self.stop).pack(side="left", padx=4)

        self.log = tk.Text(frm, height=18, wrap="word")
        self.log.grid(row=6, column=0, columnspan=3, sticky="nsew")
        frm.rowconfigure(6, weight=1)
        frm.columnconfigure(1, weight=1)
        self.q = queue.Queue()
        self.after(200, self.pump)
        self.refresh()

    def emit(self, s):
        self.q.put(s)

    def pump(self):
        while not self.q.empty():
            self.log.insert("end", self.q.get())
            self.log.see("end")
        self.after(200, self.pump)

    def refresh(self):
        def work():
            try:
                nets = A.scan_networks()
                ssids = [n["ssid"] for n in sorted(nets, key=lambda x: -x["signal"])]
                self.emit(f"[*] found {len(ssids)} APs\n")
                self.after(0, lambda: self.box.configure(values=ssids))
                if ssids and not self.ssid.get():
                    self.after(0, lambda: self.ssid.set(ssids[0]))
            except Exception as e:
                self.emit(f"[!] scan failed: {e}\n")
        threading.Thread(target=work, daemon=True).start()

    def browse(self):
        p = filedialog.askopenfilename(title="Choose wordlist")
        if p:
            self.wl.set(p)

    def test(self):
        ssid = self.ssid.get().strip()
        if not ssid:
            messagebox.showwarning("wa9", "Choose a WiFi SSID first.")
            return
        wl = self.wl.get().strip() or None
        tp = self.target.get() or None
        def work():
            import io, contextlib
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                try:
                    A.cmd_vuln_test(ssid, wl, tp)
                except SystemExit as e:
                    buf.write(f"(exit {e})\n")
                except Exception as e:
                    buf.write(f"[!] {e}\n")
            self.emit(buf.getvalue())
        threading.Thread(target=work, daemon=True).start()

    def start(self):
        if self.proc and self.proc.poll() is None:
            messagebox.showinfo("wa9", "Already running.")
            return
        if not self.own.get():
            messagebox.showwarning("wa9", "Confirm you own this network first.")
            return
        ssid, wl = self.ssid.get().strip(), self.wl.get().strip()
        if not ssid or not wl or not os.path.isfile(wl):
            messagebox.showwarning("wa9", "Set valid SSID + wordlist path.")
            return
        base = os.path.join(HERE, "wifi_audit.py")
        if not os.path.isfile(base):
            base = "/usr/local/lib/wa9/wifi_audit.py"
        cmd = [sys.executable, base, "crack", "--ssid", ssid, "--wordlist", wl,
               "--jobs", self.jobs.get().strip() or "4", "--i-own-this-network"]
        if self.target.get():
            cmd += ["--target-password", self.target.get()]
        else:
            self.emit("[!] No target set: running requires --target-password (your own pw, lab mode).\n")
            return
        self.emit(f"[*] running: {' '.join(cmd[:6])} ...\n")
        self.proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
        def reader():
            for line in self.proc.stdout:
                self.emit(line)
            self.emit(f"\n[*] done (rc={self.proc.wait()})\n")
        threading.Thread(target=reader, daemon=True).start()

    def stop(self):
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            self.emit("[*] stop requested.\n")
        else:
            self.emit("[*] nothing running.\n")

if __name__ == "__main__":
    App().mainloop()
