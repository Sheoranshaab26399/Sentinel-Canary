# Sentinel-Canary — Project Blueprint & Resume Notes

**Real-Time Ransomware Detection & Mitigation System** using File-System Watchers, Shannon Entropy Analysis and an Automated Network Kill-Switch.

*Individual project — Kunal*

---

## 1. What the project is (one-liner for resume)

> A host-based ransomware mitigation engine that plants decoy "canary" files, watches them in real time for ransomware-style encryption (via filesystem events + Shannon entropy), and instantly isolates the machine from the network and kills the offending process — cutting Mean-Time-To-Respond from minutes to milliseconds.

Traditional antivirus fails against modern ransomware because it relies on **signatures**, and ransomware uses polymorphic/never-seen-before code. Sentinel-Canary instead detects **behaviour** — no signature database needed, so it catches zero-day ransomware too.

---

## 2. The core idea (how it works)

1. **Honey / Canary files** — We scatter fake "sensitive-looking" files (`passwords.xlsx`, `backup_passwords.txt`, `financials_Q3.docx`) across decoy directories. No legitimate program ever touches them.
2. **Filesystem watcher** — A watchdog daemon monitors these files 24/7 for create/modify/delete/rename events.
3. **Entropy analysis** — When a file is modified, we compute its **Shannon entropy**. Ransomware encryption produces near-random, high-entropy output (~7.5–8 bits/byte) versus normal text/doc edits (~4–6). High entropy + a canary file being touched = almost certainly ransomware.
4. **Kill-Switch** — On detection, the system automatically:
   - Identifies the **PID** of the process doing the encryption and **terminates** it.
   - Drops the network interface / injects a firewall rule to **isolate the host**, so the ransomware can't spread to network shares or exfiltrate data.
5. **Alert + log** — Everything is logged and an alert fired for forensics.

The beauty: even if the ransomware is brand-new and no AV has a signature for it, touching a canary file trips the alarm.

---

## 3. Tech stack (what's used inside)

- **Language:** Python 3.x
- **Watchdog** — filesystem event monitoring (the watcher daemon)
- **psutil** — find and kill the malicious process (PID → terminate)
- **math / collections** — Shannon entropy calculation over file bytes
- **subprocess / os / firewall cmds** — run `ip link set down`, `iptables`/`nftables`/`ufw` or Windows Firewall rules to isolate the host
- **logging / JSON / SQLite** — event & forensic logging
- **Scapy / tcpdump / Wireshark** — verify network isolation
- **(optional) plyer / smtplib / Slack webhook** — desktop / email / chat alerts
- **OS:** Linux (Ubuntu/Kali) primary; can extend to Windows
- **Test setup:** 2 VMs on a virtual LAN — one running Sentinel-Canary, one simulating the ransomware attack

---

## 4. Features — what it can do (build list)

**Core (must-have):**
- Decoy canary-file generator (creates believable bait files in honey dirs)
- Real-time recursive filesystem watcher
- Shannon-entropy-based encryption detector (with threshold tuning)
- Process attribution — find *which* PID encrypted the file
- Automatic process kill
- Network kill-switch (interface down / firewall block)
- Forensic event log (timestamp, file, PID, entropy, action taken)

**Impressive extras (ALL IN SCOPE — building every one of these):**
- **Entropy + rate-of-change scoring** — flag *mass* modification (many files/sec), not just one file → catches ransomware mid-sweep
- **Baseline learning / threshold tuning** — reduce false positives
- **Snapshot & rollback** — auto-backup a canary dir; restore files after an attack
- **Live CLI / web dashboard** — show watcher status, alerts, entropy graph
- **Alerting** — desktop notification / email / Slack webhook
- **Configurable rules** (YAML/JSON) — which dirs to protect, entropy threshold, whitelist processes
- **Safe-mode / dry-run** — detect & alert without killing (for demos/testing)
- **Cross-platform kill-switch** — works on Linux + Windows
- **A demo "safe ransomware" simulator** you write yourself to *prove* it works in a VM — huge for interviews

---

## 5. Resume bullet points (ready to paste)

- Built a **behavior-based ransomware detection system** that plants decoy canary files and detects encryption activity in real time — catches zero-day ransomware that signature AV misses.
- Implemented **Shannon entropy analysis** to distinguish ransomware encryption (high-entropy output) from normal file writes, reducing false positives.
- Designed an **automated network kill-switch** that isolates an infected host and terminates the malicious PID within milliseconds, cutting MTTR.
- Used **Python (Watchdog, psutil, iptables/ufw)** on Linux; tested end-to-end across a 2-VM virtual LAN with a self-written ransomware simulator.
- *(stretch)* Added snapshot/rollback and a live monitoring dashboard for forensic visibility.

---

## 6. Architecture → build roadmap (start to finish)

```
[Canary File Generator] → plants bait files in honey dirs
        ↓
[Watchdog Daemon] —— file events (create/modify/rename/delete)
        ↓
[Analysis Engine] —— Shannon entropy + rate-of-change scoring
        ↓                                    (threshold crossed?)
                    no → keep watching        yes ↓
[Response Engine] ——→ 1. get PID (psutil) → kill process
                      2. firewall/iface down → isolate host
                      3. log + alert → forensic record
```

**Step-by-step build order:**

1. **Setup** — 2 Linux VMs on a virtual LAN; Python env; install watchdog/psutil.
2. **Canary generator** — function that creates convincing bait files/dirs.
3. **Watcher** — Watchdog observer on honey dirs; print/log raw events first.
4. **Entropy engine** — Shannon-entropy function; test it on a normal file vs an encrypted file to pick a threshold.
5. **Detection logic** — combine "is a canary file" + "high entropy" + "many events/sec" → trigger.
6. **Response: process kill** — map the event to a PID (psutil) and terminate it.
7. **Response: kill-switch** — subprocess call to bring interface down / add firewall rule; verify with ping/tcpdump.
8. **Logging + alerting** — structured logs (JSON/SQLite) + notification.
9. **Ransomware simulator** — a small harmless script that recursively "encrypts" (XOR/randomize) files in a test dir, so you can demo detection safely.
10. **Extras** — config file, dashboard, snapshot/rollback, whitelist, dry-run mode.
11. **Test & harden** — run the simulator, confirm: detection fires, PID killed, network isolated, files recoverable; tune threshold to kill false positives.

---

*Next step: start building — begin with the canary generator + watcher, then layer entropy detection, then the kill-switch.*
