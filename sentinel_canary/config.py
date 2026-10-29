# config.py
# Saare thresholds, paths, weights EK JAGAH yahin rakhe hain.
# Tuning karni ho toh sirf ye file edit karo — code kahin aur chhune ki zaroorat nahi.

import os

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
BASE_DIR   = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR   = os.path.join(BASE_DIR, "data")            # canary files + db yahin
HONEY_DIR  = os.path.join(DATA_DIR, "honey")           # yahin bait files banti hain
SNAP_DIR   = os.path.join(DATA_DIR, "snapshots")       # rollback ke liye backups
DB_PATH    = os.path.join(DATA_DIR, "sentinel.db")     # sqlite database
LOG_PATH   = os.path.join(DATA_DIR, "sentinel.log")    # text log

# ---------------------------------------------------------------------------
# Canary (bait) files — naam aise jo attacker ko lage "sensitive" hai
# ---------------------------------------------------------------------------
CANARY_FILES = [
    "passwords.txt",
    "financials_Q3.docx",
    "backup_keys.pem",
    "employees.xlsx",
    ".ssh_config",
]
# kitne honey sub-directories banane hain
HONEY_SUBDIRS = ["documents", "backups", "finance"]

# ---------------------------------------------------------------------------
# Detection — entropy + rate-of-change
# ---------------------------------------------------------------------------
# Shannon entropy normal text ~4-5 bit/byte hoti hai; encrypted data ~7.5-8.
# Is range ke beech aaya toh suspicious.
ENTROPY_HIGH        = 7.2     # is se upar = pakka encryption-like
ENTROPY_SUSPICIOUS  = 6.0     # is se upar = thoda suspicious

# rate-of-change: ek process kitne file events/sec kar raha hai.
# ransomware mass-modify karta hai, normal user nahi.
RATE_WINDOW_SEC     = 3.0     # kitne seconds ka window dekhenge
RATE_MANY_EVENTS    = 8       # is se zyada events window me = mass modification

# Canaries ko koi bhi chhue toh suspicious hai hi (kyunki legit program unhe nahi chhuta).
CANARY_TOUCH_SCORE  = 40      # bas canary touch karne pe itna score

# ---------------------------------------------------------------------------
# Scoring — explainable risk score 0..100
# Har signal ka weight yahin. Sum clamp hoga 0..100 pe.
# ---------------------------------------------------------------------------
W_ENTROPY_HIGH      = 50      # entropy bahut high
W_ENTROPY_SUSP      = 25      # entropy thodi high
W_RATE              = 20      # mass modification (rate high)
W_CANARY            = CANARY_TOUCH_SCORE
W_RENAME_EXT        = 15      # file rename + weird extension (.enc/.locked)
SCORE_ALERT         = 60      # is se upar = ALERT (mitigation trigger)

# ---------------------------------------------------------------------------
# Mitigation — fail2ban style escalation (watchlist -> temp -> permanent)
# ---------------------------------------------------------------------------
STRIKES_FOR_TEMP    = 1       # kitne alerts ke baad temp block
STRIKES_FOR_PERM    = 3       # kitne alerts ke baad permanent block
TEMP_BLOCK_SECONDS  = 60      # temp block kitne der (demo ke liye chhota)
KILL_PROCESS        = True    # malicious PID ko terminate karna hai ya nahi

# Ransomware-jaise extensions — detector inhe rename/touch pe flag karta hai.
RANSOM_EXTS = (".enc", ".locked", ".crypt", ".crypto", ".encrypted",
               ".ransom", ".lockbit", ".ryuk", ".crypted")

# ---------------------------------------------------------------------------
# Real ransomware simulator (ACTUAL encryption — demo ke liye)
# ---------------------------------------------------------------------------
# Kis extension se "encrypted" files mark hongi (RANSOM_EXTS me honi chahiye).
RANSOM_EXT         = ".locked"
# Kitni files encrypt kare (real sim) + per-file delay
RANSOM_DELAY_SEC   = 0.05
# real crypto ke liye — cryptography lib ho toh Fernet/AES, warna XOR fallback.
REAL_CRYPTO        = True
SIM_TARGET_DIR     = HONEY_DIR   # real sim honey dir pe chalega

# ---------------------------------------------------------------------------
# ML classifier (optional — sklearn guarded)
# ---------------------------------------------------------------------------
USE_ML             = False       # True karne pe rule-score me ml-prob add hoti hai
ML_WEIGHT          = 30          # ml-prob ko score me kaise add kare
ML_MODEL_PATH      = os.path.join(DATA_DIR, "model.pkl")

# ---------------------------------------------------------------------------
# Simulator (demo ke liye, real malware ke bina)
# ---------------------------------------------------------------------------
SIM_SEED            = 1337    # fixed seed => repeatable demo
SIM_BENIGN_EVENTS   = 12      # kitne normal events
SIM_ATTACK_EVENTS   = 18      # kitne attack events
SIM_ATTACK_PROB     = 0.55    # attack burst probability mix

# ---------------------------------------------------------------------------
# Optional features — heavy deps guarded rehte hain
# ---------------------------------------------------------------------------
USE_WATCHDOG   = True   # live filesystem watcher (watchdog installed ho toh)
USE_DASHBOARD  = True   # fastapi dashboard (installed ho toh)
USE_NOTIFY     = True   # desktop notification (plyer installed ho toh)

# network kill-switch (needs root). Default OFF — app-level mitigation kaafi hai.
ENABLE_NET_KILLSWITCH = False
