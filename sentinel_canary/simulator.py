# simulator.py
# Fixed seed ke saath benign + attack file-events generate karta hai.
# Real malware ke bina poora pipeline test karne ke liye — repeatable demo.

import random

from . import config

# benign (normal) files — legit user inko edit karta hai
_BENIGN = [
    "notes.txt", "readme.md", "report.docx", "main.py", "data.csv",
    "todo.txt", "thesis_ch2.docx", "budget.csv",
]
# attack ke waqt ransomware canary files encrypt karta hai
_ATTACK = [
    "honey/documents/passwords.txt",
    "honey/finance/financials_Q3.docx",
    "honey/backups/backup_keys.pem",
    "honey/documents/employees.xlsx",
]


class EventSimulator:
    """
    Benign + attack events ka stream deta hai.
    Attack = ek pid jo honey files ko high-entropy se modify karta hai.
    """

    def __init__(self, seed: int = config.SIM_SEED):
        self.rng = random.Random(seed)

    def events(self):
        """
        Event dicts ka list yield karo:
        {type,path,pid,entropy}
        benign: low entropy, normal pid, random files
        attack: high entropy, ek 'malicious' pid, honey files, rapid rate
        """
        benign_pid = 1200
        attack_pid = 6666  # "malware" pid

        evs = []
        # interleave: thoda benign, phir attack burst, phir benign
        for _ in range(config.SIM_BENIGN_EVENTS):
            evs.append({
                "type": "modified",
                "path": f"user/docs/{self.rng.choice(_BENIGN)}",
                "pid": benign_pid,
                "entropy": self.rng.uniform(4.0, 5.2),  # normal text entropy
            })
        # attack burst — kai honey files jaldi-jaldi encrypt
        for _ in range(config.SIM_ATTACK_EVENTS):
            evs.append({
                "type": "modified",
                "path": self.rng.choice(_ATTACK),
                "pid": attack_pid,
                "entropy": self.rng.uniform(7.4, 7.99),  # encryption-like
            })
        # thoda benign ending me
        for _ in range(4):
            evs.append({
                "type": "modified",
                "path": f"user/docs/{self.rng.choice(_BENIGN)}",
                "pid": benign_pid,
                "entropy": self.rng.uniform(4.0, 5.0),
            })
        return evs
