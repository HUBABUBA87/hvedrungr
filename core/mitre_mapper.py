"""
core.mitre_mapper
-----------------
Maps raw trap events to records in terms of the MITRE ATT&CK matrix.

Within the PoC scope, a simplified correspondence dictionary is used: key shell
commands, typical authentication attempts, file actions, etc., are mapped to
tactics and techniques. For full SIEM integration, this dictionary can be
expanded or loaded from an external JSON.

Reference source: MITRE ATT&CK Enterprise Matrix v15
(https://attack.mitre.org/).
"""

from dataclasses import dataclass

# Table "signature -> (tactic, technique_id, description)"
# The signature is searched as a substring in the normalized command.
MAPPING = [
    # --- Initial Access ---
    ("__auth_attempt__", ("Credential Access", "T1110",
                          "Brute Force: password guessing attempt")),
    ("__many_auth_failures__", ("Credential Access", "T1110.001",
                                "Brute Force: Password Guessing")),
    # --- Discovery ---
    ("whoami",  ("Discovery", "T1033", "System Owner/User Discovery")),
    ("id",      ("Discovery", "T1033", "System Owner/User Discovery")),
    ("uname",   ("Discovery", "T1082", "System Information Discovery")),
    ("hostname", ("Discovery", "T1082", "System Information Discovery")),
    ("ifconfig", ("Discovery", "T1016", "System Network Configuration Discovery")),
    ("ip ",     ("Discovery", "T1016", "System Network Configuration Discovery")),
    ("netstat", ("Discovery", "T1049", "System Network Connections Discovery")),
    ("ps",      ("Discovery", "T1057", "Process Discovery")),
    ("ls",      ("Discovery", "T1083", "File and Directory Discovery")),
    ("find",    ("Discovery", "T1083", "File and Directory Discovery")),
    ("history", ("Discovery", "T1552.003", "Bash History")),
    # --- Credential Access ---
    ("cat /etc/passwd", ("Credential Access", "T1003.008",
                         "OS Credential Dumping: /etc/passwd")),
    ("cat /etc/shadow", ("Credential Access", "T1003.008",
                         "OS Credential Dumping: /etc/shadow")),
    (".bash_history", ("Credential Access", "T1552.003", "Bash History")),
    (".ssh/", ("Credential Access", "T1552.004", "Private Keys")),
    # --- Execution ---
    ("bash",  ("Execution", "T1059.004", "Unix Shell")),
    ("sh ",   ("Execution", "T1059.004", "Unix Shell")),
    ("/bin/sh", ("Execution", "T1059.004", "Unix Shell")),
    ("python", ("Execution", "T1059.006", "Python")),
    ("perl",  ("Execution", "T1059", "Command and Scripting Interpreter")),
    # --- Persistence / lateral movement hints ---
    ("crontab", ("Persistence", "T1053.003", "Scheduled Task: Cron")),
    ("ssh ",  ("Lateral Movement", "T1021.004", "SSH")),
    ("scp ",  ("Exfiltration", "T1048", "Exfiltration Over Alternative Protocol")),
    # --- Defense Evasion ---
    ("rm -rf", ("Defense Evasion", "T1070.004", "File Deletion")),
    ("history -c", ("Defense Evasion", "T1070.003", "Clear Command History")),
    # --- Command and Control / Ingress ---
    ("wget",  ("Command and Control", "T1105", "Ingress Tool Transfer")),
    ("curl",  ("Command and Control", "T1105", "Ingress Tool Transfer")),
    # --- Honeytoken trigger ---
    ("__honeytoken__", ("Initial Access", "T1078",
                        "Valid Accounts: valid accounts usage")),
    # --- Reconnaissance proper ---
    ("__tcp_connect__", ("Reconnaissance", "T1595.001",
                         "Active Scanning: Scanning IP Blocks")),
]


@dataclass
class MitreMatch:
    tactic: str
    technique_id: str
    description: str

    def as_dict(self) -> dict:
        return {
            "tactic": self.tactic,
            "technique_id": self.technique_id,
            "description": self.description,
        }


def map_event(signature: str) -> MitreMatch:
    """
    Finds the best signature match with the mapping table.
    If nothing matches, returns the generic Discovery category.
    """
    text = (signature or "").lower().strip()
    for key, (tactic, tid, desc) in MAPPING:
        if key in text:
            return MitreMatch(tactic, tid, desc)
    return MitreMatch("Discovery", "T1083",
                      "File and Directory Discovery (default)")
