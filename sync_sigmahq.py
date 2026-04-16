#!/usr/bin/env python3
import requests
from pathlib import Path
SIGMAHQ = "https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules/windows/"
LOCAL_RULES = Path("rules/sigma")
LOCAL_RULES.mkdir(exist_ok=True)
rules = ["process_creation/proc_creation_win_powershell.yml"]
for rule in rules:
    resp = requests.get(SIGMAHQ + rule)
    if resp.status_code == 200:
        (LOCAL_RULES / rule.split("/")[-1]).write_text(resp.text)
        print(f"✓ {rule}")
