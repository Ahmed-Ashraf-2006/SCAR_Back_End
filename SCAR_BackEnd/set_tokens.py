"""Create strong random tokens in .env for the SCAR backend. Run from the scar2 folder:

    .\venv\Scripts\python.exe set_tokens.py

- Only API_TOKEN, SECURITY_TOKEN and AI_TOKEN are touched, and only when they are missing, empty or still a
  "change-me" placeholder. A token that is already set is kept.
- Every other line of .env (DATABASE_URL, SENSOR_ID, CORS_ORIGINS ...) stays as it is.
- The token values are never printed. Open .env in your editor if you need to read one, and do not paste it in chat.
"""
import os
import re
import secrets
import sys

NAMES = ("API_TOKEN", "SECURITY_TOKEN", "AI_TOKEN")
path = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")

lines = []
if os.path.isfile(path):
    with open(path, encoding="utf-8-sig") as fh:
        lines = fh.read().splitlines()
elif os.path.isfile(path + ".txt"):
    sys.exit("Found .env.txt: rename it to .env (the name must be exactly .env) and run this again.")

state = {}
for i, line in enumerate(lines):
    m = re.match(r"\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$", line)
    if m and m.group(1) in NAMES:
        state[m.group(1)] = (i, m.group(2).strip().strip("'\""))

changed = []
for name in NAMES:
    current = state.get(name)
    if current and current[1] and not current[1].lower().startswith("change-me"):
        continue
    value = secrets.token_urlsafe(32)
    if current:
        lines[current[0]] = f"{name}={value}"
    else:
        lines.append(f"{name}={value}")
    changed.append(name)

if changed:
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write("\n".join(lines) + "\n")
print("Created new random values for:", ", ".join(changed) if changed else "nothing (all three were already set)")
print("Kept as they were:", ", ".join(n for n in NAMES if n not in changed) or "nothing")
print("File:", path)
print("Now stop the server (Ctrl+C) and start it again: .env is read only at startup.")
