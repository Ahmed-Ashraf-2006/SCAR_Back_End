import os
from dotenv import load_dotenv

load_dotenv()

APP_NAME = os.getenv("APP_NAME", "SCAR Backend")
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./scar.db")
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
# Dashboard / administrator token: dashboard reads of telemetry and drones, event status changes and deletes.
API_TOKEN = os.getenv("API_TOKEN", "")

# Separate credentials per sender (PROPOSED contract). When unset they fall back to API_TOKEN so older
# deployments keep working, but production should set all three to different secrets.
SECURITY_TOKEN = os.getenv("SECURITY_TOKEN") or API_TOKEN   # Wazuh / Zeek webhook, raw ingest, unified event create
AI_TOKEN = os.getenv("AI_TOKEN") or API_TOKEN               # internal AI automation endpoint
# PROPOSED: key for the AI team's root-level contract (header X-API-Key). No fallback on purpose: set it explicitly.
AI_CONTRACT_API_KEY = os.getenv("AI_CONTRACT_API_KEY", "")
# Drone tokens are NOT configured here: each drone has its own hashed token in the drones table
# (python -m app.drone_tokens create <drone_id>).

# Origins (front-end addresses) allowed to call the API from a browser, comma separated.
# PROPOSED defaults for local React development - confirm the real address with Mohamed Wahid.
CORS_ORIGINS = [
    o.strip()
    for o in os.getenv("CORS_ORIGINS", "http://localhost:3000,http://localhost:5173").split(",")
    if o.strip()
]

# A drone is "online" if telemetry was received within this many seconds (PROPOSED rule).
# 15 s = several missed 2 Hz packets / 5 s heartbeats. Was 120 s before the contract review.
ONLINE_WINDOW_SECONDS = int(os.getenv("ONLINE_WINDOW_SECONDS", "15"))

# Telemetry / health / event schema versions the backend accepts (major number).
SUPPORTED_SCHEMA_MAJORS = {1}

# Optional deployment-specific IP for the Zeek sensor. Never infer this from src/dst IPs.
SENSOR_IP = os.getenv("SENSOR_IP") or None
