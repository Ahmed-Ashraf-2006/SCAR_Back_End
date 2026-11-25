"""Black-box security check of a running SCAR backend.

    python -m security_scripts.api_security_check --url https://scar.example.com
    # reads API_TOKEN / SECURITY_TOKEN / AI_TOKEN from the environment or .env (optional but gives more checks)

It sends harmless requests and verifies the authentication rules described in the backend README:
  * every write route refuses requests without a token or with a wrong token (401);
  * a token of one class does not open the routes of another class (needs 3 different secrets);
  * PATCH / DELETE on events need the dashboard token;
  * the server is not using the placeholder secrets from .env.example;
  * the URL uses HTTPS (otherwise Bearer tokens are readable on the network).

It never creates or deletes real data: protected requests are sent with an invalid body or a non-existent
event id (999999999) and a wrong token FIRST. Requests with a VALID token are only sent to the read route
GET /api/v1/drones and to POST /api/v1/ingest/wazuh with an invalid body (expected 422, nothing stored).

Exit code: 0 all checks passed, 1 at least one FAIL, 2 server not reachable.
"""
import argparse
import os
import sys

from security_scripts.common import DEFAULT_URL, http_json, load_env_file

PLACEHOLDERS = ("change-me", "changeme", "secret", "password", "test", "example")
NO_EVENT = 999999999

# (method, path, body) - routes that must refuse a missing or wrong token
PROTECTED = [
    ("POST", "/api/v1/telemetry", {}),
    ("POST", "/api/v1/health", {}),
    ("POST", "/api/v1/drone-events", {}),
    ("POST", "/api/v1/events", {}),
    ("POST", "/api/v1/alerts", {}),
    ("POST", "/api/v1/ingest/wazuh", {}),
    ("POST", "/api/v1/ai/analysis", {}),
    ("PATCH", f"/api/v1/events/{NO_EVENT}/status", {"status": "resolved"}),
    ("PATCH", f"/api/v1/alerts/{NO_EVENT}/status", {"status": "resolved"}),
    ("DELETE", f"/api/v1/events/{NO_EVENT}", None),
    ("GET", "/api/v1/drones", None),
    ("GET", "/api/v1/telemetry", None),
]


class Report:
    def __init__(self):
        self.rows = []

    def add(self, level: str, name: str, detail: str = ""):
        self.rows.append((level, name, detail))
        print(f"[{level:4s}] {name}" + (f" - {detail}" if detail else ""))

    @property
    def failed(self) -> bool:
        return any(level == "FAIL" for level, _, _ in self.rows)


def run(url: str, api_token: str, security_token: str, ai_token: str) -> Report:
    base = url.rstrip("/")
    rep = Report()

    status, _ = http_json("GET", f"{base}/health")
    if status == 0:
        rep.add("FAIL", "server reachable", f"cannot connect to {base}")
        return rep
    rep.add("PASS", "server reachable", f"GET /health -> {status}")

    if base.startswith("https://"):
        rep.add("PASS", "transport is HTTPS")
    elif base.startswith(("http://127.", "http://localhost")):
        rep.add("INFO", "transport is plain HTTP", "acceptable on localhost only")
    else:
        rep.add("FAIL", "transport is HTTPS", "Bearer tokens travel in clear text")

    for method, path, body in PROTECTED:
        no_token, _ = http_json(method, base + path, body=body)
        wrong, _ = http_json(method, base + path, token="definitely-not-a-valid-token", body=body)
        name = f"{method} {path.replace(str(NO_EVENT), '{id}')} refuses missing/wrong token"
        if no_token == 401 and wrong == 401:
            rep.add("PASS", name)
        else:
            rep.add("FAIL", name, f"no token -> {no_token}, wrong token -> {wrong} (expected 401)")

    tokens = {"API_TOKEN": api_token, "SECURITY_TOKEN": security_token, "AI_TOKEN": ai_token}
    given = {k: v for k, v in tokens.items() if v}
    if not given:
        rep.add("SKIP", "token-class checks", "set API_TOKEN / SECURITY_TOKEN / AI_TOKEN to run them")
        return rep

    for name, value in given.items():
        if any(mark in value.lower() for mark in PLACEHOLDERS) or len(value) < 24:
            rep.add("FAIL", f"{name} is a strong secret", "looks like a placeholder or is shorter than 24 characters")
        else:
            rep.add("PASS", f"{name} is a strong secret")
    if len(given) > 1 and len(set(given.values())) < len(given):
        rep.add("FAIL", "three different secrets", "two credential classes share the same value (fallback to API_TOKEN?)")
    elif len(given) == 3:
        rep.add("PASS", "three different secrets")

    if api_token:
        status, _ = http_json("GET", f"{base}/api/v1/drones", token=api_token)
        rep.add("PASS" if status == 200 else "FAIL", "API_TOKEN opens dashboard reads", f"GET /drones -> {status}")
        if security_token and security_token != api_token:
            status, _ = http_json("GET", f"{base}/api/v1/drones", token=security_token)
            rep.add("PASS" if status == 401 else "FAIL", "SECURITY_TOKEN cannot read the dashboard routes", f"-> {status}")
    if security_token:
        status, _ = http_json("POST", f"{base}/api/v1/ingest/wazuh", token=security_token, body={"invalid": "event"})
        rep.add("PASS" if status == 422 else "FAIL", "SECURITY_TOKEN accepted by ingest (invalid body -> 422)", f"-> {status}")
        if ai_token and ai_token != security_token:
            status, _ = http_json("POST", f"{base}/api/v1/ingest/wazuh", token=ai_token, body={"invalid": "event"})
            rep.add("PASS" if status == 401 else "FAIL", "AI_TOKEN cannot use the ingest route", f"-> {status}")
    return rep


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="Black-box authentication check of a running SCAR backend.")
    p.add_argument("--url", default=None, help=f"backend base URL (default $SCAR_API_URL or {DEFAULT_URL})")
    args = p.parse_args(argv)
    load_env_file()
    url = args.url or os.getenv("SCAR_API_URL", DEFAULT_URL)
    rep = run(url, os.getenv("API_TOKEN", ""), os.getenv("SECURITY_TOKEN", ""), os.getenv("AI_TOKEN", ""))
    passed = sum(1 for lvl, _, _ in rep.rows if lvl == "PASS")
    failed = sum(1 for lvl, _, _ in rep.rows if lvl == "FAIL")
    print(f"\n{passed} passed, {failed} failed")
    if rep.rows and rep.rows[0][0] == "FAIL" and rep.rows[0][1] == "server reachable":
        return 2
    return 1 if rep.failed else 0


if __name__ == "__main__":
    sys.exit(main())
