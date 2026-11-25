"""Shared helpers for the SCAR security scripts (standard library only, no pip install needed)."""
import json
import os
import urllib.error
import urllib.request
from typing import Any, Optional

DEFAULT_URL = "http://127.0.0.1:8000"
USER_AGENT = "scar-security-scripts/1.0"


def load_env_file(path: str = ".env") -> None:
    """Load KEY=VALUE lines into os.environ without overriding variables that are already set."""
    if not os.path.isfile(path):
        return
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            os.environ.setdefault(key.strip(), value.strip().strip("'\""))


def http_json(method: str, url: str, token: Optional[str] = None, body: Any = None, timeout: float = 10.0):
    """Send one request. Returns (status_code, parsed_json_or_text). Never raises on HTTP errors.

    A network failure (server down, DNS, timeout) returns status 0 with the error text.
    """
    data = None
    headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, _parse(resp.read())
    except urllib.error.HTTPError as exc:
        return exc.code, _parse(exc.read())
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        return 0, str(getattr(exc, "reason", exc))


def _parse(raw: bytes):
    text = raw.decode("utf-8", errors="replace")
    try:
        return json.loads(text) if text else None
    except ValueError:
        return text
