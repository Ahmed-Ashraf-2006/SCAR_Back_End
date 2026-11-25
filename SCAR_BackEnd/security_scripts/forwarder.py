"""Forward Wazuh / Zeek JSON events from a log file to the SCAR backend.

    python -m security_scripts.forwarder --source wazuh --file /var/ossec/logs/alerts/alerts.json
    python -m security_scripts.forwarder --source zeek  --file /opt/zeek/logs/current/notice.log --once

What it does
  * reads only NEW complete lines (JSON, one event per line) and remembers its position in a state file,
    so a normal restart does not send old events again. Delivery is at-least-once, not exactly-once: the
    position is saved only after the backend accepted a batch, so a crash between the accepted POST and
    the save, or deleting the state file, can send events again. The backend now recognises a resent
    event (same Wazuh alert id / same Zeek notice key) and does not store it twice: the answer reports it
    in "duplicates". Events the backend could not build a key for (for example a Wazuh event without "id")
    are still stored again on a resend;
  * detects log rotation / truncation and starts the new file from the beginning;
  * sends batches to POST /api/v1/ingest/{source} (the backend normalizes and stores the raw event);
  * if the backend rejects a batch with 422, retries the events one by one, so one bad event does not
    block the others; the rejected ones are written to a dead-letter file with the reason;
  * network errors, 5xx, 408 (timeout) and 429 (too many requests) are temporary: retried with exponential
    backoff, and if they never succeed the position is NOT advanced (nothing is lost, the events are sent
    again on the next run) and one line is appended to the failure log (--failure-log: time, file positions,
    short reason; no event contents, no token);
  * permanent 4xx answers (422, 400, 413, 409 ...) are not retried: the batch is split until the bad event is
    found and that event goes to the dead-letter file with the reason (this one DOES advance the position);
  * 401 / 403 / 404 are configuration errors: it stops with exit code 2.

Configuration (environment variables or .env, never put a token on the command line or in git):
  SCAR_API_URL     default http://127.0.0.1:8000
  SECURITY_TOKEN   the Wazuh/Zeek credential of the backend (falls back to API_TOKEN, like the backend)

Zeek must write JSON (in local.zeek: redef LogAscii::use_json = T;). Tab-separated Zeek logs are rejected.
Exit codes: 0 ok, 1 backend unreachable / server error, 2 configuration error.
"""
import argparse
import json
import logging
import os
import sys
import time
from datetime import datetime, timezone
from dataclasses import dataclass, field
from typing import Optional

from security_scripts.common import DEFAULT_URL, http_json, load_env_file

log = logging.getLogger("scar.forwarder")

SOURCES = ("wazuh", "zeek")
MAX_BATCH = 500  # the backend refuses more than 500 events per request


class ConfigError(Exception):
    """401 / 403 / 404 from the backend: wrong token, wrong URL or unsupported source."""


class BackendUnavailable(Exception):
    """Network failure or 5xx after all retries."""


@dataclass
class Stats:
    sent: int = 0
    stored: int = 0
    rejected: int = 0
    skipped_comments: int = 0
    duplicates: int = 0
    not_deduplicated: int = 0
    batches: int = 0
    errors: list = field(default_factory=list)


# ------------------------------------------------------------------ state
def _state_path(args) -> str:
    return args.state or f".scar_forwarder_{args.source}.state.json"


def load_state(path: str) -> dict:
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        return {"inode": data.get("inode"), "offset": int(data.get("offset", 0))}
    except (OSError, ValueError):
        return {"inode": None, "offset": None}


def save_state(path: str, inode: int, offset: int) -> None:
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump({"inode": inode, "offset": offset}, fh)
    os.replace(tmp, path)  # atomic: a crash never leaves a half-written state file


def start_offset(path: str, state: dict, from_start: bool) -> int:
    """Where to continue reading. Handles first run, rotation (new inode) and truncation."""
    st = os.stat(path)
    if state["offset"] is None:  # first run
        return 0 if from_start else st.st_size
    if state["inode"] != st.st_ino or st.st_size < state["offset"]:
        log.info("Log file rotated or truncated: reading it from the beginning")
        return 0
    return state["offset"]


# ------------------------------------------------------------------ reading
def read_lines(path: str, offset: int, max_lines: int):
    """Return ([text lines], new_offset). A last line without a newline is still being written: left for next time."""
    lines = []
    with open(path, "rb") as fh:
        fh.seek(offset)
        while len(lines) < max_lines:
            raw = fh.readline()
            if not raw or not raw.endswith(b"\n"):
                break
            offset += len(raw)
            lines.append(raw.decode("utf-8", errors="replace").strip())
    return lines, offset


def parse_line(source: str, line: str):
    """Return (event_dict, None) or (None, reason). Blank lines and Zeek '#' header lines give (None, '')."""
    if not line or (source == "zeek" and line.startswith("#")):
        return None, ""
    if not line.startswith("{"):
        hint = " (Zeek must log JSON: redef LogAscii::use_json = T;)" if source == "zeek" else ""
        return None, f"not a JSON object{hint}"
    try:
        event = json.loads(line)
    except ValueError as exc:
        return None, f"invalid JSON: {exc}"
    if not isinstance(event, dict):
        return None, "not a JSON object"
    return event, None


# ------------------------------------------------------------------ sending
def post_with_retry(url: str, token: str, payload, retries: int, backoff: float):
    delay = backoff
    for attempt in range(retries + 1):
        status, body = http_json("POST", url, token=token, body=payload, timeout=20)
        if status in (401, 403, 404):
            raise ConfigError(f"HTTP {status} from {url}: {_detail(body)}")
        if status in (0, 408, 429) or status >= 500:  # temporary: network error, timeout, throttling, server error
            if attempt == retries:
                raise BackendUnavailable(f"{url}: {'no connection' if status == 0 else status} ({_detail(body)})")
            log.warning("Backend not available (%s), retrying in %.1fs", status or "no connection", delay)
            time.sleep(delay)
            delay = min(delay * 2, 60)
            continue
        return status, body
    raise BackendUnavailable(url)  # pragma: no cover


def _permanent_client_error(status: int) -> bool:
    """4xx that retrying cannot fix (400, 413, 409 ...). 401/403/404 are configuration errors, 408/429 are temporary."""
    return 400 <= status < 500 and status not in (401, 403, 404, 408, 429)


def _detail(body) -> str:
    return str(body.get("detail", body)) if isinstance(body, dict) else str(body)


def send_events(url, token, events, stats: Stats, dead_letter, retries, backoff, stored_ids: Optional[list] = None):
    """Send one batch. On 422 isolate the bad events by sending them one at a time."""
    status, body = post_with_retry(url, token, events, retries, backoff)
    stats.batches += 1
    if status == 201:
        stats.sent += len(events)
        stats.stored += body.get("ingested", 0)
        stats.duplicates += body.get("duplicates", 0)
        stats.not_deduplicated += body.get("not_deduplicated", 0)
        if stored_ids is not None:
            stored_ids.extend(body.get("ids", []))
        return
    if status == 422 or _permanent_client_error(status):
        if len(events) == 1:
            stats.rejected += 1
            reason = _detail(body) if status == 422 else f"HTTP {status}: {_detail(body)}"
            log.warning("Backend rejected an event: %s", reason)
            dead_letter({"reason": reason, "event": events[0]})
            return
        mid = len(events) // 2  # bisect: finds the bad event(s) with few requests
        send_events(url, token, events[:mid], stats, dead_letter, retries, backoff, stored_ids)
        send_events(url, token, events[mid:], stats, dead_letter, retries, backoff, stored_ids)
        return
    raise BackendUnavailable(f"Unexpected HTTP {status} from {url}: {_detail(body)}")


def make_dead_letter(path: str):
    def write(record: dict) -> None:
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, ensure_ascii=False) + "\n")
    return write


def _clean(text, token: str = "", limit: int = 300) -> str:
    """Make an error text safe for a log: no token, one line, short."""
    text = " ".join(str(text).split())
    if token:
        text = text.replace(token, "***")
    return text[:limit]


def write_failure(path: str, record: dict) -> None:
    """Append one line to the failure log. Never raises: a full disk must not hide the original error."""
    try:
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, ensure_ascii=False) + "\n")
    except OSError as exc:  # pragma: no cover
        log.warning("Could not write the failure log %s: %s", path, exc)


# ------------------------------------------------------------------ main loop
def forward_once(args, token: str) -> Stats:
    stats = Stats()
    state_file = _state_path(args)
    state = load_state(state_file)
    offset = start_offset(args.file, state, args.from_start)
    inode = os.stat(args.file).st_ino
    url = f"{args.url.rstrip('/')}/api/v1/ingest/{args.source}"
    dead_letter = make_dead_letter(args.dead_letter)

    while True:
        lines, new_offset = read_lines(args.file, offset, args.batch_size)
        if not lines:
            break
        events = []
        for line in lines:
            event, problem = parse_line(args.source, line)
            if event is not None:
                events.append(event)
            elif problem:
                stats.rejected += 1
                dead_letter({"reason": problem, "line": line[:2000]})
            else:
                stats.skipped_comments += 1
        if events and not args.dry_run:
            try:
                send_events(url, token, events, stats, dead_letter, args.retries, args.backoff)
            except (BackendUnavailable, ConfigError) as exc:
                # Final failure: keep a reviewable record. It holds positions (to re-send exactly this range) and a
                # short sanitized reason, never the token and never the event contents.
                failure_log = args.failure_log or os.path.join(
                    os.path.dirname(os.path.abspath(args.dead_letter)), "scar_forwarder_failures.jsonl")
                write_failure(failure_log, {
                    "time": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                    "kind": "config_error" if isinstance(exc, ConfigError) else "backend_unavailable",
                    "source": args.source,
                    "file": args.file,
                    "from_offset": offset,
                    "to_offset": new_offset,
                    "events_in_batch": len(events),
                    "attempts_per_request": args.retries + 1,
                    "reason": _clean(exc, token),
                    "position_advanced": False,
                })
                raise
        elif events:
            stats.sent += len(events)
        if not args.dry_run:
            save_state(state_file, inode, new_offset)  # only after the backend accepted or the dead letter has them
        offset = new_offset
    return stats


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Forward Wazuh / Zeek JSON events to the SCAR backend.")
    p.add_argument("--source", required=True, choices=SOURCES)
    p.add_argument("--file", required=True, help="Wazuh alerts.json or Zeek notice.log (JSON lines)")
    p.add_argument("--url", default=None, help=f"backend base URL (default $SCAR_API_URL or {DEFAULT_URL})")
    p.add_argument("--state", default=None, help="state file (default .scar_forwarder_<source>.state.json)")
    p.add_argument("--dead-letter", default="scar_rejected_events.jsonl", help="where rejected events are written")
    p.add_argument("--failure-log", default=None,
                   help="one line per final delivery failure: file positions + short reason, no event contents, no token "
                        "(default: scar_forwarder_failures.jsonl next to the dead-letter file)")
    p.add_argument("--from-start", action="store_true", help="first run: send the whole file instead of only new lines")
    p.add_argument("--once", action="store_true", help="send what is new and exit (default: keep following the file)")
    p.add_argument("--interval", type=float, default=2.0, help="seconds between checks when following")
    p.add_argument("--batch-size", type=int, default=200, help=f"events per request (max {MAX_BATCH})")
    p.add_argument("--retries", type=int, default=5, help="retries per request on network error / 5xx")
    p.add_argument("--backoff", type=float, default=1.0, help="first retry delay in seconds (doubles each time)")
    p.add_argument("--dry-run", action="store_true", help="parse the file but send nothing and save no state")
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"), format="%(asctime)s %(levelname)s %(message)s")
    load_env_file()
    args.url = args.url or os.getenv("SCAR_API_URL", DEFAULT_URL)
    args.batch_size = max(1, min(args.batch_size, MAX_BATCH))
    token = os.getenv("SECURITY_TOKEN") or os.getenv("API_TOKEN") or ""
    if not token and not args.dry_run:
        log.error("SECURITY_TOKEN is not set (environment variable or .env)")
        return 2
    if not os.path.isfile(args.file):
        log.error("File not found: %s", args.file)
        return 2
    if args.url.startswith("http://") and not args.url.startswith(("http://127.", "http://localhost")):
        log.warning("The backend URL is not HTTPS: the token can be read on the network")

    try:
        while True:
            stats = forward_once(args, token)
            if stats.sent or stats.rejected:
                log.info("batches=%d sent=%d stored=%d duplicates=%d rejected=%d (dead letter: %s)",
                         stats.batches, stats.sent, stats.stored, stats.duplicates, stats.rejected, args.dead_letter)
                if stats.not_deduplicated:
                    log.warning("%d stored events have no duplicate protection (backend does not know the sensor): "
                                "set SENSOR_ID on the backend", stats.not_deduplicated)
            if args.once:
                return 0
            time.sleep(args.interval)
    except ConfigError as exc:
        log.error("Configuration error: %s", exc)
        return 2
    except BackendUnavailable as exc:
        log.error("Backend not available, position not advanced, nothing lost: %s", exc)
        return 1
    except KeyboardInterrupt:
        return 0


if __name__ == "__main__":
    sys.exit(main())
