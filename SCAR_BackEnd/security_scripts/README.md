# SCAR security scripts

Python scripts that connect the security stack (Wazuh, Zeek) to the backend and check the result.
Standard library only: nothing to install. Run everything from the project root (the folder that contains `app/`).
Owner: Menar (Cloud & Cybersecurity), integration partner: Ahmed Ashraf.

| Script | What it does |
|---|---|
| `forwarder.py` | Reads new Wazuh / Zeek JSON events from a log file and sends them to `POST /api/v1/ingest/{source}`. Remembers its position, handles log rotation, retries. Delivery is at-least-once (see Behaviour): a crash right after the backend accepts a batch can resend it. |
| `event_check.py` | Offline: runs a real log file through the backend's normalizers and reports accepted / rejected / skipped events and the severity distribution. Use it on real samples from Amir / Samuel before the first send. |
| `api_security_check.py` | Black-box check of a running backend: missing/wrong token on every write route, token classes separated, placeholder secrets, HTTPS. |

## Setup

Put these in `.env` (never commit it) or in the environment:

```
SCAR_API_URL=http://127.0.0.1:8000
SECURITY_TOKEN=<the same value the backend uses for SECURITY_TOKEN>
```

Zeek must write JSON: add `redef LogAscii::use_json = T;` to `local.zeek`.

## Forwarder

```
# keep following the file (default) - only NEW lines are sent on the first run
python -m security_scripts.forwarder --source wazuh --file /var/ossec/logs/alerts/alerts.json
python -m security_scripts.forwarder --source zeek  --file /opt/zeek/logs/current/notice.log

# send everything that is new once, then exit (cron friendly); --from-start sends the whole file on the first run
python -m security_scripts.forwarder --source wazuh --file alerts.json --once --from-start

# parse only, send nothing
python -m security_scripts.forwarder --source wazuh --file alerts.json --dry-run
```

Behaviour:

- State file `.scar_forwarder_<source>.state.json` stores inode + offset. A restart continues where it stopped.
  The position is saved only after the backend accepted a batch, so delivery is at-least-once: a crash between
  the accepted request and the save, or deleting the state file, can send events again. The backend recognises a
  resent Wazuh alert (same `id` and same manager/cluster/sensor origin) or Zeek notice (same sensor, note, ts, uid,
  src/dst) and does not store it twice; the summary line shows `duplicates=N`. Events with no key (no alert id, or
  the backend does not know the sensor: set `SENSOR_ID` in the backend `.env`) are stored again on a resend and are
  reported as `not_deduplicated`; the forwarder prints a warning.
- Backend down, timeout, 408, 429 or 5xx: retried with exponential backoff (first delay `--backoff`, doubling, max 60 s,
  `--retries` retries); the position is not advanced, so nothing is lost. After the last retry the forwarder exits
  with code 1, appends one line to the failure log (`--failure-log`, default `scar_forwarder_failures.jsonl` next to the dead-letter file: time, file
  positions to re-send, attempts, short reason; no token, no event contents) and the same events are sent on the next
  run. Permanent 4xx (422, 400, 413, 409 ...): not retried, the batch is split and the bad event goes to the dead-letter
  file (`--dead-letter`, it does contain the event) and the position advances. 401/403/404 stop it (exit 2, also logged).
- HTTPS: certificates are verified. A self-signed certificate is refused (it looks like "no connection") unless you
  trust it with the `SSL_CERT_FILE` environment variable. There is no option to disable verification.
- 422 (backend rejects an event): the batch is split until the bad event is found; good events are stored, the bad
  ones go to `scar_rejected_events.jsonl` with the reason. Non-JSON lines go there too.
- 401 / 403 / 404: configuration error (wrong token, URL or source), exit code 2.
- Zeek `#` header lines are skipped; Zeek connection records are skipped by the backend (not alerts).
- Warns if the URL is HTTP and not localhost.

Exit codes: 0 ok, 1 backend unavailable, 2 configuration error.

## Check real samples before sending

```
python -m security_scripts.event_check --source wazuh --file alerts.json --show-rejected
python -m security_scripts.event_check --source zeek  --file notice.log
```

Look at: rejected lines (field names that differ from the normalizer's assumptions), `zeek_notices_defaulted_to_medium`
(notices missing from `ZEEK_NOTICE_SEVERITY`), `missing_source_ip`, `duplicate_alert_ids`.
Sample files are in `security_scripts/samples/`.

## Check the backend's authentication

```
python -m security_scripts.api_security_check --url https://scar.example.com
```

Sends only harmless requests (wrong token, non-existent event id, invalid body); it does not create or delete data.
Run it after every deployment and before the demo.

## Tests

```
pytest tests/test_security_scripts.py -v
```
