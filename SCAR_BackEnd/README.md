# SCAR Backend

FastAPI backend for the SCAR (Smart Cybersecurity Autonomous Response Drone) project.

## Quick start (Windows PowerShell, from this folder: the one that contains `app`)

```
python -m venv venv
.\venv\Scripts\python.exe -m pip install -r requirements.txt
.\venv\Scripts\python.exe set_tokens.py
.\venv\Scripts\python.exe -m uvicorn app.main:app --reload
```

Linux / Mac: use `venv/bin/python` instead of `.\venv\Scripts\python.exe`.

- `set_tokens.py` creates `.env` (if missing) and writes strong random `API_TOKEN`, `SECURITY_TOKEN` and `AI_TOKEN` into it. It never prints them, keeps tokens that already exist and keeps your other lines. Without tokens, protected endpoints answer 500 "Server authentication is not configured" (this is intended; `/health` still works).
- `.env.example` shows every setting. Never commit `.env`; never paste its values or a screenshot of it in chat or to the team.
- `.env` is read when the server starts. After changing it, stop the server (Ctrl+C) and start it again (`--reload` does not watch `.env`).
- Open http://127.0.0.1:8000/docs. Press Authorize and paste the token WITHOUT the word `Bearer`. `POST /api/v1/events` needs `SECURITY_TOKEN`; changing status or deleting needs `API_TOKEN`. Open the values from `.env` in your editor.
- The database `scar.db` is created next to the code on first start (not shipped).

## Tests

```
.\venv\Scripts\python.exe -m pytest -q
```

Expected: 147 passed, 1 skipped on Linux with openssl; 146 passed, 2 skipped on Windows without openssl (the TLS test needs the `openssl` command). Windows was not tested by the author of this package.

## Structure

- `app/routers` - HTTP endpoints
- `app/services` - business logic
- `app/schemas.py` - request/response validation
- `app/models.py` - database tables
- `tests` - API tests
- `security_scripts` - forwarder and checks for Wazuh / Zeek (see its README)
- `proposed/ai_contract_adapter` - draft AI adapter, NOT applied (see proposed/README.md)
- `set_tokens.py` - local token setup
- `CHANGES.md`, `KNOWN_ISSUES.md` - what changed and what is still open

## Authentication

Four kinds of credential (PROPOSED drone contract - not yet approved by the team). All use `Authorization: Bearer <TOKEN>`.

| Credential | Who | Used for |
|---|---|---|
| Drone token (one per drone) | each drone | `POST /telemetry`, `POST /health`, `POST /drone-events`. Bound to its `drone_id`: a body with another drone's id gets 403 |
| `SECURITY_TOKEN` | security team (Wazuh / Zeek) | `POST /alerts`, `POST /ingest/{source}`, `POST /events` |
| `AI_TOKEN` | AI automation | `POST /ai/analysis` |
| `API_TOKEN` | dashboard / administrator | reading telemetry, drones and drone health; changing event or alert status; deleting events |

`SECURITY_TOKEN` and `AI_TOKEN` fall back to `API_TOKEN` when not set, so old deployments keep working - but set three different secrets in production, and use HTTPS.

Register and manage drones (only a SHA-256 hash is stored; the token is shown once):

```
python -m app.drone_tokens create SCAR-DRONE-001
python -m app.drone_tokens rotate SCAR-DRONE-001
python -m app.drone_tokens revoke SCAR-DRONE-001
python -m app.drone_tokens list
```

Dashboard read endpoints for events, alerts and overview remain open. A missing or wrong token returns 401; an unconfigured server token returns 500.

## Endpoints (all under /api/v1, Swagger at /docs)

| Endpoint | What it does | Credential |
|---|---|---|
| `POST /telemetry` | receive a drone packet (200; 409 duplicate; response may contain `gap`) | drone |
| `GET /telemetry`, `GET /telemetry/{drone_id}/latest` | read telemetry | API_TOKEN |
| `POST /health` | drone system-health message (proposed: every 5 s) | drone |
| `GET /drones/{id}/health/latest` | latest health message | API_TOKEN |
| `POST /drone-events` | security event detected by the drone, sent immediately (201) | drone |
| `GET /drones`, `GET /drones/{id}`, `GET /drones/{id}/track` | drone status (online/offline) and GPS path | API_TOKEN |
| `POST /ingest/{source}` | receive RAW Zeek / Wazuh events, normalize, store with the raw event | SECURITY_TOKEN |
| `POST /alerts` | receive a canonical Wazuh/Zeek alert webhook | SECURITY_TOKEN |
| `POST /events` | store an already-unified event | SECURITY_TOKEN |
| `POST /ai/analysis` | attach the AI team's analysis to an existing event by `event_id` | AI_TOKEN |
| `GET /events`, `GET /events/{id}`, `GET /alerts`, `GET /alerts/{id}` | read events / alerts | open |
| `PATCH /events/{id}/status`, `PATCH /alerts/{id}/status`, `DELETE /events/{id}` | change status / delete | API_TOKEN |
| `GET /overview` | alert counts, drone counts, risk (empty for now) | open |

## Drone messages (proposed contract)

All three drone messages carry `drone_id`, `schema_version` (`"major.minor"`, e.g. `"1.0"`; unknown major versions get 422), `boot_id` (changes every time the drone restarts), `sequence` and `timestamp`. `schema_version` defaults to `"1.0"` and `boot_id` to `"0"` until the contract is approved.

- **Uniqueness:** `(drone_id, boot_id, sequence)` per stream. A rebooted drone keeps working by sending a new `boot_id`; the same triple again returns 409.
- **Separate sequence counters** for telemetry, health and drone events.
- **Gap detection:** if a sequence jumps by more than 1, the response contains `"gap": {"expected_sequence": 3, "received_sequence": 6, "missing": 3}` and a warning is logged. Older out-of-order packets are accepted and not reported as gaps.
- **Telemetry** has an extra optional `telemetry.system_status` string.
- **Drone events** need a unique `event_uid`; a retry with the same uid or sequence returns 409 instead of creating a duplicate.

```json
{"drone_id":"SCAR-DRONE-001","schema_version":"1.0","boot_id":"boot-a","sequence":42,
 "timestamp":"2026-11-25T10:00:05Z",
 "health":{"overall_status":"ok","cpu_percent":41.5,"memory_percent":60,"cpu_temp_c":55.2,
           "storage_percent":33,"link_rssi_dbm":-62,"uptime_s":1200,
           "components":{"gps":"ok","camera":"degraded"}}}
```

Lists return `{ "items": [...], "total": n }`, accept `limit` and `offset`, newest first.
Events/alerts also accept `severity_label`, `status`, `source`, `from`, `to` (ISO 8601).
Dates are ISO 8601 UTC. Errors use `{ "detail": "..." }`.

## Security alert webhook

Send the unified alert to `POST /api/v1/alerts` with `Authorization: Bearer <SECURITY_TOKEN>` (it falls back to `API_TOKEN` only when `SECURITY_TOKEN` is not set). `alert_id` is the source tool's ID; the response also includes the backend's `event_id` for the AI handoff. Wazuh sends the original numeric `severity` (0-15), and the backend derives the separate `severity_label` using 0-6 low, 7-9 medium, 10-12 high, and 13-15 critical. For Zeek Notices, send `severity_label` based on the notice rules; use `medium` as the temporary default. Do not invent a numeric Wazuh level for Zeek.

`agent`, `src_ip`, `dst_ip`, and `sensor_ip` are nullable. `sensor_ip` means the monitoring sensor's own address and is never inferred from either endpoint IP. Set `SENSOR_IP` during deployment as a fallback for Zeek, or send `sensor_ip` in the webhook. Ordinary Zeek `conn.log` records are not stored as security alerts; Zeek Notice records are.

```json
{
  "alert_id": "1700000000.1234",
  "timestamp": "2026-11-20T09:00:00Z",
  "source": "wazuh",
  "rule_id": "5712",
  "rule_description": "sshd: brute force attack",
  "severity": 10,
  "agent": {"id": "001", "name": "web-01", "ip": "10.0.0.10"},
  "src_ip": "203.0.113.7",
  "dst_ip": null,
  "sensor_ip": null,
  "status": "new",
  "raw": {"id": "1700000000.1234", "rule": {"id": "5712", "level": 10}}
}
```

For Zeek, send a Notice classification in `severity_label` and set numeric `severity` to `null`; the backend does not invent a Wazuh level. `severity_label` values are `low`, `medium`, `high`, and `critical`.

Allowed statuses are `new`, `investigating`, and `resolved`. `false_positive` is no longer a status: it is a separate `disposition` field (see below). Older stored `open` and `acknowledged` values are migrated to `new` and `investigating` at startup.

## Security change requests (provisional: the team has not approved them as final)

Source: `SCAR_Drone_Backend_Security_Change_Requests.docx`. Everything below is implemented but still needs team approval.

**Status and disposition.** `status` is `new | investigating | resolved`. `disposition` is a separate nullable field; the only value today is `false_positive` (the document says the final set is the team's decision). It has no default and can be set at any status, also after `resolved` (no transition rules are enforced, none were specified). `PATCH /api/v1/events|alerts/{id}/status` accepts `status`, `disposition`, or both; `"disposition": null` clears it. `GET` lists accept `?disposition=false_positive`. `GET /api/v1/overview` returns `alerts.by_disposition` next to `alerts.by_status`.
BREAKING for old clients: sending `"status": "false_positive"` (PATCH, create, webhook, `?status=` filter) now returns 422; send `{"disposition": "false_positive"}` instead (optionally with `"status": "resolved"`). `by_status` no longer has a `false_positive` key. On startup, stored rows with status `false_positive` become status `resolved` + disposition `false_positive`.

**New nullable fields** on every event/alert read: `sensor_id`, `src_port` (0-65535), `dst_port`, `protocol` (lower-case text), `zeek_uid`. They are filled from the raw event when present (Wazuh `data.srcport/dstport/protocol`, Zeek `id.orig_p/id.resp_p/proto`, `sensor_id` or the `SENSOR_ID` setting for Zeek). Field names for Wazuh/Zeek are best-effort until real samples arrive. Invalid ports become null (the raw event keeps the original). `zeek_uid` is a reference to link records of one connection, never a unique event id.

**Duplicates (idempotency).** Each stored event can carry a unique `dedup_key`: Wazuh: the original alert id plus the origin: `manager.name`, `cluster.name/node` or `sensor_id` from the alert (or from the `POST /alerts` body), or the `SENSOR_ID` setting; the agent id is added when present but is not an origin on its own (two managers can share an agent id). Zeek notice: sensor_id (or `SENSOR_ID`) or sensor_ip (or `SENSOR_IP`) + note + original ts + uid + src/dst (the uid is never used alone). **Fail-safe:** when no origin is known, NO key is built: the event is stored every time (a resend is not recognised, but two different alerts are never merged), the ingest answer counts it in `not_deduplicated`, the backend logs a warning (counts only) and the forwarder prints it. **Setup needed for duplicate protection: set `SENSOR_ID` in the backend `.env` (one name for the sensor/manager that sends to this backend), or make sure the alerts carry manager.name / sensor_id.** `SENSOR_ID` is also stored as `sensor_id` when the event has none. If several sensors/managers send to one backend, `SENSOR_ID` alone is not enough: they must identify themselves in the event. A resent event is ignored: nothing is updated (the analyst's status/disposition stay), the raw ingest answer is still 201 with `ingested` = new rows, `duplicates` and `duplicate_ids`; `POST /alerts` and `POST /events` (with an explicit `dedup_key`) return the existing row with 200. Events with no key (Wazuh without `id`, Zeek without `ts`, Zeek webhook alerts, `POST /events` without `dedup_key`) are stored every time, as before. Old rows have no key. Retention: the key lives as long as its row.

`conn.log` is still not stored. Delivery: see `security_scripts/README.md` (retry with backoff, 408/429/5xx temporary, permanent 4xx to the dead-letter file, final failures written to `scar_forwarder_failures.jsonl` with file positions and a short sanitized reason, never the token or event contents). HTTPS/TLS is a deployment setting: the forwarder verifies certificates (a self-signed one is refused unless trusted through `SSL_CERT_FILE`), there is no switch to turn verification off, and plain HTTP only gives a warning.

## AI automation handoff

Send the AI result to `POST /api/v1/ai/analysis` after the matching event has been created. `event_id` is the backend `event_id` returned by `POST /api/v1/alerts`, `POST /api/v1/events`, or `POST /api/v1/ingest/{source}`. The endpoint replaces the latest AI analysis for that event and leaves the source severity unchanged.

```json
{
  "event_id": 12,
  "agent_name": "scar-ai-agent",
  "model_version": "1.0.0",
  "severity": "high",
  "risk_score": 82.5,
  "category": "credential_attack",
  "confidence": 0.94,
  "explanation": "Repeated failed logins were detected.",
  "recommended_action": "Block the source IP and review the account.",
  "created_at": "2026-11-23T10:30:00Z"
}
```

`severity` in the AI payload is an AI severity label and is stored separately as `ai_severity_label`; it does not replace the source's numeric `severity` or derived `severity_label`. `risk_score` must be between 0 and 100. `created_at` is optional and defaults to the current UTC time. AI analysis fields remain `null` until analysis arrives. `confidence` is stored as supplied because its scale was not specified in the handoff.

## Event IDs and sources

- `event_id` is generated by the database. The original Zeek / Wazuh `alert_id` is kept separately as `source_alert_id` internally.
- The raw event is kept unchanged in the `raw` webhook field (stored as JSON text internally).
- `source` is free text in the database. To add a new source, add one function in `app/normalizers.py` (no database change).

## Security scripts

`security_scripts/` forwards Wazuh / Zeek logs to the backend, checks real event samples against the normalizers, and audits the API authentication. See `security_scripts/README.md`.

## Sample data for the dashboard

```
python -m app.seed            # add FAKE sample events + a sample drone
python -m app.seed --clear    # remove only the sample data
```

## Changing the database structure

`create_all` does not change existing tables. Startup runs (1) an additive migration for the alert, AI and drone-event columns that maps legacy `open` / `acknowledged` statuses, and (2) a rebuild of the `telemetry` table (old rows copied, `boot_id` = `"0"`, `schema_version` = `"1.0"`) because the unique key changed to `(drone_id, boot_id, sequence)`. Back up production data before deployment; use Alembic for future schema changes.

## Not implemented yet (waiting for other teams)

- Risk score history and multiple AI analysis records per event (the current integration stores the latest result on the event).
- Network nodes/links, digital twin state (no owner / format yet).
- WebSocket real-time (the dashboard will poll for now).
- Login endpoint (a static Bearer token is used).
- Duplicate protection for Zeek/Wazuh events is fail-safe and provisional: see "Security change requests" (events without a known origin are stored every time).

## Proposed, not approved (confirm with the team)

Online/offline rule (telemetry within 15 s), the whole drone contract (schema_version, boot_id, tokens, health, drone events), CORS origins, confidence scale, and duplicate delivery behavior still need team decisions.
