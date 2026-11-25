# scar3: standalone package

One complete project = scar2 + Menar security scripts + the Security change requests below + `set_tokens.py` + `.env.example`. No local DB, venv, .env or caches inside. The draft AI adapter is only in `proposed/` and is not applied.

# Security change requests update (provisional)

Implements `SCAR_Drone_Backend_Security_Change_Requests.docx` on top of scar2 + Menar's security scripts. Not approved as final by the team.
- Disposition separated from status (see README "Security change requests"); `false_positive` removed from the status values.
- New nullable fields sensor_id, src_port, dst_port, protocol, zeek_uid.
- Idempotency: unique `dedup_key`; resent Wazuh/Zeek events are not stored twice WHEN the origin is known (manager/cluster/sensor_id in the alert or SENSOR_ID in .env). Unknown origin = no key, event stored each time and flagged (`not_deduplicated`).
- Forwarder: 408/429 retried; permanent 4xx (400/413...) split and dead-lettered; final failures logged to scar_forwarder_failures.jsonl (sanitized); summary shows duplicates.
- Database: new columns + unique index are added automatically at startup (nothing is deleted). Rows with status `false_positive` become `resolved` + disposition `false_positive`.
- Tests: tests/test_disposition.py, tests/test_security_changes.py added; ONE original test line changed (tests/test_api.py, overview by_status without false_positive).

# Changes since SCAR_Backend_Final (drone contract implementation)

Implements the proposed drone-to-backend contract and the fixes found in the review. All of it is PROPOSED
until the team approves the contract.

## Security
- Per-drone tokens (table `drones`, SHA-256 hash only), bound to `drone_id` (403 on mismatch), revocable/rotatable:
  `python -m app.drone_tokens create|rotate|revoke|list`.
- Separate `SECURITY_TOKEN` (Wazuh/Zeek webhook, ingest, POST /events) and `AI_TOKEN` (POST /ai/analysis);
  both fall back to `API_TOKEN` when unset. `API_TOKEN` is now the dashboard/admin token.
- `POST /events` was open: now needs SECURITY_TOKEN. `PATCH /events|alerts/{id}/status` and `DELETE /events/{id}`
  were open: now need API_TOKEN (the dashboard must send it for status changes).

## Contract
- `schema_version` ("1.0", unknown major -> 422) and `boot_id` on telemetry, health and drone events (both optional, defaults "1.0" / "0").
- Unique key `(drone_id, boot_id, sequence)`: a rebooted drone no longer gets 409 forever.
- Gap detection: response `gap` {expected_sequence, received_sequence, missing}; per stream, per boot.
- New: `POST /api/v1/health`, `GET /api/v1/drones/{id}/health/latest`, `POST /api/v1/drone-events` (unique `event_uid`, duplicates -> 409).
- Telemetry gets optional `system_status`.
- Online window default 120 s -> 15 s.
- Composite index `(drone_id, timestamp)` on telemetry and health.

## Database
- New tables `drones`, `system_health`; new columns on `telemetry` (boot_id, schema_version, system_status) and
  `security_events` (drone_id, boot_id, event_sequence, schema_version).
- Startup migrations: security_events additive columns (extended) and a telemetry table rebuild (rows kept).

## Tests
- tests/test_api.py rewritten for the current payloads: 84 tests, all passing (was 31 passing / 13 failing).

## Security scripts (Menar's task)
- `security_scripts/`: `forwarder.py` (Wazuh/Zeek log -> `POST /ingest/{source}`), `event_check.py` (offline normalizer check), `api_security_check.py` (auth audit), samples and `README.md`.
- `tests/test_security_scripts.py`: 19 tests against a fake backend.
- README: webhook example now says `SECURITY_TOKEN` (was `API_TOKEN`).
