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


## AI contract adapter (PROPOSED)
Added root-level AI-team routes with X-API-Key in separate ai_* tables. See AI_CONTRACT_ADAPTER.md. Existing /api/v1 behavior and original tests unchanged.
