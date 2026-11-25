# Known issues and open decisions (draft for Day 7, update before the demo)

Status words: IMPLEMENTED = in this code and covered by tests. PROPOSED = in code, not approved by the team.
NOT TESTED = no evidence yet. ABSENT = not in this code.

## Not approved yet (decisions needed)
- Drone-to-backend contract (schema_version, boot_id, sequence rules, health every 5 s, 15 s online window): PROPOSED.
- Scale of AI `confidence` (0-1 or 0-100), whether to keep AI analysis history.
- Security change requests (provisional until the team approves them): the set of `disposition` values (only `false_positive` exists), whether disposition may change after `resolved`, the duplicate rule (ignore vs update "last seen"), key scope and retention, the allowed `protocol` values, whether `sensor_id` for Wazuh is the agent or the manager, and a separate Network Events table for Zeek `conn.log` (still not stored).
- How `overview.risk` is calculated (it returns an empty object today).
- Whether dashboard reads of events, alerts and overview stay open (no token).
- Whether n8n / AI uses only `POST /api/v1/ai/analysis` (this code) or another path.

## Security scripts (security_scripts/, added from Menar's work)
- The forwarder is at-least-once: a crash between an accepted batch and the saved position, or a deleted state file, can send events again. The backend now skips a resent event that has an idempotency key (see "Security change requests" in README.md). Old rows stored before this update have no key, and events without a usable key are stored again. Duplicate protection is fail-safe: without a known origin (manager.name / cluster / sensor_id in the alert, or the SENSOR_ID setting; for Zeek also sensor_ip) no key is built and a resend is stored again; `not_deduplicated` in the ingest answer and a log warning show it. Needs Confirmation with real Wazuh samples: does the alert always carry manager.name? Plain HTTP to the backend is only a warning (deployment decision).
- Their sample files (`security_scripts/samples/`) are invented test data with deliberate bad lines. They are not real Wazuh/Zeek exports and must not be copied into `tests/samples/`.
- Zeek must log JSON (`redef LogAscii::use_json = T;`); the field names and Zeek severity table still need real exports (Amir, Samuel).

## Not tested
- Real Wazuh and Zeek samples (see tests/samples/README.md), forwarder against a live Wazuh/Zeek stack, HTTPS, running it as a service, a real drone, the AI/n8n flow, PostgreSQL, Windows end-to-end.

## Absent from this code
- Digital twin, alert delivery, dashboard contract document, retention / down-sampling for 2 packets per second, Alembic migrations.
