# Sanitized Wazuh / Zeek sample exports

This folder is for sample exports that the Wazuh and Zeek owners (Amir, Samuel) have AUTHORIZED for sharing.
Never commit a raw, unsanitized export, and never commit secrets, real internal IPs, hostnames, usernames or tokens.

Sanitize first, keeping the structure: keep every field name and nesting exactly as the tool produces it, and replace
only the sensitive values (for example 203.0.113.x and 10.0.0.x placeholders). Changing field names or dropping fields
makes the test meaningless. Ask the owner before editing a file, and keep the original out of the repository.

- `tests/samples/wazuh/*.json` : one Wazuh alert (JSON object) or a JSON list per file
- `tests/samples/zeek/*.json`  : one Zeek record or a JSON list per file (notice.log and conn.log)

`python -m pytest tests/test_real_samples.py -v` sends each file to `POST /api/v1/ingest/{source}`.
Expected: every Wazuh record and every Zeek notice is stored with its raw event; Zeek conn records are skipped on
purpose. A file that loses an alert, or that the API rejects, fails. With no files the sample test is skipped.

This is a regression scaffold. It does not prove that Wazuh or Zeek are integrated with the backend.
