# Findings from the security-integration review (for Amir, Samuel, Ahmed Ashraf)

Found by reading the code and running the sample files through the real normalizers. Not yet confirmed against real Wazuh / Zeek output.

1. **Normalizers are unverified.** `app/normalizers.py` says so itself: field names (`rule.level`, `data.srcip`, `note`, `id.orig_h`)
   and the severity mappings must be checked with real samples. Action: run `event_check.py` on a real `alerts.json` and `notice.log`.
2. **Zeek severity table has 4 notices.** Every other notice becomes `medium` (the sample `Weird::Activity` did). Action: Amir / Samuel
   decide severities for the notices that actually occur; `event_check.py` lists them under `zeek_notices_defaulted_to_medium`.
3. **Zeek must log JSON.** The default Zeek log is tab-separated and is rejected. Action: `redef LogAscii::use_json = T;`.
4. **No duplicate protection for events** (backend report, section VI). Re-sending the same alert creates a second row. The forwarder
   reduces this with its offset file, but delivery is at-least-once: a crash between an accepted batch and the saved position, or a
   deleted state file, can re-send events. If the state file is deleted, run without `--from-start` so old events are not re-sent.
5. **Wazuh events without `data.srcip` get no source IP** (e.g. privilege escalation, syscheck). The field is nullable, so this is
   accepted; the dashboard must handle a missing `src_ip`.
6. **Dashboard read routes are open** (`GET /events`, `/alerts`, `/overview`). They return IPs and raw log text. Decide if this is
   acceptable for the demo; `api_security_check.py` does not flag it because the README documents it as intended.
7. **README was out of date**: the alert webhook example said `API_TOKEN`; the route requires `SECURITY_TOKEN`. Fixed.
8. **Test status of the merged project:** the backend tests plus these scripts' 19 tests ran together on Linux (Python 3.10.12, pinned
   `requirements.txt`): 107 passed, 1 skipped (the sample test, skipped while `tests/samples/` has no files). Run `pytest -v` on Windows and
   `api_security_check.py` against your own running server before relying on it.
