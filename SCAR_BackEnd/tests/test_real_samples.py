"""Regression harness for sanitized Wazuh / Zeek sample exports (tests/samples/<source>/*.json).

THIS IS A TEST SCAFFOLD, NOT INTEGRATION PROOF. It does not show that Wazuh or Zeek are connected to the backend.
It only checks, once authorized sanitized exports are placed in tests/samples/, that the current normalizers keep
every record they are supposed to keep. With no sample files the sample test is skipped.

Rules used (they mirror app/normalizers.py, nothing new is invented):
  wazuh : every record must be stored.
  zeek  : every record with a "note" (notice.log) must be stored; a record without "note" that has both
          id.orig_h and id.resp_h (conn.log) is intentionally skipped; anything else is rejected with 422 by the API.
"""
import json
from pathlib import Path

import pytest

# keep this import FIRST: it sets the test tokens before the app is imported (client is a pytest fixture)
from tests.test_api import SEC, client  # noqa: F401,E402
from app.normalizers import _zeek_id  # noqa: E402

SAMPLES = Path(__file__).parent / "samples"
FILES = sorted(p for source in ("wazuh", "zeek") for p in (SAMPLES / source).glob("*.json"))


def split_expected(source, items):
    """Return (records that MUST be stored, records that MAY be skipped) using the normalizer's own rules."""
    if source == "wazuh":
        return list(items), []
    must, may_skip = [], []
    for raw in items:
        if raw.get("note"):
            must.append(raw)
        elif _zeek_id(raw, "orig_h") and _zeek_id(raw, "resp_h"):
            may_skip.append(raw)
        else:
            must.append(raw)  # unrecognised: the API will answer 422, which fails the check below
    return must, may_skip


def canonical(raw):
    return json.dumps(raw, sort_keys=True)


def check_ingest(client, source, payload):
    """Send payload to the ingest route and assert that exactly the expected records were stored."""
    items = payload if isinstance(payload, list) else [payload]
    must, _may_skip = split_expected(source, items)

    r = client.post(f"/api/v1/ingest/{source}", json=payload, headers=SEC)
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["ingested"] == len(body["ids"])
    assert body["ingested"] == len(must), (
        f"{len(must)} {source} record(s) should be stored but {body['ingested']} were: alerts were dropped"
    )

    stored = []
    for event_id in body["ids"]:
        event = client.get(f"/api/v1/events/{event_id}").json()
        assert event["source"] == source
        assert event["severity_label"] in {"low", "medium", "high", "critical"}
        stored.append(canonical(event["raw"]))
    assert sorted(stored) == sorted(canonical(m) for m in must), "stored raw events differ from the records sent"
    assert client.get(f"/api/v1/events?source={source}").json()["total"] == len(must)


@pytest.mark.parametrize("path", FILES, ids=[f"{p.parent.name}/{p.name}" for p in FILES])
def test_sanitized_sample_file(client, path):
    check_ingest(client, path.parent.name, json.loads(path.read_text(encoding="utf-8")))


# ---------------------------------------------------------------------------------------------
# SYNTHETIC negative controls. Invented payloads, NOT real Wazuh/Zeek output and NOT integration
# proof. They only prove that check_ingest() fails when alerts are dropped, so a green sample
# test means something.
# ---------------------------------------------------------------------------------------------
SYN_WAZUH = {"id": "syn-1", "timestamp": "2026-11-20T09:00:00.000+0000",
             "rule": {"id": "5712", "level": 10, "description": "synthetic"},
             "agent": {"id": "001", "name": "syn", "ip": "10.0.0.10"}, "data": {"srcip": "203.0.113.7"}}
SYN_ZEEK_NOTICE = {"ts": 1700000000.0, "uid": "Csyn1", "note": "Scan::Port_Scan", "msg": "synthetic",
                   "id.orig_h": "203.0.113.7", "id.resp_h": "10.0.0.5"}
SYN_ZEEK_CONN = {"ts": 1700000001.0, "uid": "Csyn2", "id.orig_h": "10.0.0.5", "id.resp_h": "10.0.0.6"}


def test_control_unmodified_backend_passes_synthetic_payloads(client):
    check_ingest(client, "wazuh", [SYN_WAZUH])
    check_ingest(client, "zeek", [SYN_ZEEK_NOTICE, SYN_ZEEK_CONN])  # the conn record is the allowed skip


def test_control_dropping_all_wazuh_alerts_is_detected(client, monkeypatch):
    monkeypatch.setattr("app.routers.ingest.normalize", lambda source, raw: None)
    with pytest.raises(AssertionError, match="dropped"):
        check_ingest(client, "wazuh", [SYN_WAZUH])


def test_control_dropping_zeek_notices_is_detected(client, monkeypatch):
    monkeypatch.setattr("app.routers.ingest.normalize", lambda source, raw: None)  # also skips the notice
    with pytest.raises(AssertionError, match="dropped"):
        check_ingest(client, "zeek", [SYN_ZEEK_NOTICE, SYN_ZEEK_CONN])


def test_control_unrecognised_zeek_record_fails_the_check(client):
    with pytest.raises(AssertionError):
        check_ingest(client, "zeek", [{"ts": 1700000002.0, "uid": "Csyn3"}])  # API answers 422
