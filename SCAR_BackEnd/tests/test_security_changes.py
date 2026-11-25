"""Security change requests: normalized fields, idempotency, delivery. Original tests are untouched."""
# keep this import FIRST: it sets the test tokens before the app is imported (client is a pytest fixture)
from tests.test_api import (EV, SEC, WAZUH_RAW, ZEEK_CONN_RAW, ZEEK_NOTICE_RAW, client, unified_event, webhook)  # noqa: F401,E402
from sqlalchemy import create_engine, inspect, text  # noqa: E402
from sqlalchemy.exc import IntegrityError  # noqa: E402
from sqlalchemy.pool import StaticPool  # noqa: E402

from app import models  # noqa: E402
from app.migrations import upgrade_security_event_columns  # noqa: E402
from app.normalizers import normalize  # noqa: E402
from tests.test_security_scripts import backend  # noqa: F401,E402  (fake backend fixture)

import pytest  # noqa: E402
from app import normalizers  # noqa: E402

ING = "/api/v1/ingest"
DASH = {"Authorization": "Bearer test-token"}


@pytest.fixture(autouse=True)
def _origin(request, monkeypatch):
    """Duplicate protection needs a known origin. Tests whose name contains 'unscoped' run WITHOUT any SENSOR_ID."""
    monkeypatch.setattr(normalizers, "SENSOR_ID", None if "unscoped" in request.node.name else "test-sensor")
    if "unscoped" in request.node.name:
        monkeypatch.setattr(normalizers, "SENSOR_IP", None)  # a real .env must not change these tests


def _count(client):
    return client.get(EV).json()["total"]


# ------------------------------------------------------------ normalized fields
def test_new_fields_are_null_when_the_source_does_not_send_them_unscoped(client):
    r = client.post(f"{ING}/wazuh", json=WAZUH_RAW, headers=SEC)
    body = client.get(f"{EV}/{r.json()['ids'][0]}").json()
    for name in ("sensor_id", "src_port", "dst_port", "protocol", "zeek_uid"):
        assert name in body and body[name] is None


def test_wazuh_ports_and_protocol_when_present_and_invalid_values_become_null(client):
    raw = {**WAZUH_RAW, "id": "p-1", "data": {"srcip": "203.0.113.7", "srcport": "51515", "dstport": 22, "protocol": "TCP"}}
    r = client.post(f"{ING}/wazuh", json=raw, headers=SEC)
    body = client.get(f"{EV}/{r.json()['ids'][0]}").json()
    assert (body["src_port"], body["dst_port"], body["protocol"]) == (51515, 22, "tcp")
    bad = {**WAZUH_RAW, "id": "p-2", "data": {"srcport": "70000", "dstport": "abc", "protocol": "  "}}
    r = client.post(f"{ING}/wazuh", json=bad, headers=SEC)
    body = client.get(f"{EV}/{r.json()['ids'][0]}").json()
    assert (body["src_port"], body["dst_port"], body["protocol"]) == (None, None, None)
    assert body["raw"] == bad  # the original is kept as sent


def test_zeek_notice_keeps_uid_as_a_reference_and_sensor_id(client):
    raw = {**ZEEK_NOTICE_RAW, "id.orig_p": 4444, "id.resp_p": 80, "proto": "tcp", "sensor_id": "zeek-lab-1"}
    r = client.post(f"{ING}/zeek", json=raw, headers=SEC)
    body = client.get(f"{EV}/{r.json()['ids'][0]}").json()
    assert body["zeek_uid"] == "CAbc123" and body["sensor_id"] == "zeek-lab-1"
    assert (body["src_port"], body["dst_port"], body["protocol"]) == (4444, 80, "tcp")


def test_unified_event_validates_ports_and_normalizes_protocol(client):
    ok = client.post(EV, json=unified_event(src_port=1, dst_port=65535, protocol=" UDP ", sensor_id="s1"), headers=SEC)
    assert ok.status_code == 201
    body = ok.json()
    assert (body["src_port"], body["dst_port"], body["protocol"], body["sensor_id"]) == (1, 65535, "udp", "s1")
    assert client.post(EV, json=unified_event(dst_port=65536), headers=SEC).status_code == 422
    assert client.post(EV, json=unified_event(src_port=-1), headers=SEC).status_code == 422


def test_alerts_webhook_and_list_return_the_new_fields(client):
    r = client.post("/api/v1/alerts", json=webhook(alert_id="n-1", sensor_id="w-sensor", src_port=1234, dst_port=22, protocol="TCP"), headers=SEC)
    assert r.status_code == 201
    out = r.json()
    assert (out["sensor_id"], out["src_port"], out["dst_port"], out["protocol"]) == ("w-sensor", 1234, 22, "tcp")
    listed = client.get("/api/v1/alerts").json()["items"][0]
    assert (listed["sensor_id"], listed["src_port"], listed["dst_port"], listed["protocol"]) == ("w-sensor", 1234, 22, "tcp")


# ------------------------------------------------------------ idempotency
def test_resending_a_wazuh_event_three_times_stores_one_alert(client):
    first = client.post(f"{ING}/wazuh", json=WAZUH_RAW, headers=SEC)
    assert first.json()["ingested"] == 1 and first.json()["duplicates"] == 0
    eid = first.json()["ids"][0]
    for _ in range(2):
        again = client.post(f"{ING}/wazuh", json=WAZUH_RAW, headers=SEC)
        assert again.status_code == 201
        assert again.json() == {"source": "wazuh", "ingested": 0, "ids": [], "duplicates": 1, "duplicate_ids": [eid], "not_deduplicated": 0}
    assert _count(client) == 1


def test_duplicate_does_not_overwrite_what_the_analyst_already_did(client):
    eid = client.post(f"{ING}/wazuh", json=WAZUH_RAW, headers=SEC).json()["ids"][0]
    client.patch(f"{EV}/{eid}/status", json={"status": "resolved", "disposition": "false_positive"}, headers=DASH)
    client.post(f"{ING}/wazuh", json=WAZUH_RAW, headers=SEC)
    body = client.get(f"{EV}/{eid}").json()
    assert body["status"] == "resolved" and body["disposition"] == "false_positive"


def test_batch_with_new_old_and_repeated_events(client):
    a = {**WAZUH_RAW, "id": "b-1"}
    client.post(f"{ING}/wazuh", json=a, headers=SEC)
    batch = [a, {**WAZUH_RAW, "id": "b-2"}, {**WAZUH_RAW, "id": "b-2"}, {**WAZUH_RAW, "id": "b-3"}]
    r = client.post(f"{ING}/wazuh", json=batch, headers=SEC).json()
    assert r["ingested"] == 2 and r["duplicates"] == 2 and len(r["duplicate_ids"]) == 2
    assert r["duplicate_ids"][1] == r["ids"][0]  # the repeat inside the batch points at the row just stored
    assert _count(client) == 3


def test_wazuh_event_without_id_has_no_key_and_is_stored_each_time(client):
    raw = {k: v for k, v in WAZUH_RAW.items() if k != "id"}
    client.post(f"{ING}/wazuh", json=raw, headers=SEC)
    client.post(f"{ING}/wazuh", json=raw, headers=SEC)
    assert _count(client) == 2


def test_zeek_key_is_not_the_uid_alone(client):
    a = client.post(f"{ING}/zeek", json=ZEEK_NOTICE_RAW, headers=SEC).json()
    assert a["ingested"] == 1
    same = client.post(f"{ING}/zeek", json=ZEEK_NOTICE_RAW, headers=SEC).json()
    assert same["ingested"] == 0 and same["duplicate_ids"] == a["ids"]
    other_note = {**ZEEK_NOTICE_RAW, "note": "SSH::Password_Guessing"}  # same uid and ts, other log record
    other_time = {**ZEEK_NOTICE_RAW, "ts": 1795168900.5}
    both = client.post(f"{ING}/zeek", json=[other_note, other_time], headers=SEC).json()
    assert both["ingested"] == 2 and both["duplicates"] == 0
    assert _count(client) == 3


def test_zeek_notice_without_uid_is_still_recognised_and_other_sensor_is_distinct(client):
    raw = {k: v for k, v in ZEEK_NOTICE_RAW.items() if k != "uid"}
    assert client.post(f"{ING}/zeek", json=raw, headers=SEC).json()["ingested"] == 1
    assert client.post(f"{ING}/zeek", json=raw, headers=SEC).json()["ingested"] == 0
    assert client.post(f"{ING}/zeek", json={**raw, "sensor_id": "zeek-2"}, headers=SEC).json()["ingested"] == 1


def test_conn_log_is_still_not_stored(client):
    r = client.post(f"{ING}/zeek", json=ZEEK_CONN_RAW, headers=SEC)
    assert r.status_code == 201 and r.json()["ingested"] == 0 and _count(client) == 0
    assert normalize("zeek", ZEEK_CONN_RAW) is None


def test_wazuh_webhook_resend_returns_the_existing_alert(client):
    first = client.post("/api/v1/alerts", json=webhook(alert_id="dup-1"), headers=SEC)
    again = client.post("/api/v1/alerts", json=webhook(alert_id="dup-1"), headers=SEC)
    assert first.status_code == 201 and again.status_code == 200
    assert again.json()["event_id"] == first.json()["event_id"] and _count(client) == 1


def test_zeek_webhook_alert_id_is_not_treated_as_unique(client):
    body = webhook(alert_id="CAbc123", source="zeek", severity=None, severity_label="medium")
    assert client.post("/api/v1/alerts", json=body, headers=SEC).status_code == 201
    assert client.post("/api/v1/alerts", json=body, headers=SEC).status_code == 201
    assert _count(client) == 2


def test_direct_event_create_is_unchanged_without_a_key_and_idempotent_with_one(client):
    assert client.post(EV, json=unified_event(), headers=SEC).status_code == 201
    assert client.post(EV, json=unified_event(), headers=SEC).status_code == 201
    k = unified_event(dedup_key="my-key-1")
    one = client.post(EV, json=k, headers=SEC)
    two = client.post(EV, json=k, headers=SEC)
    assert one.status_code == 201 and two.status_code == 200 and one.json()["id"] == two.json()["id"]
    assert _count(client) == 3


def test_database_refuses_a_second_row_with_the_same_key_but_allows_many_nulls(client):
    from tests.test_api import TestingSession
    db = TestingSession()
    for _ in range(2):
        db.add(models.SecurityEvent(source="x", event_type="t", severity="low", description="", timestamp=models.utcnow()))
    db.commit()
    db.add(models.SecurityEvent(source="x", event_type="t", severity="low", description="", timestamp=models.utcnow(), dedup_key="k"))
    db.commit()
    db.add(models.SecurityEvent(source="x", event_type="t", severity="low", description="", timestamp=models.utcnow(), dedup_key="k"))
    try:
        db.commit()
        raised = False
    except IntegrityError:
        db.rollback()
        raised = True
    db.close()
    assert raised


def test_parallel_insert_race_is_reported_as_duplicate(client, monkeypatch):
    """The key is stored by someone else after our check: the unique index catches it, we return that row."""
    from app.services import event_service
    from tests.test_api import TestingSession
    first = client.post(f"{ING}/wazuh", json={**WAZUH_RAW, "id": "race-1"}, headers=SEC).json()["ids"][0]
    real = event_service._find_by_key
    calls = {"n": 0}

    def blind_first(db, key):
        calls["n"] += 1
        return None if calls["n"] == 1 else real(db, key)

    monkeypatch.setattr(event_service, "_find_by_key", blind_first)
    db = TestingSession()
    from app.schemas import AlertWebhookCreate
    data = AlertWebhookCreate(**webhook(alert_id="race-1"))
    event, created = event_service.create_webhook_alert_idempotent(db, data)
    db.close()
    assert created is False and event.id == first


# ------------------------------------------------------------ migration of an existing database
OLD = ("id INTEGER PRIMARY KEY, source VARCHAR(100), event_type VARCHAR(100), severity VARCHAR(20), "
       "description TEXT, status VARCHAR(20), timestamp DATETIME, received_at DATETIME")


def _old_db(rows=3):
    e = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    with e.begin() as c:
        c.execute(text(f"CREATE TABLE security_events ({OLD})"))
        for i in range(1, rows + 1):
            c.execute(text("INSERT INTO security_events (id, source, event_type, severity, description, status) "
                           "VALUES (:i, 'wazuh', 't', 'low', 'd', 'new')"), {"i": i})
    return e


def test_migration_adds_columns_and_unique_index_and_keeps_old_rows():
    e = _old_db()
    upgrade_security_event_columns(e)
    upgrade_security_event_columns(e)  # twice is fine
    names = {c["name"] for c in inspect(e).get_columns("security_events")}
    assert {"sensor_id", "src_port", "dst_port", "protocol", "zeek_uid", "dedup_key", "disposition"} <= names
    indexes = {i["name"]: i for i in inspect(e).get_indexes("security_events")}
    assert indexes["ix_security_events_dedup_key"]["unique"]
    with e.begin() as c:
        assert c.execute(text("SELECT count(*) FROM security_events")).scalar() == 3
        assert c.execute(text("SELECT count(*) FROM security_events WHERE dedup_key IS NULL")).scalar() == 3
        c.execute(text("UPDATE security_events SET dedup_key = 'k' WHERE id = 1"))
    try:
        with e.begin() as c:
            c.execute(text("UPDATE security_events SET dedup_key = 'k' WHERE id = 2"))
        raised = False
    except IntegrityError:
        raised = True
    assert raised


# ------------------------------------------------------------ delivery reliability (forwarder)
def test_forwarder_retries_429_and_counts_duplicates(tmp_path):
    import json
    from security_scripts import forwarder
    from tests.test_security_scripts import FakeBackend, _args, _wazuh
    b = FakeBackend()
    try:
        orig = b.server.RequestHandlerClass.do_POST
        state = {"n": 0}

        def throttled(self):
            state["n"] += 1
            if state["n"] == 1:
                return self._send(429, {"detail": "slow down"})
            return orig(self)

        b.server.RequestHandlerClass.do_POST = throttled
        f = tmp_path / "alerts.json"
        f.write_text(_wazuh(1))
        stats = forwarder.forward_once(_args(tmp_path, b, f), "t" * 32)
        assert stats.sent == 1 and state["n"] == 2
        assert stats.duplicates == 0
    finally:
        b.close()


def test_same_wazuh_alert_id_from_another_manager_or_agent_is_a_different_alert(client):
    """A Wazuh alert id is only unique inside one manager: the key carries the identities the alert has."""
    base = {**WAZUH_RAW, "id": "same-id", "manager": {"name": "mgr-A"}}
    assert client.post(f"{ING}/wazuh", json=base, headers=SEC).json()["ingested"] == 1
    assert client.post(f"{ING}/wazuh", json=base, headers=SEC).json()["ingested"] == 0
    other_manager = {**base, "manager": {"name": "mgr-B"}}
    other_node = {**base, "cluster": {"name": "c1", "node": "n2"}}
    other_agent = {**base, "agent": {"id": "002", "name": "db-01", "ip": "10.0.0.11"}}
    r = client.post(f"{ING}/wazuh", json=[other_manager, other_node, other_agent], headers=SEC).json()
    assert r["ingested"] == 3 and r["duplicates"] == 0 and _count(client) == 4
    assert client.post(f"{ING}/wazuh", json=[other_manager, other_node, other_agent], headers=SEC).json()["duplicates"] == 3


def test_same_wazuh_alert_through_webhook_and_raw_ingest_is_stored_once(client):
    client.post("/api/v1/alerts", json=webhook(alert_id="x-9"), headers=SEC)
    r = client.post(f"{ING}/wazuh", json={**WAZUH_RAW, "id": "x-9"}, headers=SEC).json()
    assert r["ingested"] == 0 and r["duplicates"] == 1 and _count(client) == 1


# ------------------------------------------------------------ delivery: permanent errors, failure log, TLS
def _patched_backend(handler):
    from tests.test_security_scripts import FakeBackend
    b = FakeBackend()
    orig = b.server.RequestHandlerClass.do_POST
    b.server.RequestHandlerClass.do_POST = lambda self: handler(self, orig)
    return b


def _wazuh_line(i, desc="x"):
    import json
    return json.dumps({"id": str(i), "rule": {"id": "1", "level": 5, "description": desc}}) + "\n"


def test_permanent_400_is_not_retried_the_bad_event_goes_to_the_dead_letter_and_good_ones_are_stored(tmp_path):
    import json
    from security_scripts import forwarder
    from tests.test_security_scripts import _args
    calls = {"n": 0}

    def handler(self, orig):
        calls["n"] += 1
        length = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(length) or b"null")
        events = body if isinstance(body, list) else [body]
        if any(e.get("id") == "2" for e in events):
            return self._send(400, {"detail": "bad request"})
        outer_events.append(events)
        self._send(201, {"source": "wazuh", "ingested": len(events), "ids": list(range(len(events)))})

    outer_events = []
    b = _patched_backend(handler)
    try:
        f = tmp_path / "a.json"
        f.write_text("".join(_wazuh_line(i) for i in (1, 2, 3)))
        args = _args(tmp_path, b, f)
        stats = forwarder.forward_once(args, "t" * 32)
        assert stats.rejected == 1 and stats.stored == 2
        dead = [json.loads(x) for x in (tmp_path / "dead.jsonl").read_text().splitlines()]
        assert len(dead) == 1 and dead[0]["reason"].startswith("HTTP 400") and dead[0]["event"]["id"] == "2"
        assert calls["n"] <= 6  # split, no retry storm (no backoff sleeps happened: the test would be slow)
        assert forwarder.load_state(str(tmp_path / "state.json"))["offset"] == f.stat().st_size
    finally:
        b.close()


def test_413_splits_the_batch(tmp_path):
    import json
    from security_scripts import forwarder
    from tests.test_security_scripts import _args

    def handler(self, orig):
        length = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(length) or b"null")
        events = body if isinstance(body, list) else [body]
        if len(events) > 2:
            return self._send(413, {"detail": "too large"})
        self._send(201, {"source": "wazuh", "ingested": len(events), "ids": list(range(len(events)))})

    b = _patched_backend(handler)
    try:
        f = tmp_path / "a.json"
        f.write_text("".join(_wazuh_line(i) for i in range(1, 6)))
        stats = forwarder.forward_once(_args(tmp_path, b, f), "t" * 32)
        assert stats.stored == 5 and stats.rejected == 0
    finally:
        b.close()


def test_final_failure_writes_a_sanitized_failure_log_and_keeps_the_position(tmp_path):
    import json
    import pytest
    from security_scripts import forwarder
    from tests.test_security_scripts import _args

    def handler(self, orig):
        self.rfile.read(int(self.headers.get("Content-Length", 0)))
        self._send(503, {"detail": "down; token was " + "t" * 32})

    b = _patched_backend(handler)
    try:
        f = tmp_path / "a.json"
        f.write_text("".join(_wazuh_line(i, desc="PRIVATE-DESCRIPTION") for i in (1, 2)))
        args = _args(tmp_path, b, f, retries=1, failure_log=tmp_path / "fail.jsonl")
        with pytest.raises(forwarder.BackendUnavailable):
            forwarder.forward_once(args, "t" * 32)
        text = (tmp_path / "fail.jsonl").read_text()
        rec = json.loads(text.splitlines()[0])
        assert rec["kind"] == "backend_unavailable" and rec["events_in_batch"] == 2 and rec["position_advanced"] is False
        assert rec["from_offset"] == 0 and rec["to_offset"] == f.stat().st_size and rec["attempts_per_request"] == 2
        assert "PRIVATE-DESCRIPTION" not in text and "t" * 32 not in text and "***" in rec["reason"]
        assert forwarder.load_state(str(tmp_path / "state.json"))["offset"] is None  # not advanced
    finally:
        b.close()


def test_failure_log_also_records_a_configuration_error(tmp_path, backend):
    import json
    import pytest
    from security_scripts import forwarder
    from tests.test_security_scripts import _args
    f = tmp_path / "a.json"
    f.write_text(_wazuh_line(1))
    with pytest.raises(forwarder.ConfigError):
        forwarder.forward_once(_args(tmp_path, backend, f, failure_log=tmp_path / "fail.jsonl"), "wrong-token")
    rec = json.loads((tmp_path / "fail.jsonl").read_text().splitlines()[0])
    assert rec["kind"] == "config_error" and "wrong-token" not in json.dumps(rec)


def test_https_certificates_are_verified_by_the_forwarder_helper(tmp_path, monkeypatch):
    """A self-signed HTTPS server is refused (status 0) unless its certificate is explicitly trusted."""
    import shutil
    import ssl
    import subprocess
    import threading
    from http.server import BaseHTTPRequestHandler, HTTPServer
    import pytest
    from security_scripts.common import http_json
    if not shutil.which("openssl"):
        pytest.skip("openssl is not installed")
    cert, key = tmp_path / "c.pem", tmp_path / "k.pem"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key), "-out", str(cert),
                    "-days", "1", "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1"],
                   check=True, capture_output=True)

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_POST(self):
            self.rfile.read(int(self.headers.get("Content-Length", 0)))
            self.send_response(201)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"{}")

    srv = HTTPServer(("127.0.0.1", 0), H)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(cert), str(key))
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    url = f"https://127.0.0.1:{srv.server_port}/"
    try:
        status, _ = http_json("POST", url, token="t", body={"a": 1}, timeout=5)
        assert status == 0  # certificate not trusted: no data is sent
        monkeypatch.setenv("SSL_CERT_FILE", str(cert))  # explicitly trusting that certificate is the supported way
        status, _ = http_json("POST", url, token="t", body={"a": 1}, timeout=5)
        assert status == 201
    finally:
        srv.shutdown()


# ------------------------------------------------------------ fail-safe: unknown origin is never merged
def test_unscoped_wazuh_events_are_not_deduplicated_and_are_flagged(client):
    first = client.post(f"{ING}/wazuh", json=WAZUH_RAW, headers=SEC).json()
    again = client.post(f"{ING}/wazuh", json=WAZUH_RAW, headers=SEC).json()
    assert first["ingested"] == 1 and first["not_deduplicated"] == 1
    assert again["ingested"] == 1 and again["duplicates"] == 0 and again["not_deduplicated"] == 1
    assert _count(client) == 2  # nothing is silently dropped when the origin is unknown


def test_unscoped_same_alert_id_from_two_unidentified_managers_is_never_merged(client):
    a = {**WAZUH_RAW, "id": "1700000000.1", "agent": {"id": "001", "name": "a", "ip": "10.0.0.1"}}
    b = {**WAZUH_RAW, "id": "1700000000.1", "agent": {"id": "001", "name": "b", "ip": "10.9.9.9"}}
    r = client.post(f"{ING}/wazuh", json=[a, b], headers=SEC).json()
    assert r["ingested"] == 2 and r["duplicates"] == 0 and r["not_deduplicated"] == 2


def test_unscoped_zeek_notice_without_sensor_identity_is_not_deduplicated(client):
    a = client.post(f"{ING}/zeek", json=ZEEK_NOTICE_RAW, headers=SEC).json()
    b = client.post(f"{ING}/zeek", json=ZEEK_NOTICE_RAW, headers=SEC).json()
    assert a["ingested"] == 1 and b["ingested"] == 1 and b["not_deduplicated"] == 1 and _count(client) == 2


def test_unscoped_wazuh_webhook_without_origin_is_stored_each_time(client):
    assert client.post("/api/v1/alerts", json=webhook(alert_id="u-1"), headers=SEC).status_code == 201
    assert client.post("/api/v1/alerts", json=webhook(alert_id="u-1"), headers=SEC).status_code == 201
    assert _count(client) == 2


def test_manager_name_in_the_alert_enables_dedup_without_any_setting_unscoped(client):
    raw = {**WAZUH_RAW, "id": "m-1", "manager": {"name": "wazuh-manager-1"}}
    assert client.post(f"{ING}/wazuh", json=raw, headers=SEC).json()["not_deduplicated"] == 0
    again = client.post(f"{ING}/wazuh", json=raw, headers=SEC).json()
    assert again["ingested"] == 0 and again["duplicates"] == 1


def test_unscoped_sensor_ip_alone_enables_zeek_dedup(client):
    raw = {**ZEEK_NOTICE_RAW, "sensor_ip": "10.1.1.1"}
    assert client.post(f"{ING}/zeek", json=raw, headers=SEC).json()["ingested"] == 1
    assert client.post(f"{ING}/zeek", json=raw, headers=SEC).json()["duplicates"] == 1


def test_sensor_id_setting_feeds_wazuh_zeek_raw_and_webhook_consistently(client):
    """With SENSOR_ID configured (the autouse fixture), all routes use it as the origin and store it as sensor_id."""
    w = client.post(f"{ING}/wazuh", json={**WAZUH_RAW, "id": "c-1"}, headers=SEC).json()
    assert client.get(f"{EV}/{w['ids'][0]}").json()["sensor_id"] == "test-sensor"
    hook = client.post("/api/v1/alerts", json=webhook(alert_id="c-1"), headers=SEC)
    assert hook.status_code == 200 and hook.json()["event_id"] == w["ids"][0]  # same key through the webhook
    z = client.post(f"{ING}/zeek", json=ZEEK_NOTICE_RAW, headers=SEC).json()
    assert client.get(f"{EV}/{z['ids'][0]}").json()["sensor_id"] == "test-sensor"
    assert client.post(f"{ING}/zeek", json=ZEEK_NOTICE_RAW, headers=SEC).json()["duplicates"] == 1
    # an explicit sensor_id in the event wins over the setting and is a different origin
    other = client.post(f"{ING}/wazuh", json={**WAZUH_RAW, "id": "c-1", "sensor_id": "other-sensor"}, headers=SEC).json()
    assert other["ingested"] == 1 and other["not_deduplicated"] == 0
