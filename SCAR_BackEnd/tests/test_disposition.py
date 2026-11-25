"""Disposition (classification) is separate from the alert status. Original tests are untouched."""
# keep this import FIRST: it sets the test tokens before the app is imported (client is a pytest fixture)
from tests.test_api import SEC, client  # noqa: F401,E402
from sqlalchemy import create_engine, text  # noqa: E402
from sqlalchemy.pool import StaticPool  # noqa: E402

from app.migrations import upgrade_security_event_columns  # noqa: E402

DASH = {"Authorization": "Bearer test-token"}


def _alert(client, alert_id):
    body = {"alert_id": alert_id, "timestamp": "2026-11-25T10:00:00Z", "source": "wazuh", "rule_id": "5710",
            "rule_description": "ssh scan", "severity": 8, "status": "new", "raw": {"id": alert_id}}
    r = client.post("/api/v1/alerts", json=body, headers=SEC)
    assert r.status_code == 201
    return r.json()["event_id"]


def test_disposition_is_null_by_default_in_all_reads(client):
    eid = _alert(client, "w-1")
    assert client.get(f"/api/v1/alerts/{eid}").json()["disposition"] is None
    assert client.get(f"/api/v1/events/{eid}").json()["disposition"] is None
    assert client.get("/api/v1/events").json()["items"][0]["disposition"] is None
    assert client.get("/api/v1/alerts").json()["items"][0]["disposition"] is None


def test_set_clear_and_status_only_patch_on_both_routes(client):
    for base in ("/api/v1/events", "/api/v1/alerts"):
        eid = _alert(client, "w-" + base[-6:])
        r = client.patch(f"{base}/{eid}/status", json={"disposition": "false_positive"}, headers=DASH)
        assert r.status_code == 200 and r.json()["disposition"] == "false_positive" and r.json()["status"] == "new"
        r = client.patch(f"{base}/{eid}/status", json={"status": "resolved"}, headers=DASH)  # old clients
        assert r.json()["status"] == "resolved" and r.json()["disposition"] == "false_positive"
        r = client.patch(f"{base}/{eid}/status", json={"status": "investigating", "disposition": None}, headers=DASH)
        assert r.json()["status"] == "investigating" and r.json()["disposition"] is None
        assert client.get(f"{base}/{eid}").json()["disposition"] is None


def test_patch_validation_and_auth(client):
    eid = _alert(client, "w-2")
    url = f"/api/v1/events/{eid}/status"
    assert client.patch(url, json={"disposition": "false_positive"}).status_code == 401
    assert client.patch(url, json={}, headers=DASH).status_code == 422
    assert client.patch(url, json={"disposition": "maybe"}, headers=DASH).status_code == 422
    assert client.patch(url, json={"status": "bogus"}, headers=DASH).status_code == 422
    assert client.patch("/api/v1/events/999999/status", json={"status": "resolved"}, headers=DASH).status_code == 404


OLD_COLUMNS = ("id INTEGER PRIMARY KEY, source VARCHAR(100), event_type VARCHAR(100), severity VARCHAR(20), "
               "description TEXT, status VARCHAR(20), timestamp DATETIME, received_at DATETIME")


def _old_engine():
    e = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    with e.begin() as c:
        c.execute(text(f"CREATE TABLE security_events ({OLD_COLUMNS})"))
        for i, st in enumerate(["new", "investigating", "resolved", "false_positive", "open", "acknowledged"], 1):
            c.execute(text("INSERT INTO security_events (id, source, event_type, severity, description, status) "
                           "VALUES (:i, 'wazuh', 't', 'low', 'd', :s)"), {"i": i, "s": st})
    return e


def _rows(e):
    with e.begin() as c:
        return {r[0]: (r[1], r[2]) for r in c.execute(text("SELECT id, status, disposition FROM security_events"))}


def test_migration_moves_false_positive_to_disposition_and_loses_nothing():
    e = _old_engine()
    upgrade_security_event_columns(e)
    assert _rows(e) == {1: ("new", None), 2: ("investigating", None), 3: ("resolved", None),
                        4: ("resolved", "false_positive"), 5: ("new", None), 6: ("investigating", None)}


def test_migration_is_safe_to_run_twice():
    e = _old_engine()
    upgrade_security_event_columns(e)
    first = _rows(e)
    upgrade_security_event_columns(e)
    assert _rows(e) == first


def test_false_positive_is_no_longer_a_status(client):
    eid = _alert(client, "w-3")
    for base in ("/api/v1/events", "/api/v1/alerts"):
        assert client.patch(f"{base}/{eid}/status", json={"status": "false_positive"}, headers=DASH).status_code == 422
    assert client.get("/api/v1/events?status=false_positive").status_code == 422
    bad = {"alert_id": "w-4", "timestamp": "2026-11-25T10:00:00Z", "source": "wazuh", "rule_description": "x",
           "severity": 8, "status": "false_positive", "raw": {}}
    assert client.post("/api/v1/alerts", json=bad, headers=SEC).status_code == 422


def test_disposition_filter_and_overview_counts(client):
    a, b = _alert(client, "w-5"), _alert(client, "w-6")
    client.patch(f"/api/v1/events/{a}/status", json={"status": "resolved", "disposition": "false_positive"}, headers=DASH)
    for base in ("/api/v1/events", "/api/v1/alerts"):
        got = client.get(f"{base}?disposition=false_positive").json()
        assert got["total"] == 1 and got["items"][0]["event_id"] == a
        assert client.get(f"{base}?disposition=maybe").status_code == 422
    alerts = client.get("/api/v1/overview").json()["alerts"]
    assert alerts["by_disposition"] == {"false_positive": 1}
    assert alerts["by_status"] == {"new": 1, "investigating": 0, "resolved": 1}
