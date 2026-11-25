"""Tests for security_scripts (forwarder, event_check, api_security_check) using a small fake backend.

They need only the standard library plus the backend's normalizers (pydantic); no real server is started.
"""
import json
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer as HTTPServer

import pytest

from security_scripts import api_security_check, event_check, forwarder

SAMPLES = os.path.join(os.path.dirname(__file__), "..", "security_scripts", "samples")
TOKEN = "t" * 32


class FakeBackend:
    """Mimics the ingest route: 401 without the right token, 422 for events without rule.level / note / uid."""

    def __init__(self, fail_first=0):
        self.received = []       # list of batches (each a list of events)
        self.calls = 0
        self.fail_first = fail_first
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _send(self, code, body):
                data = json.dumps(body).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(data)

            def do_POST(self):
                outer.calls += 1
                length = int(self.headers.get("Content-Length", 0))
                body = json.loads(self.rfile.read(length) or b"null")
                if self.headers.get("Authorization") != f"Bearer {TOKEN}":
                    return self._send(401, {"detail": "Invalid or missing token"})
                if outer.fail_first > 0:
                    outer.fail_first -= 1
                    return self._send(503, {"detail": "busy"})
                if not self.path.startswith("/api/v1/ingest/"):
                    return self._send(404, {"detail": "Not Found"})
                events = body if isinstance(body, list) else [body]
                for index, ev in enumerate(events):
                    if not (isinstance(ev.get("rule"), dict) and "level" in ev["rule"]) and "note" not in ev and "uid" not in ev:
                        return self._send(422, {"detail": f"Event #{index}: bad event"})
                outer.received.append(events)
                self._send(201, {"source": "wazuh", "ingested": len(events), "ids": list(range(len(events)))})

        self.server = HTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_port}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()


@pytest.fixture
def backend():
    b = FakeBackend()
    yield b
    b.close()


def _wazuh(i, level=5):
    return json.dumps({"id": str(i), "rule": {"id": "1", "level": level, "description": "x"}}) + "\n"


def _args(tmp_path, backend, log_file, source="wazuh", **extra):
    argv = ["--source", source, "--file", str(log_file), "--url", backend.url,
            "--state", str(tmp_path / "state.json"), "--dead-letter", str(tmp_path / "dead.jsonl"),
            "--once", "--backoff", "0.01", "--retries", "3", "--from-start"]
    for key, value in extra.items():
        argv += [f"--{key.replace('_', '-')}", str(value)]
    return forwarder.build_parser().parse_args(argv)


# ----------------------------------------------------------------- forwarder
def test_parse_line_cases():
    assert forwarder.parse_line("wazuh", '{"a": 1}') == ({"a": 1}, None)
    assert forwarder.parse_line("zeek", "#fields ts") == (None, "")
    assert forwarder.parse_line("wazuh", "")[1] == ""
    assert "not a JSON" in forwarder.parse_line("zeek", "1764.0\tCZ1\tScan")[1]
    assert "use_json" in forwarder.parse_line("zeek", "1764.0\tCZ1")[1]
    assert "invalid JSON" in forwarder.parse_line("wazuh", '{"a": ')[1]


def test_read_lines_leaves_incomplete_last_line(tmp_path):
    f = tmp_path / "a.json"
    f.write_bytes(b'{"a":1}\n{"b":2}\n{"c":')  # last line still being written
    lines, offset = forwarder.read_lines(str(f), 0, 10)
    assert lines == ['{"a":1}', '{"b":2}']
    assert offset == len(b'{"a":1}\n{"b":2}\n')


def test_forward_sends_everything_then_nothing_on_second_run(tmp_path, backend):
    f = tmp_path / "alerts.json"
    f.write_text("".join(_wazuh(i) for i in range(5)))
    args = _args(tmp_path, backend, f)
    stats = forwarder.forward_once(args, TOKEN)
    assert (stats.sent, stats.stored, stats.rejected) == (5, 5, 0)
    again = forwarder.forward_once(args, TOKEN)
    assert again.sent == 0 and backend.calls == 1  # no duplicates after a restart


def test_forward_only_new_lines_after_append(tmp_path, backend):
    f = tmp_path / "alerts.json"
    f.write_text(_wazuh(1))
    args = _args(tmp_path, backend, f)
    forwarder.forward_once(args, TOKEN)
    with open(f, "a") as fh:
        fh.write(_wazuh(2) + _wazuh(3))
    stats = forwarder.forward_once(args, TOKEN)
    assert stats.sent == 2


def test_first_run_without_from_start_skips_old_events(tmp_path, backend):
    f = tmp_path / "alerts.json"
    f.write_text(_wazuh(1) + _wazuh(2))
    args = _args(tmp_path, backend, f)
    args.from_start = False
    assert forwarder.forward_once(args, TOKEN).sent == 0


def test_rotation_restarts_from_beginning(tmp_path, backend):
    f = tmp_path / "alerts.json"
    f.write_text("".join(_wazuh(i) for i in range(4)))
    args = _args(tmp_path, backend, f)
    forwarder.forward_once(args, TOKEN)
    f.write_text(_wazuh(99))  # truncated and rewritten, shorter than the saved offset
    assert forwarder.forward_once(args, TOKEN).sent == 1


def test_bad_events_isolated_and_dead_lettered(tmp_path, backend):
    f = tmp_path / "alerts.json"
    bad = json.dumps({"id": "bad", "rule": {"description": "no level"}}) + "\n"
    f.write_text(_wazuh(1) + bad + "garbage\n" + _wazuh(2) + _wazuh(3))
    stats = forwarder.forward_once(_args(tmp_path, backend, f), TOKEN)
    assert stats.stored == 3          # the three good events were stored
    assert stats.rejected == 2        # the event the backend refused + the non-JSON line
    reasons = [json.loads(line)["reason"] for line in (tmp_path / "dead.jsonl").read_text().splitlines()]
    assert any("bad event" in r for r in reasons) and any("not a JSON" in r for r in reasons)


def test_retry_on_5xx_then_success(tmp_path):
    b = FakeBackend(fail_first=2)
    try:
        f = tmp_path / "alerts.json"
        f.write_text(_wazuh(1))
        stats = forwarder.forward_once(_args(tmp_path, b, f), TOKEN)
        assert stats.stored == 1 and b.calls == 3
    finally:
        b.close()


def test_backend_down_does_not_advance_position(tmp_path):
    b = FakeBackend(fail_first=999)
    try:
        f = tmp_path / "alerts.json"
        f.write_text(_wazuh(1))
        args = _args(tmp_path, b, f)
        with pytest.raises(forwarder.BackendUnavailable):
            forwarder.forward_once(args, TOKEN)
        assert not (tmp_path / "state.json").exists()  # nothing lost: will be sent next time
    finally:
        b.close()


def test_wrong_token_is_a_config_error(tmp_path, backend):
    f = tmp_path / "alerts.json"
    f.write_text(_wazuh(1))
    with pytest.raises(forwarder.ConfigError):
        forwarder.forward_once(_args(tmp_path, backend, f), "wrong-token")


def test_batches_respect_batch_size(tmp_path, backend):
    f = tmp_path / "alerts.json"
    f.write_text("".join(_wazuh(i) for i in range(25)))
    forwarder.forward_once(_args(tmp_path, backend, f, batch_size=10), TOKEN)
    assert [len(b) for b in backend.received] == [10, 10, 5]


def test_main_exit_codes(tmp_path, backend, monkeypatch):
    f = tmp_path / "alerts.json"
    f.write_text(_wazuh(1))
    common = ["--source", "wazuh", "--file", str(f), "--url", backend.url, "--once", "--from-start",
              "--state", str(tmp_path / "s.json"), "--dead-letter", str(tmp_path / "d.jsonl")]
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("API_TOKEN", raising=False)
    monkeypatch.delenv("SECURITY_TOKEN", raising=False)
    assert forwarder.main(common) == 2                      # no token configured
    monkeypatch.setenv("SECURITY_TOKEN", "wrong")
    assert forwarder.main(common) == 2                      # 401 from backend
    monkeypatch.setenv("SECURITY_TOKEN", TOKEN)
    assert forwarder.main(common) == 0


def test_zeek_notice_file_with_header_and_connection(tmp_path, backend):
    stats = forwarder.forward_once(
        _args(tmp_path, backend, os.path.join(SAMPLES, "zeek_notice.log"), source="zeek"), TOKEN)
    assert stats.skipped_comments == 1 and stats.sent == 4  # the backend itself skips the conn record


# ----------------------------------------------------------------- event_check
def test_event_check_wazuh_sample():
    report, rejected = event_check.check_file("wazuh", os.path.join(SAMPLES, "wazuh_alerts.json"))
    assert report["accepted"] == 4 and report["rejected"] == 2
    assert report["severity"] == {"low": 2, "high": 1, "critical": 1}
    assert [n for n, _ in rejected] == [4, 5]


def test_event_check_zeek_sample():
    report, rejected = event_check.check_file("zeek", os.path.join(SAMPLES, "zeek_notice.log"))
    assert report["accepted"] == 3 and report["skipped_connections"] == 1 and not rejected
    assert report["zeek_notices_defaulted_to_medium"] == {"Weird::Activity": 1}


def test_event_check_exit_code():
    assert event_check.main(["--source", "wazuh", "--file", os.path.join(SAMPLES, "wazuh_alerts.json")]) == 1
    assert event_check.main(["--source", "zeek", "--file", os.path.join(SAMPLES, "zeek_notice.log")]) == 0


# ----------------------------------------------------------------- api_security_check
class _Api(BaseHTTPRequestHandler):
    open_routes: set = set()

    def log_message(self, *a):
        pass

    def _reply(self):
        path = self.path
        auth = self.headers.get("Authorization", "")
        if self.command == "GET" and path == "/health":
            code = 200
        elif (self.command, path.split("/{")[0]) in self.open_routes or (self.command, path) in self.open_routes:
            code = 200
        elif auth == "Bearer api-" + "a" * 28 and path.startswith("/api/v1/drones"):
            code = 200
        elif auth == "Bearer sec-" + "b" * 28 and path.startswith("/api/v1/ingest/"):
            code = 422
        else:
            code = 401
        body = b"{}"
        self.send_response(code)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    do_GET = do_POST = do_PATCH = do_DELETE = _reply


def _serve(open_routes=()):
    handler = type("H", (_Api,), {"open_routes": set(open_routes)})
    server = HTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, f"http://127.0.0.1:{server.server_port}"


def test_api_check_passes_on_a_closed_server():
    server, url = _serve()
    try:
        rep = api_security_check.run(url, "api-" + "a" * 28, "sec-" + "b" * 28, "ai-" + "c" * 28)
        assert not rep.failed, [r for r in rep.rows if r[0] == "FAIL"]
    finally:
        server.shutdown()


def test_api_check_flags_open_route_and_weak_shared_tokens():
    server, url = _serve(open_routes=[("DELETE", "/api/v1/events/999999999")])
    try:
        rep = api_security_check.run(url, "change-me-123", "change-me-123", "")
        fails = [name for level, name, _ in rep.rows if level == "FAIL"]
        assert any(name.startswith("DELETE /api/v1/events/{id}") for name in fails)
        assert any("strong secret" in name for name in fails)
        assert any("three different secrets" in name for name in fails)
    finally:
        server.shutdown()


def test_api_check_server_down_returns_2():
    assert api_security_check.main(["--url", "http://127.0.0.1:9"]) == 2
