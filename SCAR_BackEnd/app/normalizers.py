"""Convert raw Zeek / Wazuh events into the unified SCAR event format.

The backend receives events in their ORIGINAL format, converts them here, and stores
the unified fields together with the untouched raw event.

Adding a new source (for example Suricata) only needs a new function registered in
NORMALIZERS below. The database does not change, because `source` is a free-text column.

IMPORTANT - these are best-effort assumptions based on the usual JSON output of each tool.
They must be checked against REAL sample files from the security team (Amir / Samuel):
  * the field names read from the raw events
  * the Wazuh level -> severity mapping
  * the Zeek notice -> severity mapping
"""
import ipaddress
import re
from datetime import datetime, timezone
from typing import Any, Callable, Optional

from pydantic import ValidationError

from app.config import SENSOR_ID, SENSOR_IP
from app.schemas import EventCreate


class NormalizationError(ValueError):
    """The raw event could not be converted."""


# ---------------------------------------------------------------- helpers
def _parse_time(value: Any) -> datetime:
    if value is None:
        return datetime.now(timezone.utc)
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(float(value), tz=timezone.utc)
    if isinstance(value, str):
        text = value.strip()
        try:
            return datetime.fromtimestamp(float(text), tz=timezone.utc)  # epoch sent as text
        except ValueError:
            pass
        text = text.replace("Z", "+00:00")
        text = re.sub(r"([+-]\d{2})(\d{2})$", r"\1:\2", text)  # +0000 -> +00:00
        try:
            dt = datetime.fromisoformat(text)
        except ValueError:
            raise NormalizationError(f"Unrecognised timestamp: {value!r}")
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    raise NormalizationError(f"Unrecognised timestamp: {value!r}")


def _ip(value: Any) -> Optional[str]:
    """Return the value if it is a valid IP address, otherwise None (the raw event keeps the original)."""
    if not value:
        return None
    try:
        return str(ipaddress.ip_address(str(value).strip()))
    except ValueError:
        return None


def _first(data: dict, *keys: str) -> Any:
    for key in keys:
        if data.get(key) not in (None, ""):
            return data[key]
    return None


def _text(value: Any) -> Optional[str]:
    return None if value is None else str(value)


def _port(value: Any) -> Optional[int]:
    """A TCP/UDP port 0-65535, otherwise None (the raw event keeps the original value)."""
    if value is None or isinstance(value, bool):
        return None
    try:
        number = int(str(value).strip())
    except ValueError:
        return None
    return number if 0 <= number <= 65535 else None


def _protocol(value: Any) -> Optional[str]:
    """Lower-case protocol name as sent by the source (tcp, udp, icmp ...). The allowed set is Needs Confirmation."""
    if value is None or isinstance(value, bool):
        return None
    text = str(value).strip().lower()
    return text[:20] if text else None


def _key(*parts: Any) -> Optional[str]:
    """Idempotency key from parts joined with '|'. None if the first parts are missing; long keys are hashed."""
    import hashlib

    key = "|".join("" if p is None else str(p) for p in parts)
    return key if len(key) <= 400 else "sha256:" + hashlib.sha256(key.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------- Wazuh
def wazuh_dedup_key(alert_id: Any, raw: Any, agent_id: Any = None, sensor_id: Any = None) -> Optional[str]:
    """Idempotency key of a Wazuh alert, or None when the source cannot be identified (fail-safe).

    A Wazuh alert id is only unique inside one manager. So a key is built ONLY when the alert (or the
    deployment) names its origin: manager.name, cluster.name/node, sensor_id (in the event, or the SENSOR_ID
    setting). The agent id is added to the key when present but is not an origin on its own, because two
    managers can have the same agent id. Without an origin no key is built: the event is stored every time
    (a resend is NOT recognised) and the ingest answer counts it in `not_deduplicated`. Two alerts from
    different origins are therefore never merged. A resend carries the same alert, hence the same key.
    """
    if alert_id in (None, ""):
        return None
    raw = raw if isinstance(raw, dict) else {}

    def sub(name: str, field: str) -> Any:
        obj = raw.get(name)
        return obj.get(field) if isinstance(obj, dict) else None

    origin = [
        sub("manager", "name"), sub("cluster", "name"), sub("cluster", "node"),
        sensor_id or raw.get("sensor_id") or SENSOR_ID,
    ]
    if not any(o not in (None, "") for o in origin):
        return None
    agent = sub("agent", "id")
    return _key("wazuh", alert_id, *origin, agent if agent not in (None, "") else agent_id)


def wazuh_severity(level: int) -> str:
    """PROPOSED mapping of Wazuh rule levels (0-15) to the four SCAR severities."""
    if level >= 13:
        return "critical"
    if level >= 10:
        return "high"
    if level >= 7:
        return "medium"
    return "low"


def normalize_wazuh(raw: dict) -> dict:
    rule = raw.get("rule")
    if not isinstance(rule, dict) or rule.get("level") is None:
        raise NormalizationError("Wazuh event must contain rule.level")
    try:
        level = int(rule["level"])
    except (TypeError, ValueError):
        raise NormalizationError("rule.level must be a number")
    if not 0 <= level <= 15:
        raise NormalizationError("rule.level must be between 0 and 15")

    agent = raw.get("agent") if isinstance(raw.get("agent"), dict) else {}
    data = raw.get("data") if isinstance(raw.get("data"), dict) else {}
    groups = rule.get("groups") if isinstance(rule.get("groups"), list) else []
    description = rule.get("description") or _text(raw.get("full_log")) or ""

    return {
        "source_alert_id": _text(raw.get("id")),
        "event_type": str(groups[0]) if groups else "wazuh_alert",
        "title": rule.get("description"),
        "severity_label": wazuh_severity(level),
        "severity_value": level,
        "description": description,
        "device_ip": _ip(agent.get("ip")),
        "sensor_agent_id": _text(agent.get("id")),
        "sensor_agent_name": _text(agent.get("name")),
        "sensor_agent_ip": _ip(agent.get("ip")),
        "source_ip": _ip(_first(data, "srcip", "src_ip")),
        "destination_ip": _ip(_first(data, "dstip", "dst_ip", "dest_ip")),
        "rule_id": _text(rule.get("id")),
        "timestamp": _parse_time(_first(raw, "timestamp", "@timestamp")),
        # PROPOSED field names: check against real Wazuh samples (Needs Confirmation)
        "sensor_id": _text(raw.get("sensor_id")) or SENSOR_ID,
        "src_port": _port(_first(data, "srcport", "src_port")),
        "dst_port": _port(_first(data, "dstport", "dst_port", "dest_port")),
        "protocol": _protocol(_first(data, "protocol", "proto")),
        "zeek_uid": None,
        # original alert id + the manager/cluster/agent identity carried by the alert (see wazuh_dedup_key)
        "dedup_key": wazuh_dedup_key(raw.get("id"), raw, agent.get("id")),
    }


# ---------------------------------------------------------------- Zeek
# PROPOSED severities for a few well known Zeek notices. Anything else becomes "medium".
ZEEK_NOTICE_SEVERITY = {
    "Scan::Port_Scan": "medium",
    "Scan::Address_Scan": "medium",
    "SSH::Password_Guessing": "high",
    "SSL::Invalid_Server_Cert": "medium",
}


def _zeek_id(raw: dict, name: str) -> Any:
    """Zeek JSON uses either flat keys ("id.orig_h") or a nested "id" object."""
    flat = raw.get(f"id.{name}")
    if flat is not None:
        return flat
    nested = raw.get("id")
    return nested.get(name) if isinstance(nested, dict) else None


def normalize_zeek(raw: dict) -> dict:
    orig_h, resp_h = _zeek_id(raw, "orig_h"), _zeek_id(raw, "resp_h")
    uid = _text(raw.get("uid"))
    timestamp = _parse_time(raw.get("ts"))

    if raw.get("note"):  # notice.log
        note = str(raw["note"])
        sensor_ip = _ip(raw.get("sensor_ip")) or _ip(SENSOR_IP)
        sensor_id = _text(raw.get("sensor_id")) or SENSOR_ID
        return {
            "source_alert_id": uid,
            "event_type": note,
            "title": note,
            "severity_label": ZEEK_NOTICE_SEVERITY.get(note, "medium"),
            "severity_value": None,
            "description": str(raw.get("msg") or note),
            "device_ip": None,
            "sensor_agent_id": None,
            "sensor_agent_name": None,
            "sensor_agent_ip": None,
            "sensor_ip": sensor_ip,
            "source_ip": _ip(_first(raw, "src") or orig_h),
            "destination_ip": _ip(_first(raw, "dst") or resp_h),
            "rule_id": note,
            "timestamp": timestamp,
            "sensor_id": sensor_id,
            "src_port": _port(_zeek_id(raw, "orig_p")),
            "dst_port": _port(_zeek_id(raw, "resp_p")),
            "protocol": _protocol(raw.get("proto")),
            "zeek_uid": uid,
            # PROPOSED key: log type + sensor + note + original ts + uid + src/dst. The uid is never used alone.
            # The sensor is part of the key: the same notice seen by two sensors is two alerts.
            # Without a timestamp in the raw event the time is "now", which is not stable, so no key.
            # Fail-safe: no sensor identity (sensor_id / SENSOR_ID / sensor_ip / SENSOR_IP) or no ts -> no key.
            "dedup_key": _key("zeek", "notice", sensor_id, sensor_ip, note, raw.get("ts"), uid, _text(_first(raw, "src") or orig_h), _text(_first(raw, "dst") or resp_h))
            if raw.get("ts") not in (None, "") and (sensor_id or sensor_ip)
            else None,
        }

    if orig_h and resp_h:  # conn.log is telemetry, not an alert by itself
        raise NormalizationError("Zeek connection records are not security alerts")

    raise NormalizationError(
        "Unrecognised Zeek event: expected a notice (with 'note') or a connection record (id.orig_h / id.resp_h)"
    )


# ---------------------------------------------------------------- registry
NORMALIZERS: dict[str, Callable[[dict], dict]] = {
    "wazuh": normalize_wazuh,
    "zeek": normalize_zeek,
}


def supported_sources() -> list[str]:
    return sorted(NORMALIZERS)


def normalize(source: str, raw: Any) -> EventCreate | None:
    """Raw event -> validated unified event; ordinary Zeek connections are skipped."""
    func = NORMALIZERS.get(source.strip().lower())
    if func is None:
        raise NormalizationError(f"Unsupported source '{source}'. Supported: {', '.join(supported_sources())}")
    if not isinstance(raw, dict):
        raise NormalizationError("Each event must be a JSON object")

    if source.strip().lower() == "zeek" and not raw.get("note"):
        orig_h, resp_h = _zeek_id(raw, "orig_h"), _zeek_id(raw, "resp_h")
        if orig_h and resp_h:
            return None

    fields = func(raw)
    try:
        return EventCreate(source=source, raw_event=raw, **fields)
    except ValidationError as exc:
        raise NormalizationError(exc.errors()[0]["msg"])
