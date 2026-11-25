"""Check real or sample Wazuh / Zeek files against the backend's own normalizers, offline.

    python -m security_scripts.event_check --source wazuh --file alerts.json
    python -m security_scripts.event_check --source zeek  --file notice.log --show-rejected

Purpose: the normalizers (app/normalizers.py) are best-effort assumptions. Run this on REAL samples from
the security team (Amir / Samuel) to see, before anything is sent, which events would be accepted, which
would be rejected and why, and how the severities are distributed. It uses the same code the backend uses,
so the answer is the same as POST /api/v1/ingest/{source}. Nothing is sent and nothing is stored.

Exit code: 0 if every event was accepted or intentionally skipped, 1 if any event was rejected.
Run it from the project root (the folder that contains app/).
"""
import argparse
import json
import sys
from collections import Counter

from security_scripts.forwarder import SOURCES, parse_line


def check_file(source: str, path: str, show_rejected: bool = False):
    from app.normalizers import NormalizationError, normalize  # imported here: needs the project root on sys.path

    accepted, skipped, rejected = [], 0, []
    with open(path, encoding="utf-8", errors="replace") as fh:
        for number, line in enumerate(fh, start=1):
            event, problem = parse_line(source, line.strip())
            if event is None:
                if problem:
                    rejected.append((number, problem))
                continue
            try:
                unified = normalize(source, event)
            except NormalizationError as exc:
                rejected.append((number, str(exc)))
                continue
            if unified is None:
                skipped += 1  # ordinary Zeek connection record: not a security alert
            else:
                accepted.append(unified)

    report = {
        "accepted": len(accepted),
        "skipped_connections": skipped,
        "rejected": len(rejected),
        "severity": dict(Counter(e.severity_label.value if hasattr(e.severity_label, "value") else e.severity_label
                                 for e in accepted)),
        "event_types": dict(Counter(e.event_type for e in accepted).most_common(10)),
        "missing_source_ip": sum(1 for e in accepted if not e.source_ip),
        "missing_alert_id": sum(1 for e in accepted if not e.source_alert_id),
        "duplicate_alert_ids": sum(c - 1 for c in Counter(e.source_alert_id for e in accepted if e.source_alert_id).values() if c > 1),
    }
    if source == "zeek":
        from app.normalizers import ZEEK_NOTICE_SEVERITY
        unknown = Counter(e.event_type for e in accepted if e.event_type not in ZEEK_NOTICE_SEVERITY)
        report["zeek_notices_defaulted_to_medium"] = dict(unknown)
    return report, rejected


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="Check Wazuh / Zeek events against the SCAR normalizers (offline).")
    p.add_argument("--source", required=True, choices=SOURCES)
    p.add_argument("--file", required=True)
    p.add_argument("--show-rejected", action="store_true", help="print line number and reason of each rejected line")
    p.add_argument("--json", action="store_true", help="machine-readable output")
    args = p.parse_args(argv)

    report, rejected = check_file(args.source, args.file, args.show_rejected)
    if args.json:
        print(json.dumps({**report, "rejected_lines": rejected}, indent=2))
    else:
        print(f"File: {args.file}  ({args.source})")
        for key, value in report.items():
            print(f"  {key:34s} {value}")
        if args.show_rejected or rejected:
            for number, reason in rejected[:50]:
                print(f"  line {number}: {reason}")
            if len(rejected) > 50:
                print(f"  ... and {len(rejected) - 50} more")
    return 1 if rejected else 0


if __name__ == "__main__":
    sys.exit(main())
