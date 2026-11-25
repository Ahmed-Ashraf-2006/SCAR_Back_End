"""Manage per-drone tokens.

    python -m app.drone_tokens create SCAR-DRONE-001    register a drone and print its token ONCE
    python -m app.drone_tokens rotate SCAR-DRONE-001    issue a new token (the old one stops working)
    python -m app.drone_tokens revoke SCAR-DRONE-001    block the drone
    python -m app.drone_tokens list

Only the SHA-256 hash is stored, so a lost token cannot be shown again - rotate it instead.
"""
import secrets
import sys
from datetime import datetime, timezone

from app import models  # noqa: F401  (registers the tables)
from app.database import Base, SessionLocal, engine
from app.models import Drone
from app.security import hash_token


def _new_token() -> str:
    return secrets.token_urlsafe(32)


def create(db, drone_id: str) -> str:
    if db.query(Drone).filter(Drone.drone_id == drone_id).first():
        raise ValueError(f"{drone_id} already exists; use rotate")
    token = _new_token()
    db.add(Drone(drone_id=drone_id, token_hash=hash_token(token), active=True))
    db.commit()
    return token


def rotate(db, drone_id: str) -> str:
    drone = db.query(Drone).filter(Drone.drone_id == drone_id).first()
    if drone is None:
        raise ValueError(f"{drone_id} does not exist; use create")
    token = _new_token()
    drone.token_hash = hash_token(token)
    drone.active = True
    drone.revoked_at = None
    db.commit()
    return token


def revoke(db, drone_id: str) -> None:
    drone = db.query(Drone).filter(Drone.drone_id == drone_id).first()
    if drone is None:
        raise ValueError(f"{drone_id} does not exist")
    drone.active = False
    drone.revoked_at = datetime.now(timezone.utc)
    db.commit()


if __name__ == "__main__":
    if len(sys.argv) < 2 or sys.argv[1] not in {"create", "rotate", "revoke", "list"}:
        print(__doc__)
        sys.exit(1)
    Base.metadata.create_all(bind=engine)
    with SessionLocal() as session:
        cmd = sys.argv[1]
        if cmd == "list":
            for d in session.query(Drone).order_by(Drone.drone_id):
                print(f"{d.drone_id}\t{'active' if d.active else 'REVOKED'}\tcreated {d.created_at:%Y-%m-%d %H:%M}")
        else:
            if len(sys.argv) < 3:
                print(__doc__)
                sys.exit(1)
            try:
                if cmd == "revoke":
                    revoke(session, sys.argv[2])
                    print(f"{sys.argv[2]} revoked.")
                else:
                    token = (create if cmd == "create" else rotate)(session, sys.argv[2])
                    print(f"Token for {sys.argv[2]} (shown only once):\n{token}")
            except ValueError as exc:
                print(exc)
                sys.exit(1)
