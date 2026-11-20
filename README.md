# SCAR Backend

FastAPI backend for the SCAR (Smart Cybersecurity Autonomous Response Drone) project.

## Run

```
python -m venv venv
venv\Scripts\activate        # Windows
source venv/bin/activate     # Linux / Mac
pip install -r requirements.txt
uvicorn app.main:app --reload
```

Open http://127.0.0.1:8000/docs for the Swagger UI.

## Tests

```
pytest -v
```

## Structure

- `app/routers` - HTTP endpoints
- `app/services` - business logic
- `app/schemas.py` - request/response validation
- `app/models.py` - database tables
- `tests` - API tests

## Authentication

Telemetry endpoints need a Bearer token. Set `API_TOKEN` in `.env` (see `.env.example`).

```
Authorization: Bearer <TOKEN>
```

## Telemetry endpoint

`POST /api/v1/telemetry` - format follows the team handoff document.
Duplicate (drone_id + sequence) packets return 409 (proposed, to be confirmed).

## Notes

Event format, DB schema, numeric ranges and the duplicate status code are **proposed** and must be confirmed
with the team (Abdelrhman - telemetry, Omar - database, Ahmed - API contract).
