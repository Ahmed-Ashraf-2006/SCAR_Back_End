# AI contract adapter (PROPOSED, not team-approved)

Adds the root-level routes from the AI team's DRAFT `scar-ai/docs/contracts.md` (section 4.1) next to the
existing `/api/v1` API. Nothing existing was changed: same routes, tokens, tables and statuses.

Status: PROPOSED adapter. The AI team's contract is a draft that needs the backend team's "agreed".
Path style (root vs /api/v1), X-API-Key vs Bearer, and the event model are still team decisions.

## Auth
Header `X-API-Key: <AI_CONTRACT_API_KEY>` (set it in `.env`; no fallback to the other tokens, if empty the
AI routes answer 500). The Bearer tokens of `/api/v1` do not open these routes, and this key does not open `/api/v1`.

## Routes (root, not under /api/v1)
POST /events (idempotent on event_id; 201 new, 200 repeat) | GET /events?status=pending&limit=50 (oldest first)
GET /events/{id} | GET /events/{id}/analysis-results | POST /events/{id}/claim (200, 409 if not pending)
PATCH /events/{id}/status {status, error?} | POST /events/requeue-stuck {older_than_seconds}
POST /analysis-results/bulk {event_id, results:[...]} (upsert on event_id+agent+model_version; the 3 agents
are all kept) | POST /missions, GET /missions/{id}, /missions/{id}/events, /missions/{id}/analysis-results?agent=risk
POST /workflow-runs | POST /alerts | POST /reports. `/health` already exists and is unchanged.

## Two different statuses (do not mix)
- Alert status of `/api/v1` (security_events.status): new, investigating, resolved, false_positive.
- AI processing status (ai_events.status, this adapter only): pending, processing, analyzed, failed.
They are never mapped to each other here.

## Storage
New tables `ai_events`, `ai_analysis_results`, `ai_missions`, `ai_workflow_runs`, `ai_alerts`, `ai_reports`
(created automatically at startup). AI events are NOT copied into `security_events` (so the dashboard
`/api/v1` data is unchanged). Whether to link or merge them is a team decision (Needs Confirmation).

## Not covered (Needs Confirmation / not done)
authorized_assets (baseline) | digital twin tables | push from backend to n8n (`/webhook/scar/analyze`)
(only the 30 s sweeper pulling `GET /events?status=pending` works) | PostgreSQL schema (this runs on the
backend's SQLAlchemy DB, SQLite by default) | hosting / reachable base URL | Telegram.
The old single `POST /api/v1/ai/analysis` still works and still stores one result per event (overwrites).
