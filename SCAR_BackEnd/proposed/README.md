# proposed/ (NOT part of the running backend)

`ai_contract_adapter/` is a draft AI contract adapter (PROPOSED, not approved by the team, not tested against a real AI/n8n workflow).
It is a set of replacement files for `app/` (main.py, config.py, a new router and models) and is NOT applied to the code in `app/`.
Do not copy it into `app/` unless the team approves the AI contract. Read `ai_contract_adapter/README.md` first.
Its tests are not run by `pytest` here (pytest.ini limits tests to `tests/`).
