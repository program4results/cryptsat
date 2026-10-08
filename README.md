# CryptSat MDM (SALTRACKER)

Multi-tenant Android management service for ministry tablets (MBSSE Sierra Leone first, then The Gambia and
Eswatini). Phase 1 is policy and security management through the Android Management API (AMAPI), with SALTRACKER
as the EMM developer. CryptSat geofencing and zero-knowledge / zero-trust features come after devices are under
control. Separate from sl.p4sgi, which will only read from this service.

Design: https://claude.ai/code/artifact/ad0987d0-1b8e-413d-84f9-cd5a6eb57b23

## Status: foundation, not deployable yet
Stack: Python 3.12+, FastAPI, Postgres 16 (psycopg 3).

Built and tested:
- Postgres schema with row-level security on every tenant table, enforced for a non-owner service role.
- Hash-chained audit log, one chain per tenant plus a platform chain; append-only in the database; exportable
  as JSONL that verifies offline.
- Tenants (one per ministry, one AMAPI enterprise each), per-tenant kill switch, rollout rings
  (pilot, 5%, 25%, 100%) that advance one step at a time with a recorded manual check.
- Versioned, validated policies; dry run fixes the exact devices an apply may touch; apply refuses without one.
- Commands: LOCK and REBOOT only, super-admin only. Wipe is blocked in the API, the adapter and the database.
- Protected serial list for the existing field tablets: flagged with an alert if ever seen, never touched.
- Enrolment tokens require an attestation that tablets are new or factory-reset; the token value is never stored.
- Read-only endpoint for the sl.p4sgi adapter (`/readonly/v1/...`, role `reader`).

Missing: OIDC login with MFA (every request is 401 until then), the real Google client (fails closed with 503),
secret-store wiring, deployment, and audit of logins (comes with OIDC).

## Not verified with Google (check before the first real enrolment)
Checked on 2026-10-08 against the AMAPI reference: the policy keys allowed in `app/policy.py` exist on Policy;
LOCK and REBOOT are command types and WIPE is one too (hence the blocks); enrolment-token fields.
Still unverified:
- Whether `debuggingFeaturesAllowed` and `installUnknownSourcesAllowed` are deprecated in favour of
  `advancedSecurityOverrides`, and the `statusReportingSettings` subfield names in the baseline template.
- Device field names in `amapi.device_from_amapi()`, the policy-id character set, and how a device's policy
  is reassigned.
- Google partner validation, quota and timeline. Data residency rules per ministry.

## Rules
- Enrol only new or factory-reset tablets. Never the 120 existing field tablets.
- Wipe stays off. Policy changes are dry-run first, then staged rings. Every tenant can be paused.
- Real credentials never go in git (`service-account*.json` is ignored).

## Run the tests
```
psql -U postgres -f db/bootstrap.sql            # once, as a superuser
psql -U postgres -c "ALTER ROLE cryptsat_owner PASSWORD 'owner'"
psql -U postgres -c "ALTER ROLE cryptsat_app PASSWORD 'app'"
psql -U postgres -c "CREATE DATABASE cryptsat_test OWNER cryptsat_owner"
python -m venv .venv && .venv/bin/pip install -r requirements-dev.txt
.venv/bin/pytest -q                             # rebuilds the test schema each run
```

## Run locally (dev only)
```
export CRYPTSAT_ENV=dev CRYPTSAT_AUTH=dev CRYPTSAT_AMAPI=fake
export CRYPTSAT_DB_OWNER_DSN=postgresql://cryptsat_owner:...@localhost/cryptsat
export CRYPTSAT_DB_DSN=postgresql://cryptsat_app:...@localhost/cryptsat
python -m app.migrate
uvicorn app.asgi:app --reload
# requests carry X-Dev-User and X-Dev-Roles, e.g. "X-Dev-Roles: sl-mbsse:admin" or "*:super_admin"
```
Dev auth and the fake AMAPI refuse to start unless `CRYPTSAT_ENV` is `dev` or `test`.

## Settings
| Variable | Default | Meaning |
|---|---|---|
| `CRYPTSAT_ENV` | `production` | `dev` / `test` unlock dev-only settings |
| `CRYPTSAT_AUTH` | `none` | `none` refuses all requests (OIDC pending); `dev` header principal |
| `CRYPTSAT_AMAPI` | `none` | `none` fails Google calls with 503; `fake` in-memory |
| `CRYPTSAT_DB_DSN` | | service role (`cryptsat_app`) |
| `CRYPTSAT_DB_OWNER_DSN` | | schema owner, migrations only |
| `CRYPTSAT_DRY_RUN_MAX_AGE_HOURS` | `24` | dry runs older than this cannot be applied |

## Roles
Per tenant: `viewer` < `operator` (sync, dry run, pause) < `admin` (policies, apply, rings, resume, tokens,
audit export). `reader` is the sl.p4sgi adapter and can only call `/readonly`. `super_admin` (platform):
tenants, enterprise binding, device commands.

## API outline
`POST /tenants` · `POST /tenants/{t}/enterprise` · `POST /tenants/{t}/pause|resume|stage` ·
`PUT /tenants/{t}/pilot-devices` · `POST|GET /tenants/{t}/protected-serials` ·
`POST /tenants/{t}/devices/sync` · `GET /tenants/{t}/devices` · `POST /tenants/{t}/devices/{d}/commands` ·
`POST /tenants/{t}/policies/{name}/versions` · `POST .../versions/{v}/dry-run` ·
`POST /tenants/{t}/dry-runs/{id}/apply` · `POST /tenants/{t}/enrolment-tokens` ·
`GET /tenants/{t}/audit[/verify|/export]` · `GET /readonly/v1/tenants/{t}/devices`
