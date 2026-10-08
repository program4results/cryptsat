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
- Single sign-on (OIDC bearer tokens): signature, issuer, audience and expiry checks; MFA required for people;
  roles from the `role_grants` table (super-admin managed, audited, last-super-admin guard); service identities
  limited to `reader`; each sign-in audited once.
- `python -m app.verify_audit` checks every chain and exits 1 on any break (for a scheduled job).
- Container image (`Dockerfile`, non-root) and deployment notes in `docs/deploy.md`.

Missing: the real Google client (fails closed with 503) and service-account handling, the dashboard and its
sign-in flow, alerting, infrastructure as code.

## Google facts (checked 2026-10-08)
Verified: policy keys allowed in `app/policy.py` exist on Policy; `passwordRequirements` and
`installUnknownSourcesAllowed` are deprecated (now rejected); `statusReportingSettings` subfields; LOCK and REBOOT
are command types and WIPE is one too (hence the blocks); enrolment-token fields; Device fields used in
`amapi.device_from_amapi()`; devices are reassigned with `devices.patch` of `policyName`.

Still unverified (check before the first real enrolment):
- Whether `debuggingFeaturesAllowed` is deprecated in favour of `advancedSecurityOverrides.developerSettings`
  (the baseline still uses it for the ADB exception), and that setting's values.
- `hardwareInfo.serialNumber` on Device (page cut off).
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
| `CRYPTSAT_AUTH` | `none` | `none` refuses all requests; `oidc` single sign-on; `dev` header principal |
| `CRYPTSAT_OIDC_ISSUER` / `_AUDIENCE` | | identity provider issuer (https) and this service's client id |
| `CRYPTSAT_OIDC_MFA` | `amr` | `amr`, `acr:<value>`, or `idp-enforced` (see `docs/deploy.md`) |
| `CRYPTSAT_OIDC_ALLOWED_DOMAINS` | | optional comma list of email domains for people |
| `CRYPTSAT_OIDC_JWKS_URI` | | optional; otherwise discovered from the issuer |
| `CRYPTSAT_AMAPI` | `none` | `none` fails Google calls with 503; `fake` in-memory |
| `CRYPTSAT_DB_DSN` | | service role (`cryptsat_app`) |
| `CRYPTSAT_DB_OWNER_DSN` | | schema owner, migrations only |
| `CRYPTSAT_DRY_RUN_MAX_AGE_HOURS` | `24` | dry runs older than this cannot be applied |

## Roles
Granted in the database by super-admins (`POST /grants`); the first super-admin is created once with
`python -m app.grants bootstrap <email>`. Per tenant: `viewer` < `operator` (sync, dry run, pause) < `admin` (policies, apply, rings, resume, tokens,
audit export). `reader` is the sl.p4sgi adapter and can only call `/readonly`. `super_admin` (platform):
tenants, enterprise binding, device commands.

## API outline
`POST /tenants` · `POST /tenants/{t}/enterprise` · `POST /tenants/{t}/pause|resume|stage` ·
`PUT /tenants/{t}/pilot-devices` · `POST|GET /tenants/{t}/protected-serials` ·
`POST /tenants/{t}/devices/sync` · `GET /tenants/{t}/devices` · `POST /tenants/{t}/devices/{d}/commands` ·
`POST /tenants/{t}/policies/{name}/versions` · `POST .../versions/{v}/dry-run` ·
`POST /tenants/{t}/dry-runs/{id}/apply` · `POST /tenants/{t}/enrolment-tokens` ·
`GET /tenants/{t}/audit[/verify|/export]` · `GET /readonly/v1/tenants/{t}/devices` ·
`GET /me` · `GET|POST /grants` · `POST /grants/revoke` · `GET /tenants/{t}/grants`
