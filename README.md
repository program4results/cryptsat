# CryptSat MDM (SALTRACKER)

Multi-tenant Android management service for ministry tablets (MBSSE Sierra Leone first, then The Gambia and Eswatini).
Phase 1 is policy and security management through the Android Management API (AMAPI). CryptSat geofencing and
zero-knowledge / zero-trust features come after devices are under control.

Design: https://claude.ai/code/artifact/ad0987d0-1b8e-413d-84f9-cd5a6eb57b23

## Status: early foundation, NOT usable yet
Present: hash-chained audit log, tenants, rollout rings, policy validation/diff, command allowlist (no wipe), in-memory fake AMAPI adapter.
Missing: HTTP API, authentication (OIDC), database layer, real Google client, tests.

## Not verified
- Google partner validation, quota and timeline.
- AMAPI policy field names in `app/policy.py` (check the AMAPI Policy reference before first real enrolment).
- Data residency rules per ministry.

## Rules
- Enrol only new or factory-reset tablets. Never the 120 existing field tablets.
- Wipe stays off. Policy changes are dry-run first, then staged rings. Every tenant can be paused.
- Real credentials never go in git (`service-account*.json` is ignored).
