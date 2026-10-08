# Deploying CryptSat MDM

Status: notes for the first environment. Nothing here has been deployed. Hosting region and data residency
per ministry are still an open legal decision (design doc), so no region is fixed below.

## Shape
One service per environment (staging, production), each with its own database, its own identity-provider
client and, later, its own AMAPI service account. The design doc proposes Google Cloud under a SALTRACKER
project; the image itself runs anywhere that runs containers.

- **Service:** the image from `Dockerfile` (non-root, port 8080). Stateless; scale horizontally.
- **Database:** managed Postgres 16. Two roles from `db/bootstrap.sql`: `cryptsat_owner` (migrations only) and
  `cryptsat_app` (the service; row-level security applies to it). Enable automated backups and point-in-time
  recovery; the audit log is the record ministries rely on.
- **Migrations:** run the same image as a one-off job, `python -m app.migrate`, with
  `CRYPTSAT_DB_OWNER_DSN`. Run before each release. The service never receives the owner DSN.
- **Secrets:** from the platform secret store as environment variables, never in git or the image:
  `CRYPTSAT_DB_DSN`, `CRYPTSAT_DB_OWNER_DSN` (migration job only), and later the AMAPI service-account key.
  Rotate on a schedule; alert on access.
- **TLS:** terminated by the platform's load balancer. The service trusts `X-Forwarded-*` via `--proxy-headers`;
  do not expose port 8080 directly.

## Settings for production
| Variable | Value |
|---|---|
| `CRYPTSAT_ENV` | `production` (image default) |
| `CRYPTSAT_AUTH` | `oidc` |
| `CRYPTSAT_OIDC_ISSUER` | the identity provider's issuer URL (https) |
| `CRYPTSAT_OIDC_AUDIENCE` | this environment's OAuth client id |
| `CRYPTSAT_OIDC_MFA` | `amr` (default). Use `idp-enforced` only if the provider enforces MFA for every account and does not report it in tokens. |
| `CRYPTSAT_OIDC_ALLOWED_DOMAINS` | e.g. `saltracker.example` plus each ministry's domain |
| `CRYPTSAT_AMAPI` | `none` until the real client exists (calls return 503) |
| `CRYPTSAT_DB_DSN` | from the secret store |

`CRYPTSAT_AUTH=dev` and `CRYPTSAT_AMAPI=fake` refuse to start in production.

### Identity provider notes
- **Google Workspace** (if SALTRACKER and ministry staff sign in with Google): issuer
  `https://accounts.google.com`. Google ID tokens are not expected to carry an `amr` claim (not verified), so
  enforce 2-Step Verification for every account in the Workspace admin console and set
  `CRYPTSAT_OIDC_MFA=idp-enforced`. Restrict with `CRYPTSAT_OIDC_ALLOWED_DOMAINS`.
- **Microsoft Entra ID or Keycloak:** both can put `amr` (or a step-up `acr`) in tokens; keep the default `amr`
  or use `acr:<value>`.
- The service only verifies bearer tokens. The sign-in flow itself (authorization code with PKCE) belongs to
  the dashboard client, which is not built yet.

## First start
1. Bootstrap roles and the database (`db/bootstrap.sql`), set passwords from the secret store.
2. Run the migration job.
3. Create the first super-admin once: `python -m app.grants bootstrap you@saltracker.example`
   (as a one-off job with `CRYPTSAT_DB_DSN`). It refuses if any super-admin exists.
4. Sign in, then add the break-glass group and per-tenant roles through `POST /grants`.
5. Create the MBSSE tenant; bind its AMAPI enterprise only after Google approval (`POST /tenants/{t}/enterprise`).
6. Record the 120 existing field tablets' serials with `POST /tenants/{t}/protected-serials` before any
   enrolment token is issued.

## Not done yet
Real AMAPI client and service-account handling; dashboard and its sign-in flow; alerting on
`alert.protected_device_enrolled`, `auth.refused` spikes and audit verification failures; scheduled audit
verification; infrastructure as code.
