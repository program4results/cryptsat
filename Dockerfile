# CryptSat MDM service image. No credentials are baked in: all settings and secrets arrive as environment
# variables from the platform's secret store at run time.
FROM python:3.13-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /srv
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY app ./app
COPY migrations ./migrations

# Run as an unprivileged user with no shell login and a read-only code directory.
RUN useradd --system --uid 10001 --no-create-home --shell /usr/sbin/nologin cryptsat \
    && chmod -R a-w /srv
USER 10001

ENV CRYPTSAT_ENV=production PORT=8080
EXPOSE 8080

# Same image runs migrations as a one-off job:  python -m app.migrate
CMD ["sh", "-c", "exec uvicorn app.asgi:app --host 0.0.0.0 --port ${PORT} --proxy-headers --no-server-header"]
