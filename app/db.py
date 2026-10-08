"""Postgres access. Every unit of work is one transaction with the tenant scope set transaction-locally,
so row-level security applies and a pooled connection can never carry one tenant's scope into another request."""
from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager

import psycopg
from psycopg.rows import dict_row
from psycopg_pool import ConnectionPool

PLATFORM_CHAIN = "_platform"


class Database:
    def __init__(self, dsn: str, min_size: int = 1, max_size: int = 10) -> None:
        if not dsn:
            raise RuntimeError("CRYPTSAT_DB_DSN is not set")
        self.pool = ConnectionPool(
            dsn, min_size=min_size, max_size=max_size, open=False,
            kwargs={"autocommit": True, "row_factory": dict_row},
        )

    def open(self) -> None:
        self.pool.open(wait=True, timeout=10)

    def close(self) -> None:
        self.pool.close()

    @contextmanager
    def tenant(self, tenant_id: str) -> Iterator[psycopg.Connection]:
        """Transaction scoped to one tenant (or the '_platform' audit chain)."""
        with self.pool.connection() as conn, conn.transaction():
            conn.execute("SELECT set_config('app.tenant_id', %s, true), set_config('app.scope', 'tenant', true)",
                         [tenant_id])
            yield conn

    @contextmanager
    def auth(self) -> Iterator[psycopg.Connection]:
        """Sign-in scope: may read role grants, record sessions and write the '_platform' audit chain. Nothing else."""
        with self.pool.connection() as conn, conn.transaction():
            conn.execute("SELECT set_config('app.tenant_id', %s, true), set_config('app.scope', 'auth', true)",
                         [PLATFORM_CHAIN])
            yield conn

    @contextmanager
    def platform(self) -> Iterator[psycopg.Connection]:
        """Platform scope: may list and create tenants and write the '_platform' audit chain. Super-admin only."""
        with self.pool.connection() as conn, conn.transaction():
            conn.execute("SELECT set_config('app.tenant_id', %s, true), set_config('app.scope', 'platform', true)",
                         [PLATFORM_CHAIN])
            yield conn
