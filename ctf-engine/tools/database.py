"""
tools/database.py — Database Verification Tools.

Provides lightweight connectivity checks and query runners for
the databases commonly used in CTF labs.
"""

import logging

logger = logging.getLogger(__name__)


def check_db_connection(db_type: str, host: str = "localhost", port: int | None = None) -> str:
    """
    Verify that a database port is accepting connections.
    db_type: 'mongo' | 'mysql' | 'postgres' | 'redis' | 'sqlite'
    """
    import socket

    default_ports = {
        "mongo": 27017, "mongodb": 27017,
        "mysql": 3306,
        "postgres": 5432, "postgresql": 5432,
        "redis": 6379,
    }
    port = port or default_ports.get(db_type.lower(), 0)
    if not port:
        return f"ERROR: Unknown db_type '{db_type}'. Use mongo/mysql/postgres/redis."

    try:
        with socket.create_connection((host, port), timeout=5):
            return f"OK: {db_type} is reachable at {host}:{port}"
    except (ConnectionRefusedError, socket.timeout, OSError) as e:
        return f"FAIL: {db_type} NOT reachable at {host}:{port} — {e}"


def mongo_query(host: str = "localhost", port: int = 27017, db: str = "test",
                collection: str = "users", query: dict | None = None) -> str:
    """Run a MongoDB find query and return results (first 5 documents)."""
    try:
        from pymongo import MongoClient
        client = MongoClient(host, port, serverSelectionTimeoutMS=5000)
        results = list(client[db][collection].find(query or {}, {"_id": 0}).limit(5))
        client.close()
        if not results:
            return f"(no documents found in {db}.{collection})"
        import json
        return json.dumps(results, indent=2, default=str)
    except ImportError:
        return "ERROR: pymongo is not installed. Run: pip install pymongo"
    except Exception as e:
        return f"ERROR: MongoDB query failed: {e}"


def sqlite_query(db_path: str, sql: str) -> str:
    """Run a SQL query against a SQLite database file."""
    try:
        import sqlite3
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.execute(sql)
        rows = [dict(r) for r in cursor.fetchmany(10)]
        conn.close()
        if not rows:
            return "(query returned no rows)"
        import json
        return json.dumps(rows, indent=2, default=str)
    except Exception as e:
        return f"ERROR: SQLite query failed: {e}"
