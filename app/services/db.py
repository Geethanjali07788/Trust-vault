import sqlite3
from pathlib import Path
from flask import g, current_app

DEFAULT_SCHEMA_PATH = Path(__file__).resolve().parent.parent.parent / "database" / "schema.sql"

def get_db(db_path=None):
    """
    Returns an active SQLite database connection.
    In a Flask request context, the connection is cached on `g` and automatically closed at the end of the request.
    Foreign key constraints and WAL mode are strictly enforced on every connection.
    """
    if db_path is None:
        if current_app:
            db_path = current_app.config.get("DATABASE_PATH")
        else:
            from config import Config
            db_path = Config.DATABASE_PATH

    # If within a Flask request context, reuse connection stored in g
    if current_app:
        if "db" not in g:
            conn = sqlite3.connect(
                db_path,
                detect_types=sqlite3.PARSE_DECLTYPES | sqlite3.PARSE_COLNAMES
            )
            conn.row_factory = sqlite3.Row
            # Enforce foreign key constraints (SQLite has them OFF by default!)
            conn.execute("PRAGMA foreign_keys = ON;")
            # Enable Write-Ahead Logging for high concurrent read performance
            if db_path != ":memory:":
                conn.execute("PRAGMA journal_mode = WAL;")
            g.db = conn
        return g.db
    else:
        # Standalone script connection (outside Flask request context)
        conn = sqlite3.connect(
            db_path,
            detect_types=sqlite3.PARSE_DECLTYPES | sqlite3.PARSE_COLNAMES
        )
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON;")
        if db_path != ":memory:":
            conn.execute("PRAGMA journal_mode = WAL;")
        return conn


def close_db(e=None):
    """Closes the database connection at the end of the Flask request lifecycle."""
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db(db_path=None, schema_path=None):
    """
    Executes database/schema.sql to initialize all tables and indexes.
    """
    if schema_path is None:
        schema_path = DEFAULT_SCHEMA_PATH

    conn = get_db(db_path)
    with open(schema_path, "r", encoding="utf-8") as f:
        schema_sql = f.read()
    conn.executescript(schema_sql)
    conn.commit()
    return conn


def init_app(app):
    """Registers database teardown hooks and CLI commands with the Flask application."""
    app.teardown_appcontext(close_db)
