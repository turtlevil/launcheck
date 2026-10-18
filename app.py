"""launcheck — hackathon MVP, FastAPI + SQLite + optional OpenAI scenario generation.

Run: uvicorn app:app --reload
The demonstration is fictional and is not a security-hardened production integration.
"""
from __future__ import annotations

import csv
import hashlib
import hmac
import secrets
import time
import io
import json
import os
import re
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any

from fastapi import FastAPI, File, HTTPException, UploadFile, Request
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware
from dotenv import load_dotenv
import connectors
from pydantic import BaseModel, Field

ROOT = Path(__file__).resolve().parent
load_dotenv(ROOT / ".env")
DB_PATH = Path(os.getenv('LAUNCHCHECK_DB', str(ROOT / 'launchcheck.sqlite3')))
DB_PATH.parent.mkdir(parents=True, exist_ok=True)
MAX_UPLOAD_BYTES = 3 * 1024 * 1024
MAX_TEXT_CHARS = 22000
ACTIONS = {'hold', 'pilot', 'full'}
ACTION_LABELS = {
    'hold': 'Pause launch pending sign-off',
    'pilot': 'Proceed with restricted pilot',
    'full': 'Proceed with full launch',
}

@contextmanager
def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute('PRAGMA foreign_keys = ON')
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec='seconds')


def init_db():
    with db() as conn:
        conn.executescript('''
        CREATE TABLE IF NOT EXISTS projects (
            id TEXT PRIMARY KEY, name TEXT NOT NULL, decision TEXT NOT NULL,
            is_demo INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS sources (
            id TEXT PRIMARY KEY, project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
            filename TEXT NOT NULL, kind TEXT NOT NULL, content TEXT NOT NULL, created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS scenarios (
            id TEXT PRIMARY KEY, project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
            role TEXT NOT NULL, title TEXT NOT NULL, situation TEXT NOT NULL,
            question TEXT NOT NULL, options_json TEXT NOT NULL, source_ids_json TEXT NOT NULL,
            reference_action TEXT NOT NULL DEFAULT 'unknown', created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS responses (
            id TEXT PRIMARY KEY, scenario_id TEXT NOT NULL UNIQUE REFERENCES scenarios(id) ON DELETE CASCADE,
            participant TEXT NOT NULL, action TEXT NOT NULL, rationale TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        ''')
        conn.executescript('''
        CREATE TABLE IF NOT EXISTS workspace (
          id INTEGER PRIMARY KEY CHECK (id = 1), company TEXT NOT NULL,
          owner_name TEXT NOT NULL, owner_email TEXT NOT NULL UNIQUE,
          password_hash TEXT NOT NULL, slack_hint TEXT NOT NULL DEFAULT '',
          gmail_hint TEXT NOT NULL DEFAULT '', wanted_json TEXT NOT NULL,
          created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS connections (
          provider TEXT PRIMARY KEY, label TEXT NOT NULL,
          encrypted_token TEXT NOT NULL, created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS selected_channels (
          channel_id TEXT PRIMARY KEY, channel_name TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS invites (
          token_hash TEXT PRIMARY KEY, scenario_id TEXT NOT NULL REFERENCES scenarios(id) ON DELETE CASCADE,
          expires_at INTEGER NOT NULL, used_at INTEGER NOT NULL DEFAULT 0
        );
        ''')
        for column, definition in [('provider', "TEXT NOT NULL DEFAULT 'upload'"), ('external_id', "TEXT NOT NULL DEFAULT ''")]:
            cols={r['name'] for r in conn.execute('PRAGMA table_info(sources)')}
            if column not in cols:
                conn.execute(f'ALTER TABLE sources ADD COLUMN {column} {definition}')
        # v3: individual employee accounts and separately authorized provider connections.
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS employees (
          id TEXT PRIMARY KEY, name TEXT NOT NULL, email TEXT NOT NULL UNIQUE,
          role TEXT NOT NULL, password_hash TEXT NOT NULL, created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS employee_invites (
          token_hash TEXT PRIMARY KEY, email TEXT NOT NULL, role TEXT NOT NULL,
          expires_at INTEGER NOT NULL, redeemed_at INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS employee_connections (
          employee_id TEXT NOT NULL REFERENCES employees(id) ON DELETE CASCADE,
          provider TEXT NOT NULL, label TEXT NOT NULL, encrypted_token TEXT NOT NULL,
          created_at TEXT NOT NULL, PRIMARY KEY(employee_id,provider)
        );
        CREATE TABLE IF NOT EXISTS employee_channels (
          employee_id TEXT NOT NULL REFERENCES employees(id) ON DELETE CASCADE,
          channel_id TEXT NOT NULL, channel_name TEXT NOT NULL,
          PRIMARY KEY(employee_id,channel_id)
        );
        CREATE TABLE IF NOT EXISTS employee_project_consent (
          employee_id TEXT NOT NULL REFERENCES employees(id) ON DELETE CASCADE,
          project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
          granted_at TEXT NOT NULL,
          PRIMARY KEY(employee_id,project_id)
        );
        """)
        cols={r['name'] for r in conn.execute('PRAGMA table_info(sources)')}
        if 'employee_id' not in cols:
            conn.execute("ALTER TABLE sources ADD COLUMN employee_id TEXT NOT NULL DEFAULT ''")
        # v5: preserve pre-existing questions as published; new questions start in draft.
        question_columns = {r['name'] for r in conn.execute('PRAGMA table_info(scenarios)')}
        for col, ddl in (
            ('question_type', "TEXT NOT NULL DEFAULT 'multiple_choice'"),
            ('status', "TEXT NOT NULL DEFAULT 'published'"),
            ('cohort', "TEXT NOT NULL DEFAULT 'legacy'"),
        ):
            if col not in question_columns:
                conn.execute(f'ALTER TABLE scenarios ADD COLUMN {col} {ddl}')
        # No default fictional company. The owner must create a workspace first.


def insert_project(conn, name: str, decision: str, is_demo=False):
    project_id = uuid.uuid4().hex[:12]
    conn.execute('INSERT INTO projects VALUES (?, ?, ?, ?, ?)',
                 (project_id, name.strip(), decision.strip(), int(is_demo), now()))
    return project_id


def insert_source(conn, project_id: str, filename: str, kind: str, content: str, provider="upload", external_id=""):
    source_id = uuid.uuid4().hex[:12]
    conn.execute('''INSERT INTO sources (id,project_id,filename,kind,content,created_at,provider,external_id)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
                 (source_id, project_id, filename, kind, content[:MAX_TEXT_CHARS], now(), provider, external_id))
    return source_id


def insert_scenario(conn, project_id: str, scenario: dict):
    sid = uuid.uuid4().hex[:12]
    conn.execute('''INSERT INTO scenarios
      (id,project_id,role,title,situation,question,options_json,source_ids_json,
       reference_action,created_at,question_type,status,cohort)
      VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)''',
      (sid, project_id, scenario['role'].strip(), scenario['title'].strip(),
       scenario['situation'].strip(), scenario['question'].strip(),
       json.dumps(scenario.get('options', [])), json.dumps(scenario.get('source_ids', [])),
       scenario.get('reference_action', 'unknown'), now(),
       scenario.get('question_type', 'multiple_choice'), scenario.get('status', 'published'),
       scenario.get('cohort', 'legacy')))
    return sid


