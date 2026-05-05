import os
import json
import jwt
import pytest
from cryptography.hazmat.primitives import serialization

# Env vars deben estar seteadas ANTES de importar main.py
# porque main.py lee KEY_PATH y ejecuta load_rsa_keys() al importar.
_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

os.environ.setdefault("KEY_PATH",      os.path.join(_root, "app", "keys", "public_key.pem"))
os.environ.setdefault("BASELINE_PATH", os.path.join(_root, "data", "baseline.json"))
os.environ.setdefault("CAMPAING",      "=MWZzRWdvx2Y")
# DB vars necesarias para que get_db_connection() no explote en import (no se llama en tests unitarios)
os.environ.setdefault("DB_HOST_B64",   "ZGI=")
os.environ.setdefault("DB_USER_B64",   "YWRtaW4=")
os.environ.setdefault("DB_PASS_B64",   "YWRtaW5wYXNz")
os.environ.setdefault("DB_NAME_B64",   "Y2xvdWRzZWM=")

import main as _main  # seguro: KEY_PATH ya está seteado

_PRIVATE_KEY_PATH = os.path.join(_root, "app", "keys", "private_key.pem")

with open(os.path.join(_root, "data", "baseline.json")) as _f:
    _BASELINES = {r["resource_id"]: r for r in json.load(_f)}


@pytest.fixture
def client():
    _main.app.config["TESTING"] = True
    with _main.app.test_client() as c:
        yield c


@pytest.fixture
def private_key():
    with open(_PRIVATE_KEY_PATH, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


@pytest.fixture
def valid_token(private_key):
    return jwt.encode({"user": "bob", "role": "cloudsec"}, private_key, algorithm="RS256")


@pytest.fixture
def mock_db(monkeypatch):
    """
    Mock de psycopg2 para tests unitarios de endpoints.
    SmartCursor interpreta queries por contenido para retornar datos realistas.
    """

    class SmartCursor:
        def __init__(self):
            self._last_query = ""
            self._last_params = None

        def execute(self, query, params=None):
            self._last_query = query.strip().lower()
            self._last_params = params

        def fetchone(self):
            q = self._last_query
            params = self._last_params

            # seed_baseline_if_empty: indica que la tabla ya tiene datos → skip seed
            if "count(*) from resources_baseline" in q:
                return (1,)

            # ingest: leer baseline por resource_id
            if "select config from resources_baseline" in q:
                rid = params[0] if params else None
                data = _BASELINES.get(rid)
                return (data,) if data else None

            # admin/flag: leer rol del usuario
            if "select role from users" in q:
                username = params[0] if params else None
                # Solo bob tiene rol cloudsec; username=None no hace match
                return ("cloudsec",) if username == "bob" else None

            return None

        def fetchall(self):
            q = self._last_query

            if "select username from users" in q:
                return [("alice",), ("bob",), ("admin",)]

            # drifts/summary: GROUP BY type
            if "select type, count" in q:
                return [("VM", 3), ("LoadBalancer", 1)]

            # drifts/summary: GROUP BY severity
            if "select severity, count" in q:
                return [("Critical", 1), ("High", 1), ("Medium", 1), ("Low", 1)]

            return []

        def close(self):
            pass

    class SmartConn:
        def cursor(self):
            return SmartCursor()

        def commit(self):
            pass

        def close(self):
            pass

    monkeypatch.setattr("main.get_db_connection", lambda: SmartConn())