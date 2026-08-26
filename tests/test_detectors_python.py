"""Python AST detector tests. Go tests live in test_detectors.py and must stay green."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

DETECTORS = Path(__file__).resolve().parents[1] / "checkers"
sys.path.insert(0, str(DETECTORS))

from no_except_exception_pass_swallow import (  # noqa: E402
    detect as detect_except,
)
from no_httpx_client_without_explicit_timeout import (  # noqa: E402
    detect as detect_httpx,
)
from no_python_dynamic_sql_execution import (  # noqa: E402
    detect as detect_sql,
)
from no_raw_pii_logging import (  # noqa: E402
    detect as detect_pii,
)
from no_requests_call_without_timeout import (  # noqa: E402
    detect as detect_requests,
)
from no_request_layer_outbound_client_construction import (  # noqa: E402
    detect as detect_route_ctor,
)
from no_route_request_json_without_invalid_json_guard import (  # noqa: E402
    detect as detect_req_json,
)
from no_sync_blocking_io_in_async_def_route import (  # noqa: E402
    detect as detect_blocking,
)
from pyast_client import load_facts  # noqa: E402


# ---------- facts extractor ----------

def test_facts_none_on_syntax_error():
    assert load_facts("async def oops(:\n") is None


def test_facts_resolves_import_aliases():
    src = (
        "from httpx import AsyncClient\n"
        "from time import sleep\n"
        "import requests as req\n"
        "def f():\n"
        "    AsyncClient()\n"
        "    sleep(1)\n"
        "    req.get('x')\n"
    )
    facts = load_facts(src)
    names = [c["name"] for c in facts["calls"]]
    assert "httpx.AsyncClient" in names
    assert "time.sleep" in names
    assert "requests.get" in names


def test_facts_starargs_and_kwargs_marked():
    src = (
        "import requests\n"
        "def f(url, extra):\n"
        "    requests.get(url, *extra)\n"
        "    requests.post(url, **extra)\n"
        "    requests.delete(url, timeout=2)\n"
    )
    facts = load_facts(src)
    by_name = {c["name"]: c for c in facts["calls"]}
    assert by_name["requests.get"]["has_starargs"] is True
    assert by_name["requests.post"]["has_kwargs"] is True
    assert by_name["requests.delete"]["has_starargs"] is False
    assert by_name["requests.delete"]["has_kwargs"] is False


def test_facts_except_bare_and_narrow():
    src = (
        "try:\n    x()\n"
        "except:\n    pass\n"
        "try:\n    y()\n"
        "except KeyError:\n    pass\n"
        "try:\n    z()\n"
        "except Exception:\n    ...\n"
    )
    facts = load_facts(src)
    kinds = {(h["type"], h["body_kind"]) for h in facts["except_handlers"]}
    assert (None, "pass") in kinds
    assert ("KeyError", "pass") in kinds
    assert ("Exception", "ellipsis") in kinds


def test_facts_first_arg_kind_and_summary():
    src = (
        "def f(user_id, table, extra):\n"
        "    cursor.execute('SELECT 1')\n"
        "    cursor.execute(f\"SELECT {user_id}\")\n"
        "    cursor.execute('SELECT ' + table)\n"
        "    cursor.execute('SELECT {}'.format(user_id))\n"
        "    cursor.execute(query)\n"
        "    cursor.execute(build())\n"
        "    cursor.execute('SELECT ' + 'users')\n"
        "    cursor.execute(f'SELECT 1')\n"
        "    cursor.execute(*extra)\n"
    )
    facts = load_facts(src)
    kinds = [c["first_arg_kind"] for c in facts["calls"] if c["name"] == "cursor.execute"]
    assert kinds == [
        "string_literal",
        "fstring",
        "concat",
        "format",
        "name",
        "other",
        "string_literal",
        "string_literal",
        "other",
    ]
    fstring = next(
        c for c in facts["calls"]
        if c["name"] == "cursor.execute" and c["first_arg_kind"] == "fstring"
    )
    assert "user_id" in (fstring.get("first_arg_summary") or "")


def test_facts_in_try_mirrors_tsast():
    src = (
        "def f():\n"
        "    try:\n"
        "        inside()\n"
        "    except ValueError:\n"
        "        handler()\n"
        "    finally:\n"
        "        cleanup()\n"
        "    after()\n"
    )
    facts = load_facts(src)
    by_name = {c["name"]: c for c in facts["calls"]}
    assert by_name["inside"]["in_try"] is True
    assert by_name["handler"]["in_try"] is False
    assert by_name["cleanup"]["in_try"] is False
    assert by_name["after"]["in_try"] is False


def test_facts_request_json_property_is_a_call_fact():
    src = (
        "def hook():\n"
        "    body = request.json\n"
        "    return body\n"
    )
    facts = load_facts(src)
    names = [c["name"] for c in facts["calls"]]
    assert "request.json" in names
    rec = next(c for c in facts["calls"] if c["name"] == "request.json")
    assert rec["in_try"] is False
    assert rec["first_arg_kind"] is None


# ---------- python.asyncio.no-sync-blocking-io-in-async-def-route ----------

BAD_BLOCKING = [
    '''import requests
from fastapi import FastAPI
app = FastAPI()

@app.get("/stock/{sku}")
async def catalog_stock(sku: str):
    return requests.get(f"https://x/{sku}").json()
''',
    '''from flask import Flask
app = Flask(__name__)

@app.post("/hooks")
async def hook():
    import time
    time.sleep(2)
    return {"ok": True}
''',
    '''from urllib.request import urlopen
from fastapi import APIRouter
router = APIRouter()

@router.get("/weather")
async def weather():
    with urlopen("https://x") as resp:
        return resp.read()
''',
]

GOOD_BLOCKING = '''import httpx
from fastapi import FastAPI
app = FastAPI()

@app.get("/tickets")
async def search_tickets(q: str):
    async with httpx.AsyncClient(timeout=5.0) as client:
        resp = await client.get("https://x", params={"q": q})
        return resp.json()
'''

NEAR_MISS_BLOCKING = [
    GOOD_BLOCKING,
    '''import asyncio
from fastapi import FastAPI
app = FastAPI()

@app.post("/digest")
async def enqueue_digest():
    await asyncio.sleep(0.05)
    return {"queued": True}
''',
    '''import requests
import asyncio

async def poll_until_ready(job_id: str):
    payload = requests.get(f"https://jobs/{job_id}").json()
    await asyncio.sleep(0.4)
    return payload
''',
    '''import requests
from fastapi import FastAPI
app = FastAPI()

@app.get("/legacy")
def sync_stock(sku: str):
    return requests.get(f"https://x/{sku}").json()
''',
    '''import aiofiles
from fastapi import FastAPI
app = FastAPI()

@app.get("/note")
async def read_note():
    async with aiofiles.open("/tmp/n", "r") as fh:
        return await fh.read()
''',
]


@pytest.mark.parametrize("src", BAD_BLOCKING, ids=["requests-get", "time-sleep", "urlopen"])
def test_blocking_bad_is_flagged(src):
    assert len(detect_blocking(src)) >= 1


@pytest.mark.parametrize(
    "src",
    NEAR_MISS_BLOCKING,
    ids=["httpx-async", "asyncio-sleep", "helper-not-route", "sync-def-route", "aiofiles"],
)
def test_blocking_good_and_near_misses_pass(src):
    assert detect_blocking(src) == []


def test_blocking_skips_python_tests():
    src = BAD_BLOCKING[0]
    assert detect_blocking(src, filename="test_routes.py") == []
    assert detect_blocking(src, filename="routes_test.py") == []
    assert len(detect_blocking(src, filename="routes.py")) >= 1


# ---------- python.http.no-httpx-client-without-explicit-timeout ----------

BAD_HTTPX = [
    "import httpx\n\ndef build():\n    return httpx.AsyncClient()\n",
    "import httpx\n\ndef build(token):\n    return httpx.Client(headers={'t': token})\n",
    "from httpx import AsyncClient\n\ndef build(url):\n    return AsyncClient(base_url=url, timeout=None)\n",
]

GOOD_HTTPX = (
    "import httpx\n\n"
    "def inventory_client():\n"
    "    return httpx.AsyncClient(timeout=8.0)\n"
)

NEAR_MISS_HTTPX = [
    GOOD_HTTPX,
    "import httpx\n\ndef fetch(url):\n    return httpx.get(url, timeout=5.0)\n",
    "import httpx\n\n"
    "async def boom():\n"
    "    raise httpx.TimeoutException('late')\n",
    "import httpx\nfrom httpx import Client\n\n"
    "def reporting_client():\n"
    "    return Client(timeout=httpx.Timeout(10.0, connect=3.0))\n",
]


@pytest.mark.parametrize("src", BAD_HTTPX, ids=["async-no-args", "client-headers", "timeout-none"])
def test_httpx_bad_is_flagged(src):
    assert len(detect_httpx(src)) >= 1


@pytest.mark.parametrize(
    "src",
    NEAR_MISS_HTTPX,
    ids=["timeout-kw", "module-get", "timeout-exception", "timeout-object"],
)
def test_httpx_good_and_near_misses_pass(src):
    assert detect_httpx(src) == []


def test_httpx_timeout_none_message():
    src = "import httpx\nc = httpx.Client(timeout=None)\n"
    findings = detect_httpx(src)
    assert len(findings) == 1
    assert "timeout=None" in findings[0].message


# ---------- python.reliability.no-except-exception-pass-swallow ----------

BAD_EXCEPT = [
    "def warm(loader):\n    try:\n        loader.refresh()\n    except Exception:\n        pass\n",
    "def close_pool(pool):\n    try:\n        pool.dispose()\n    except BaseException:\n        pass\n",
    "def read_flag(raw):\n    try:\n        return raw.strip()\n    except:\n        pass\n    return False\n",
]

GOOD_EXCEPT = (
    "def display_name(row):\n"
    "    try:\n        return row['label']\n"
    "    except KeyError:\n        pass\n"
    "    return 'untitled'\n"
)

NEAR_MISS_EXCEPT = [
    GOOD_EXCEPT,
    "import logging\nlog = logging.getLogger(__name__)\n"
    "def write_audit(store, event):\n"
    "    try:\n        store.insert(event)\n"
    "    except Exception:\n        log.exception('audit insert failed')\n",
    "def load_document(repo, doc_id):\n"
    "    try:\n        return repo.fetch(doc_id)\n"
    "    except Exception:\n        raise\n",
    "def optional(repo, key):\n"
    "    try:\n        return repo.get(key)\n"
    "    except Exception:\n        return None\n",
    "class Stream:\n"
    "    def __del__(self):\n"
    "        try:\n            self.detach()\n"
    "        except Exception:\n            pass\n",
]


@pytest.mark.parametrize("src", BAD_EXCEPT, ids=["exception-pass", "base-pass", "bare-pass"])
def test_except_bad_is_flagged(src):
    assert len(detect_except(src)) >= 1


@pytest.mark.parametrize(
    "src",
    NEAR_MISS_EXCEPT,
    ids=["keyerror", "logger-exception", "reraise", "return-none", "del-dtor"],
)
def test_except_good_and_near_misses_pass(src):
    assert detect_except(src) == []


def test_except_ellipsis_flagged():
    src = "try:\n    f()\nexcept Exception:\n    ...\n"
    assert len(detect_except(src)) >= 1


# ---------- python.http.no-requests-call-without-timeout ----------

BAD_REQUESTS = [
    "import requests\n\ndef load(sku):\n    return requests.get(f'https://x/{sku}')\n",
    "import requests as req\n\ndef save(body):\n    return req.post('https://x', json=body)\n",
    "from requests import get\n\ndef ping():\n    return get('https://x', timeout=None)\n",
]

NEAR_MISS_REQUESTS = [
    "import requests\n\ndef load(sku):\n    return requests.get(f'https://x/{sku}', timeout=5)\n",
    "import requests\n\ndef load(sku, **kwargs):\n    return requests.get(f'https://x/{sku}', **kwargs)\n",
    "import httpx\n\ndef load(url):\n    return httpx.get(url)\n",
    "import requests\n\ndef load(session, url):\n    return session.get(url)\n",
]


@pytest.mark.parametrize("src", BAD_REQUESTS, ids=["get", "aliased-post", "timeout-none"])
def test_requests_bad_is_flagged(src):
    assert len(detect_requests(src)) >= 1


@pytest.mark.parametrize(
    "src",
    NEAR_MISS_REQUESTS,
    ids=["timeout-kw", "kwargs-spread", "httpx", "session-get"],
)
def test_requests_good_and_near_misses_pass(src):
    assert detect_requests(src) == []


def test_requests_timeout_none_message():
    src = "import requests\nrequests.get('https://x', timeout=None)\n"
    findings = detect_requests(src)
    assert len(findings) == 1
    assert "timeout=None" in findings[0].message


def test_requests_skips_python_tests():
    src = BAD_REQUESTS[0]
    assert detect_requests(src, filename="test_client.py") == []
    assert len(detect_requests(src, filename="client.py")) >= 1


# ---------- python.architecture.no-request-layer-outbound-client-construction ----------

BAD_ROUTE_CTOR = [
    '''from fastapi import FastAPI
import httpx
app = FastAPI()

@app.get("/stock")
async def stock():
    async with httpx.AsyncClient(timeout=5) as client:
        return (await client.get("https://x")).json()
''',
    '''from flask import Flask
import requests
app = Flask(__name__)

@app.route("/hooks", methods=["POST"])
def hook():
    s = requests.Session()
    return s.post("https://x").text
''',
]

NEAR_MISS_ROUTE_CTOR = [
    '''import httpx
from fastapi import FastAPI
app = FastAPI()

def inventory_client():
    return httpx.AsyncClient(timeout=8.0)

@app.get("/stock")
async def stock():
    return {"ok": True}
''',
    '''import httpx
from fastapi import FastAPI
app = FastAPI()

@app.get("/stock")
async def stock(client: httpx.AsyncClient):
    return (await client.get("https://x")).json()
''',
]


@pytest.mark.parametrize("src", BAD_ROUTE_CTOR, ids=["fastapi-httpx", "flask-session"])
def test_route_ctor_bad_is_flagged(src):
    assert len(detect_route_ctor(src)) >= 1


@pytest.mark.parametrize("src", NEAR_MISS_ROUTE_CTOR, ids=["factory", "injected"])
def test_route_ctor_good_and_near_misses_pass(src):
    assert detect_route_ctor(src) == []


# ---------- python.security.no-dynamic-sql-execution ----------

BAD_SQL = [
    '''def load_charge(cursor, charge_id: str):
    return cursor.execute(f"SELECT * FROM charges WHERE id = '{charge_id}'")
''',
    '''def list_bins(connection, warehouse_id: str):
    return connection.execute("SELECT * FROM bins WHERE warehouse_id = " + warehouse_id)
''',
    '''from sqlalchemy import text

def load_sku(session, sku: str):
    return session.execute(text("SELECT * FROM skus WHERE sku = '{}'".format(sku)))
''',
    '''def unlock(cursor, passphrase: str):
    return cursor.execute(f"pragma key={passphrase}")
''',
]

NEAR_MISS_SQL = [
    '''def load_charge(cursor, charge_id: str):
    return cursor.execute("SELECT * FROM charges WHERE id = ?", (charge_id,))
''',
    '''def load_charge(cursor, charge_id: str):
    return cursor.execute("SELECT * FROM charges WHERE id = %s", (charge_id,))
''',
    '''def load_users(cursor):
    return cursor.execute("SELECT * FROM " + "users WHERE active = 1")
''',
    '''def load_users(cursor):
    return cursor.execute(f"SELECT * FROM users")
''',
    '''def load_charge(cursor, charge_id: str, **kwargs):
    return cursor.execute(f"SELECT * FROM charges WHERE id = '{charge_id}'", **kwargs)
''',
    '''def load_charge(cursor, query):
    return cursor.execute(query)
''',
    '''from sqlalchemy import text

def load_sku(session, sku: str):
    return session.execute(text("SELECT * FROM skus WHERE sku = :sku"), {"sku": sku})
''',
    '''def not_sql(loop, name):
    loop.execute(f"task-{name}")
''',
    '''def set_isolation(cursor, level: str):
    cursor.execute(f"SET TRANSACTION ISOLATION LEVEL {level}")
''',
    '''def fetch_row(cursor, ident: str):
    cursor.execute("FETCH FORWARD 1 FROM " + ident)
''',
    '''def read_uncommitted(cursor, isolation_level: str):
    cursor.execute(f"PRAGMA read_uncommitted = {isolation_level}")
''',
    '''def set_encoding(cursor, client_encoding: str):
    cursor.execute(f"""
            SET CLIENT_ENCODING TO '{client_encoding.replace("'", "''")}'""")
''',
]


@pytest.mark.parametrize(
    "src", BAD_SQL, ids=["fstring", "concat", "sa-text-format", "pragma-key"],
)
def test_sql_bad_is_flagged(src):
    assert len(detect_sql(src)) >= 1


@pytest.mark.parametrize(
    "src",
    NEAR_MISS_SQL,
    ids=[
        "bound-qmark",
        "bound-percent",
        "literal-concat",
        "static-fstring",
        "kwargs-spread",
        "name-arg",
        "sa-text-literal",
        "non-sql-execute",
        "set-isolation",
        "fetch-cursor",
        "pragma-isolation",
        "set-client-encoding",
    ],
)
def test_sql_good_and_near_misses_pass(src):
    assert detect_sql(src) == []


def test_sql_skips_python_tests():
    src = BAD_SQL[0]
    assert detect_sql(src, filename="test_db.py") == []
    assert len(detect_sql(src, filename="db.py")) >= 1


def test_sql_executemany_fstring_flagged():
    src = 'cursor.executemany(f"INSERT INTO t VALUES ({x})", rows)\n'
    assert len(detect_sql(src)) >= 1


# ---------- python.security.no-raw-pii-logging ----------

BAD_PII = [
    '''import logging
logger = logging.getLogger(__name__)

def signup(email: str) -> None:
    logger.info(email)
''',
    '''import logging
log = logging.getLogger("billing")

def call_vendor(phone: str) -> None:
    log.warning(f"Calling vendor {phone}")
''',
    '''import logging

def persist_tax(ssn: str) -> None:
    logging.error("tax id %s", ssn)
''',
]

NEAR_MISS_PII = [
    '''import logging
logger = logging.getLogger(__name__)

def ping() -> None:
    logger.info("ok")
''',
    '''import logging
logger = logging.getLogger(__name__)

def signup(email: str) -> None:
    logger.info(redact(email))
''',
    '''import logging
logger = logging.getLogger(__name__)

def signup(email_hash: str) -> None:
    logger.info("stored %s", email_hash)
''',
    '''import logging
logger = logging.getLogger(__name__)

def connect(gmail_client) -> None:
    logger.info("ready %s", gmail_client)
''',
    '''import logging
logger = logging.getLogger(__name__)

def signup(phone: str) -> None:
    logger.info("msisdn %s", mask(phone))
''',
]


@pytest.mark.parametrize("src", BAD_PII, ids=["bare-email", "fstring-phone", "logging-ssn"])
def test_pii_bad_is_flagged(src):
    assert len(detect_pii(src)) >= 1


@pytest.mark.parametrize(
    "src",
    NEAR_MISS_PII,
    ids=["literal-ok", "redact", "email-hash", "gmail-client", "mask"],
)
def test_pii_good_and_near_misses_pass(src):
    assert detect_pii(src) == []


def test_pii_does_not_flag_non_logger_info():
    src = "def catalog_info(email):\n    catalog.info(email)\n"
    assert detect_pii(src) == []


# ---------- python.reliability.no-route-request-json-without-invalid-json-guard ----------

BAD_REQ_JSON = [
    '''from fastapi import FastAPI, Request
app = FastAPI()

@app.post("/chat")
async def chat(request: Request):
    body = await request.json()
    return {"message": body.get("message", "")}
''',
    '''from flask import Flask, request
app = Flask(__name__)

@app.route("/hooks", methods=["POST"])
def inbound_hook():
    body = request.json
    return {"event": body["type"]}
''',
    '''from flask import Blueprint, request
bp = Blueprint("webhooks", __name__)

@bp.route("/ingest", methods=["POST"])
def ingest():
    payload = request.json
    return payload
''',
]

NEAR_MISS_REQ_JSON = [
    '''from fastapi import FastAPI, Request
import json
app = FastAPI()

@app.post("/chat")
async def chat(request: Request):
    try:
        body = await request.json()
    except json.JSONDecodeError:
        return {"error": "invalid JSON body"}
    return {"message": body.get("message", "")}
''',
    '''from fastapi import Request

async def parse_body(request: Request):
    return await request.json()
''',
    '''from flask import Flask, request
app = Flask(__name__)

@app.route("/health")
def health():
    return {"ok": True}
''',
]


@pytest.mark.parametrize("src", BAD_REQ_JSON, ids=["fastapi-await", "flask-prop", "bp-route"])
def test_req_json_bad_is_flagged(src):
    assert len(detect_req_json(src)) >= 1


@pytest.mark.parametrize(
    "src",
    NEAR_MISS_REQ_JSON,
    ids=["try-jsondecode", "helper-not-route", "route-no-json"],
)
def test_req_json_good_and_near_misses_pass(src):
    assert detect_req_json(src) == []


def test_req_json_skips_python_tests():
    src = BAD_REQ_JSON[0]
    assert detect_req_json(src, filename="test_routes.py") == []
    assert len(detect_req_json(src, filename="routes.py")) >= 1
