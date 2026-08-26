import sys
from pathlib import Path

import pytest

DETECTORS = Path(__file__).resolve().parents[1] / "checkers"
sys.path.insert(0, str(DETECTORS))

from no_fetch_without_abort_timeout import detect as detect_fetch  # noqa: E402
from no_empty_catch_in_route_handler import detect as detect_catch  # noqa: E402
from no_unguarded_json_parse_on_external_input import detect as detect_json  # noqa: E402
from no_or_default_for_nonzero_number import detect as detect_or  # noqa: E402
from no_eager_heavy_dependency_import import detect as detect_heavy  # noqa: E402
from no_unvalidated_external_href import detect as detect_href  # noqa: E402
from no_orphaned_effect_timeouts import detect as detect_timeout  # noqa: E402
from no_mixed_controlled_uncontrolled import detect as detect_mixed  # noqa: E402


# ---------- typescript.http.no-fetch-without-abort-timeout ----------

BAD_FETCH = [
    'export async function load(id: string) {\n  return fetch("/items/" + id)\n}\n',
    '''export async function save(body: string) {
  return fetch("/items", { method: "POST", headers: { "content-type": "text/plain" }, body })
}
''',
    'prefetch = () => { fetch("/next") }\n',
]

GOOD_FETCH = '''export async function load(id: string) {
  return fetch("/items/" + id, { signal: AbortSignal.timeout(5_000) })
}
'''

NEAR_MISS_FETCH = [
    GOOD_FETCH,
    '''export async function load(id: string) {
  const controller = new AbortController()
  return fetch("/items/" + id, { signal: controller.signal })
}
''',
    '''export async function load(id: string) {
  const opts = { method: "GET", signal: AbortSignal.timeout(3_000) }
  return fetch("/items/" + id, opts)
}
''',
    'export async function load(id: string) {\n  return axios.get("/items/" + id)\n}\n',
    '''export function wrap(fetch: (url: string) => Promise<Response>, url: string) {
  return fetch(url)
}
''',
    '''export async function load(url: string, init: RequestInit) {
  return fetch(url, init)
}
''',
    'export async function load(url: string) {\n  return ky.get(url)\n}\n',
]


@pytest.mark.parametrize("src", BAD_FETCH, ids=["url-only", "headers-no-signal", "prefetch"])
def test_fetch_bad_is_flagged(src):
    assert len(detect_fetch(src)) >= 1


@pytest.mark.parametrize(
    "src",
    NEAR_MISS_FETCH,
    ids=["timeout", "controller", "same-fn-opts", "axios", "local-fetch-param",
         "unknown-init", "ky"],
)
def test_fetch_good_and_near_misses_pass(src):
    assert detect_fetch(src) == []


def test_fetch_spread_known_signal_not_flagged():
    src = '''export async function load(id: string) {
  const base = { signal: AbortSignal.timeout(2_000) }
  return fetch("/items/" + id, { ...base, method: "GET" })
}
'''
    assert detect_fetch(src) == []


def test_fetch_test_file_skipped():
    src = 'export async function load() { return fetch("/x") }\n'
    assert detect_fetch(src, filename="client.test.ts") == []
    assert detect_fetch(src, filename="client.spec.ts") == []
    assert len(detect_fetch(src, filename="client.ts")) >= 1


# ---------- typescript.express.no-empty-catch-in-route-handler ----------

BAD_CATCH = [
    '''app.get("/health", async (req, res) => {
  try { await ping() } catch {}
})
''',
    '''app.post("/hooks", async (c) => {
  try { await c.req.json() } catch { // ignore
  }
})
''',
    '''export async function guard(ctx, next) {
  try { await next() } catch (err) { /* swallowed */ }
}
''',
]

NEAR_MISS_CATCH = [
    '''app.get("/health", async (req, res) => {
  try { await ping() } catch (err) {
    res.status(503).json({ ok: false })
  }
})
''',
    '''function decodeMaybe(raw: string) {
  try { return JSON.parse(raw) } catch { return null }
}
''',
    '''export async function pingRoute(c) {
  try { await check() } catch (err) { return c.json({ ok: false }) }
}
''',
    '''function readCodec(buf: string) {
  try { return parseFrame(buf) } catch {
    // ignore malformed optional frame in the codec
  }
}
''',
]


@pytest.mark.parametrize("src", BAD_CATCH, ids=["express-empty", "hono-ignore", "koa-comment"])
def test_catch_bad_is_flagged(src):
    assert len(detect_catch(src)) >= 1


@pytest.mark.parametrize(
    "src",
    NEAR_MISS_CATCH,
    ids=["handler-responds", "parser-fallback", "handler-returns", "codec-ignore"],
)
def test_catch_good_and_near_misses_pass(src):
    assert detect_catch(src) == []


def test_catch_execution_ctx_feature_detect_not_flagged():
    src = '''app.get("/x", async (c) => {
  try {
    const executionContext = c.executionCtx
  } catch {}
})
'''
    assert detect_catch(src) == []


def test_test_directory_skipped():
    src = 'export async function load() { return fetch("/x") }\n'
    assert detect_fetch(src, filename="test/hooks.ts") == []
    assert detect_json('await request.json()\n', filename="ky/test/main.ts") == []


def test_catch_nested_helper_inside_handler_not_flagged():
    src = '''app.get("/x", async (req, res) => {
  function decode(raw: string) {
    try { return JSON.parse(raw) } catch {}
  }
  res.json(decode("[]"))
})
'''
    assert detect_catch(src) == []


# ---------- typescript.reliability.no-unguarded-json-parse-on-external-input ----------

BAD_JSON = [
    '''export async function ingest(req: Request) {
  const raw = await req.text()
  return JSON.parse(raw)
}
''',
    '''export async function readBody(request: Request) {
  return await request.json()
}
''',
    '''export async function hydrate(response: Response) {
  return await response.json()
}
''',
]

NEAR_MISS_JSON = [
    '''export async function ingest(req: Request) {
  const raw = await req.text()
  try { return JSON.parse(raw) } catch { throw new Error("bad json") }
}
''',
    'const fallback = JSON.parse(\'{"plan":"free"}\')\n',
    'export function clone(x: unknown) { return JSON.parse(JSON.stringify(x)) }\n',
    '''export function parseBody(raw: string, schema: { parse: (v: unknown) => unknown }) {
  return schema.parse(JSON.parse(raw))
}
''',
    '''export async function readBody(request: Request) {
  try { return await request.json() } catch { return null }
}
''',
    'export function send(res: { json: (v: unknown) => void }) { res.json({ ok: true }) }\n',
    '''export function parseTokens(data: string) {
  return JSON.parse(data)
}
''',
]


@pytest.mark.parametrize("src", BAD_JSON, ids=["parse-req-text", "request.json", "response.json"])
def test_json_bad_is_flagged(src):
    assert len(detect_json(src)) >= 1


@pytest.mark.parametrize(
    "src",
    NEAR_MISS_JSON,
    ids=["try", "literal", "stringify", "schema", "json-in-try", "res.json-send", "internal"],
)
def test_json_good_and_near_misses_pass(src):
    assert detect_json(src) == []


def test_hono_outbound_c_res_json_not_flagged():
    src = '''export async function pretty(c) {
  const obj = await c.res.json()
  return obj
}
'''
    assert detect_json(src) == []


def test_hono_inbound_c_req_json_is_flagged():
    src = '''export async function read(c) {
  return await c.req.json()
}
'''
    assert len(detect_json(src)) >= 1


def test_json_inside_catch_is_not_a_guard():
    src = '''export async function ingest(req: Request) {
  try { await hop() } catch {
    return JSON.parse(await req.text())
  }
}
'''
    assert len(detect_json(src)) >= 1


# ---------- typescript.correctness.no-or-default-for-nonzero-number ----------

BAD_OR = [
    "export function timeout(ms?: number) {\n  return ms || 30000\n}\n",
    "export function port(p?: number) {\n  return p || 24678\n}\n",
    "export function precision(n?: number) {\n  return value.toFixed(n || 1)\n}\n",
    "export function parsedDelay(raw: string) {\n  return Number(raw) || 3000\n}\n",
]

NEAR_MISS_OR = [
    "export function timeout(ms?: number) {\n  return ms ?? 30000\n}\n",
    "export function count(n?: number) {\n  return n || 0\n}\n",
    "export function label(s?: string) {\n  return s || 'untitled'\n}\n",
    "export function timeout(ms?: number, fallback = 30_000) {\n  return ms ?? fallback\n}\n",
    "export function delay(url: URL) {\n  return url.searchParams.get('delay') || 3000\n}\n",
]


@pytest.mark.parametrize("src", BAD_OR, ids=["timeout", "port", "precision", "number-ctor"])
def test_or_bad_is_flagged(src):
    assert len(detect_or(src)) >= 1


@pytest.mark.parametrize(
    "src",
    NEAR_MISS_OR,
    ids=["nullish", "or-zero", "string-default", "ident-fallback", "query-param-get"],
)
def test_or_good_and_near_misses_pass(src):
    assert detect_or(src) == []


def test_or_test_file_skipped():
    src = BAD_OR[0]
    assert detect_or(src, filename="timeout.test.ts") == []
    assert len(detect_or(src, filename="timeout.ts")) >= 1


# ---------- typescript.performance.no-eager-heavy-dependency-import ----------

BAD_HEAVY = [
    "import _ from 'lodash'\nexport const x = _.uniq([1])\n",
    "import union from 'lodash/union'\nexport const x = union([1], [2])\n",
    "import moment from 'moment'\nexport const x = moment()\n",
]

NEAR_MISS_HEAVY = [
    "export async function load() {\n  const _ = await import('lodash')\n  return _.uniq([1])\n}\n",
    "import type { Moment } from 'moment'\nexport type T = Moment\n",
    "import { something } from './local'\nexport const x = something\n",
]


@pytest.mark.parametrize("src", BAD_HEAVY, ids=["lodash", "lodash-sub", "moment"])
def test_heavy_bad_is_flagged(src):
    assert len(detect_heavy(src)) >= 1


@pytest.mark.parametrize("src", NEAR_MISS_HEAVY, ids=["dynamic", "type-only", "relative"])
def test_heavy_good_and_near_misses_pass(src):
    assert detect_heavy(src) == []


# ---------- typescript.security.no-unvalidated-external-href ----------

_TSX = "Link.tsx"

BAD_HREF = [
    '''export function RedirectLink(props: { searchParams: URLSearchParams }) {
  return <a href={props.searchParams.get("next")}>continue</a>
}
''',
    '''export function ProfileLink(userUrl: string) {
  return <a href={userUrl}>profile</a>
}
''',
    '''export function PayloadLink(payload: string) {
  return <a href={`javascript:${payload}`}>run</a>
}
''',
]

NEAR_MISS_HREF = [
    '''export function SettingsLink() {
  return <a href="/ok">settings</a>
}
''',
    '''export function CdnAsset(id: string) {
  return <a href={`https://example.com/${id}`}>asset</a>
}
''',
    '''export function RouteLink() {
  return <a href={Routes.dashboard}>home</a>
}
''',
    '''export function SafeExternal(url: string) {
  if (!url.startsWith("https")) return null
  return <a href={url}>site</a>
}
''',
    '''export function HashLink() {
  return <a href="#section">section</a>
}
''',
    '''export function Prefetch({ href }: { href: string }) {
  return <link rel="prefetch" href={href} />
}
''',
    '''export function Stylesheet({ href }: { href: string }) {
  return <link rel="stylesheet" href={href} />
}
''',
]


@pytest.mark.parametrize("src", BAD_HREF, ids=["searchParams", "user-ident", "javascript-template"])
def test_href_bad_is_flagged(src):
    assert len(detect_href(src, filename=_TSX)) >= 1


@pytest.mark.parametrize(
    "src",
    NEAR_MISS_HREF,
    ids=["literal-path", "https-template", "pascal-routes", "startsWith-allowlist", "hash", "link-prefetch", "link-stylesheet"],
)
def test_href_good_and_near_misses_pass(src):
    assert detect_href(src, filename=_TSX) == []


def test_href_create_element_identifier_flagged():
    src = '''import { createElement } from "react"
export function Go(next: string) {
  return createElement("a", { href: next }, "go")
}
'''
    assert len(detect_href(src, filename="link.ts")) >= 1


def test_href_regex_allowlist_passes():
    src = '''export function Safe(next: string) {
  if (!/^https?:/.test(next)) return null
  return <a href={next}>go</a>
}
'''
    assert detect_href(src, filename=_TSX) == []


def test_href_test_file_skipped():
    src = BAD_HREF[0]
    assert detect_href(src, filename="Link.test.tsx") == []
    assert len(detect_href(src, filename=_TSX)) >= 1


# ---------- typescript.ui.no-orphaned-effect-timeouts ----------

BAD_TIMEOUT = [
    '''import { useEffect } from "react"
export function Tick() {
  useEffect(() => {
    setTimeout(() => { console.log("tick") }, 1000)
  }, [])
  return null
}
''',
    '''import { useLayoutEffect } from "react"
export function Pulse() {
  useLayoutEffect(() => {
    setInterval(() => { console.log("pulse") }, 500)
  }, [])
  return null
}
''',
    '''import { useEffect } from "react"
export function Later() {
  useEffect(() => {
    const id = window.setTimeout(() => {}, 200)
    return () => { console.log("done", id) }
  }, [])
  return null
}
''',
]

NEAR_MISS_TIMEOUT = [
    '''import { useEffect } from "react"
export function Tick() {
  useEffect(() => {
    const id = setTimeout(() => { console.log("tick") }, 1000)
    return () => clearTimeout(id)
  }, [])
  return null
}
''',
    '''export function Button() {
  return <button onClick={() => setTimeout(() => {}, 0)}>go</button>
}
''',
    '''import { useEffect } from "react"
export function Tick() {
  useEffect(() => {
    const ac = new AbortController()
    setTimeout(() => { console.log("tick") }, 1000)
    return () => ac.abort()
  }, [])
  return null
}
''',
    '''import { useEffect } from "react"
export function Hover() {
  useEffect(() => {
    const onMove = () => { setTimeout(() => {}, 50) }
    window.addEventListener("mousemove", onMove)
    return () => window.removeEventListener("mousemove", onMove)
  }, [])
  return null
}
''',
]


@pytest.mark.parametrize("src", BAD_TIMEOUT, ids=["setTimeout", "useLayoutEffect-interval", "return-no-clear"])
def test_timeout_bad_is_flagged(src):
    assert len(detect_timeout(src, filename="Tick.tsx")) >= 1


@pytest.mark.parametrize(
    "src",
    NEAR_MISS_TIMEOUT,
    ids=["clearTimeout", "event-handler", "abort-cleanup", "nested-listener"],
)
def test_timeout_good_and_near_misses_pass(src):
    assert detect_timeout(src, filename="Tick.tsx") == []


def test_timeout_test_file_skipped():
    src = BAD_TIMEOUT[0]
    assert detect_timeout(src, filename="Tick.test.tsx") == []
    assert len(detect_timeout(src, filename="Tick.tsx")) >= 1


# ---------- typescript.react.no-mixed-controlled-uncontrolled ----------

BAD_MIXED = [
    '''export function NameField(props: { name: string }) {
  return <input value={props.name} defaultValue="anonymous" />
}
''',
    '''export function Agree(props: { on: boolean }) {
  return <input type="checkbox" checked={props.on} defaultChecked />
}
''',
    '''import { createElement } from "react"
export function NameField(name: string) {
  return createElement("input", { value: name, defaultValue: "" })
}
''',
]

NEAR_MISS_MIXED = [
    '''export function NameField(props: { name: string }) {
  return <input value={props.name} onChange={() => {}} />
}
''',
    '''export function NameField() {
  return <input defaultValue="anonymous" />
}
''',
    '''export function NameField(props: Record<string, unknown> & { name: string }) {
  return <input {...props} value={props.name} onChange={() => {}} />
}
''',
]


@pytest.mark.parametrize("src", BAD_MIXED, ids=["value-defaultValue", "checked-defaultChecked", "createElement"])
def test_mixed_bad_is_flagged(src):
    assert len(detect_mixed(src, filename="Field.tsx")) >= 1


@pytest.mark.parametrize(
    "src",
    NEAR_MISS_MIXED,
    ids=["value-only", "defaultValue-only", "spread-unknown"],
)
def test_mixed_good_and_near_misses_pass(src):
    assert detect_mixed(src, filename="Field.tsx") == []


def test_mixed_test_file_skipped():
    src = BAD_MIXED[0]
    assert detect_mixed(src, filename="Field.test.tsx") == []
    assert len(detect_mixed(src, filename="Field.tsx")) >= 1
