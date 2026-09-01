"""G0.5: learn Candidate.ratio is adoption of the good convention."""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

LEARN = Path(__file__).resolve().parents[1] / "scripts" / "learn"
CLI = Path(__file__).resolve().parents[1] / "scripts" / "learn.py"
sys.path.insert(0, str(LEARN))

import java_analyzer as java  # noqa: E402
import python_analyzer as py  # noqa: E402
import ts_analyzer as ts  # noqa: E402
from stats import Candidate, should_emit  # noqa: E402


CLEAN_ASYNC = '''\
from fastapi import FastAPI
app = FastAPI()

@app.get("/a")
async def a():
    return {"ok": True}

@app.get("/b")
async def b():
    return 1

@router.post("/c")
async def c():
    await db.fetch()
'''

BLOCKING_ASYNC = '''\
import time
import requests
from fastapi import FastAPI
app = FastAPI()

@app.get("/a")
async def a():
    time.sleep(1)
    return {"ok": True}

@app.get("/b")
async def b():
    requests.get("http://example.invalid")
    return 1

@app.get("/c")
async def c():
    time.sleep(2)
    return 2
'''

EMPTY_CATCHES = '''\
export function a(): void {
  try { doA(); } catch (e) {}
}
export function b(): void {
  try { doB(); } catch (e) {}
}
export function c(): void {
  try { doC(); } catch {
  }
}
'''

HANDLED_CATCHES = '''\
export function a(): void {
  try { doA(); } catch (e) { console.error(e); }
}
export function b(): void {
  try { doB(); } catch (err) { throw err; }
}
export function c(): void {
  try { doC(); } catch (e) { log(e); rethrow(e); }
}
'''

TXN_CLEAN = '''\
package example;
import org.springframework.transaction.annotation.Transactional;
public class OrderService {
    @Transactional
    public void saveA() {
        repo.save(a);
    }
    @Transactional
    public void saveB() {
        repo.save(b);
    }
    @Transactional
    public void saveC() {
        repo.save(c);
    }
}
'''

TXN_HTTP = '''\
package example;
import org.springframework.transaction.annotation.Transactional;
public class BillingService {
    @Transactional
    public void billA() {
        restTemplate.getForObject(url, String.class);
    }
    @Transactional
    public void billB() {
        restTemplate.getForObject(url, String.class);
    }
    @Transactional
    public void billC() {
        restTemplate.getForObject(url, String.class);
    }
}
'''


def _write(root: Path, rel: str, text: str) -> Path:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    return path


def test_empty_catch_all_empty_is_slop_magnet_not_established(tmp_path):
    src = _write(tmp_path, "handlers.ts", EMPTY_CATCHES)
    c = ts._empty_catches([src])
    assert c.total == 3
    assert c.matched == 0
    assert c.ratio == pytest.approx(0.0)
    assert should_emit(c)
    # Old bug: matched == total always -> ratio 1.0 "established"
    assert c.ratio != pytest.approx(1.0)

    emitted = {x.rule_id: x for x in ts.analyze(tmp_path)}
    assert "typescript.errors.no-empty-catch" in emitted
    assert emitted["typescript.errors.no-empty-catch"].ratio == pytest.approx(0.0)


def test_empty_catch_nonempty_is_high_adoption(tmp_path):
    src = _write(tmp_path, "handlers.ts", HANDLED_CATCHES)
    c = ts._empty_catches([src])
    assert c.total == 3
    assert c.matched == 3
    assert c.ratio == pytest.approx(1.0)


def test_async_routes_all_clean_high_adoption(tmp_path):
    src = _write(tmp_path, "pkg/api.py", CLEAN_ASYNC)
    c = py._async_route_purity([src])
    assert c.total == 3
    assert c.matched == 3
    assert c.ratio == pytest.approx(1.0)
    emitted = {x.rule_id: x for x in py.analyze(tmp_path)}
    assert emitted["python.api.async-routes-blocking-free"].ratio == pytest.approx(1.0)


def test_async_routes_blocking_is_low_adoption(tmp_path):
    src = _write(tmp_path, "pkg/api.py", BLOCKING_ASYNC)
    c = py._async_route_purity([src])
    assert c.total == 3
    assert c.matched == 0
    assert c.ratio == pytest.approx(0.0)


def test_transactional_without_http_high_adoption(tmp_path):
    src = _write(tmp_path, "src/OrderService.java", TXN_CLEAN)
    c = java._transactional_scope([src])
    assert c.total == 3
    assert c.matched == 3
    assert c.ratio == pytest.approx(1.0)
    emitted = {x.rule_id: x for x in java.analyze(tmp_path)}
    assert emitted["java.transactions.no-external-io"].ratio == pytest.approx(1.0)


def test_transactional_with_http_low_adoption(tmp_path):
    src = _write(tmp_path, "src/BillingService.java", TXN_HTTP)
    c = java._transactional_scope([src])
    assert c.total == 3
    assert c.matched == 0
    assert c.ratio == pytest.approx(0.0)
    emitted = {x.rule_id: x for x in java.analyze(tmp_path)}
    assert emitted["java.transactions.no-external-io"].ratio == pytest.approx(0.0)


def test_floating_promises_not_emitted(tmp_path):
    for name in ("a.ts", "b.ts", "c.ts"):
        _write(tmp_path, name, "export function f() { foo(); bar(); baz(); }\n")
    ids = [c.rule_id for c in ts.analyze(tmp_path)]
    assert "typescript.promises.no-floating" not in ids


def test_evidence_paths_relative_to_repo(tmp_path):
    _write(tmp_path, "pkg/api.py", BLOCKING_ASYNC)
    py._REPO_ROOT = tmp_path
    try:
        c = py._async_route_purity([tmp_path / "pkg" / "api.py"])
    finally:
        py._REPO_ROOT = None
    assert c.evidence
    for e in c.evidence:
        assert not e.file.startswith("/"), e.file
        assert e.file == "pkg/api.py"


def test_should_emit_skips_violation_polarity():
    c = Candidate(
        rule_id="x", stack="ts", invariant="x",
        matched=3, total=3, polarity="violation",
    )
    assert c.ratio == pytest.approx(1.0)
    assert not should_emit(c)


def test_print_induce_prompt_writes_files_without_llm(tmp_path):
    repo = tmp_path / "repo"
    _write(repo, "pkg/api.py", "x = 1\n")
    out = tmp_path / "out"
    proc = subprocess.run(
        [sys.executable, str(CLI), "--repo", str(repo), "--lang", "python",
         "--print-induce-prompt", "--out", str(out)],
        capture_output=True, text=True, check=False,
    )
    assert proc.returncode == 0, proc.stderr
    prompt = (out / "induce-prompt.md").read_text()
    sampled = (out / "sampled-files.txt").read_text()
    assert "This CLI does not call a model" in prompt
    assert "pkg/api.py" in sampled
    assert "/home/amaresh" not in sampled
    assert "openai" not in prompt.lower()
    assert "anthropic" not in prompt.lower()
