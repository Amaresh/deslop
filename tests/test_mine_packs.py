from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from check import run_check
from pack_lib import PACK_ROOT, load_pack_by_id, mine_rule_ids

CHECK = PACK_ROOT / "scripts" / "check.py"


def _cli(repo: Path, pack: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            str(CHECK),
            "--repo-root",
            str(repo),
            "--pack",
            pack,
            "--format",
            "json",
        ],
        check=False,
        capture_output=True,
        text=True,
    )


def test_python_dirty_fails_and_clean_passes() -> None:
    dirty = _cli(PACK_ROOT / "fixtures" / "python" / "dirty", "python")
    clean = _cli(PACK_ROOT / "fixtures" / "python" / "clean", "python")
    assert dirty.returncode == 1, dirty.stderr + dirty.stdout
    assert clean.returncode == 0, clean.stderr + clean.stdout
    payload = json.loads(dirty.stdout)
    fired = {item["rule_id"] for item in payload["findings"]}
    assert fired == set(mine_rule_ids(load_pack_by_id("python")))


def test_ts_dirty_fails_and_clean_passes() -> None:
    dirty = _cli(PACK_ROOT / "fixtures" / "ts" / "dirty", "ts")
    clean = _cli(PACK_ROOT / "fixtures" / "ts" / "clean", "ts")
    assert dirty.returncode == 1, dirty.stderr + dirty.stdout
    assert clean.returncode == 0, clean.stderr + clean.stdout
    payload = json.loads(dirty.stdout)
    fired = {item["rule_id"] for item in payload["findings"]}
    assert fired == set(mine_rule_ids(load_pack_by_id("ts")))


def test_go_dirty_fails_and_clean_passes() -> None:
    dirty = _cli(PACK_ROOT / "fixtures" / "go" / "dirty", "go")
    clean = _cli(PACK_ROOT / "fixtures" / "go" / "clean", "go")
    assert dirty.returncode == 1, dirty.stderr + dirty.stdout
    assert clean.returncode == 0, clean.stderr + clean.stdout
    payload = json.loads(dirty.stdout)
    fired = {item["rule_id"] for item in payload["findings"]}
    expected = set(mine_rule_ids(load_pack_by_id("go")))
    assert expected <= fired


def test_android_dirty_fails_and_clean_passes() -> None:
    dirty = _cli(PACK_ROOT / "fixtures" / "android" / "dirty", "android")
    clean = _cli(PACK_ROOT / "fixtures" / "android" / "clean", "android")
    assert dirty.returncode == 1, dirty.stderr + dirty.stdout
    assert clean.returncode == 0, clean.stderr + clean.stdout
    payload = json.loads(dirty.stdout)
    fired = {item["rule_id"] for item in payload["findings"]}
    assert fired == set(mine_rule_ids(load_pack_by_id("android")))


def test_java_mine_findall_and_controller_fire() -> None:
    result = run_check(
        repo_root=PACK_ROOT / "fixtures" / "java-mine" / "dirty",
        packs=[load_pack_by_id("java")],
    )
    fired = {finding.rule_id for finding in result.findings}
    assert "java.reliability.no-unbounded-findall-without-pagination" in fired
    assert "java.architecture.no-controller-direct-repository-access" in fired
    clean = run_check(
        repo_root=PACK_ROOT / "fixtures" / "java-mine" / "clean",
        packs=[load_pack_by_id("java")],
    )
    clean_ids = {finding.rule_id for finding in clean.findings}
    assert "java.reliability.no-unbounded-findall-without-pagination" not in clean_ids
    assert "java.architecture.no-controller-direct-repository-access" not in clean_ids


def test_java_after_commit_dispatch_fires_on_dirty_fixture() -> None:
    rid = "java.reliability.no-after-commit-dispatch-from-after-commit-listener"
    dirty = run_check(
        repo_root=PACK_ROOT / "fixtures" / "dirty",
        packs=[load_pack_by_id("java")],
    )
    assert rid in {finding.rule_id for finding in dirty.findings}
    clean = run_check(
        repo_root=PACK_ROOT / "fixtures" / "clean",
        packs=[load_pack_by_id("java")],
    )
    assert rid not in {finding.rule_id for finding in clean.findings}
