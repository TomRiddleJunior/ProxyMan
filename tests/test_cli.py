"""End-to-end CLI tests: full pipeline rehearsal with --dry-run (no network)."""
import json
import os
import subprocess
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MAIN = os.path.join(REPO, "main.py")
PY = sys.executable

ADDRS = [f"45.1.{i // 250}.{i % 250}:{8000 + (i % 100)}" for i in range(20)]


def _seed_public_list(tmp_path):
    public = tmp_path / "public_list"
    public.mkdir()
    (public / "proxies.json").write_text(json.dumps([{"address": a} for a in ADDRS]))
    return public


def _run_check(tmp_path, out_dir):
    return subprocess.run(
        [PY, MAIN, "--mode", "check", "--dry-run", "--output-dir", str(out_dir)],
        cwd=str(tmp_path),
        capture_output=True,
        text=True,
        timeout=180,
    )


def test_dry_run_end_to_end_check_mode(tmp_path):
    _seed_public_list(tmp_path)
    out = tmp_path / "out"

    result = _run_check(tmp_path, out)
    assert result.returncode == 0, result.stderr[-2000:]

    data = json.loads((out / "proxies.json").read_text())
    assert 0 < len(data) < len(ADDRS), f"expected partial liveness, got {len(data)}"

    state = json.loads((tmp_path / "state" / "pool_state.json").read_text())
    assert len(state["entries"]) == len(ADDRS)  # every candidate tracked

    # second run reuses persisted state
    _run_check(tmp_path, out)
    state2 = json.loads((tmp_path / "state" / "pool_state.json").read_text())
    assert set(state2["entries"]) == set(state["entries"])


def test_dry_run_skips_known_dead_after_three_runs(tmp_path):
    _seed_public_list(tmp_path)
    out = tmp_path / "out"

    # first three runs: dead hosts accumulate 3 consecutive failures
    for _ in range(3):
        r = _run_check(tmp_path, out)
        assert r.returncode == 0, r.stderr[-2000:]

    # fourth run: known-dead hosts must be skipped by the stability filter
    r = _run_check(tmp_path, out)
    combined = r.stdout + r.stderr
    assert "Skipped" in combined, combined[-2000:]

    state = json.loads((tmp_path / "state" / "pool_state.json").read_text())
    dead = sum(1 for e in state["entries"].values() if e["consecutive_failures"] >= 3)
    assert dead > 0


def test_missing_public_list_exits_gracefully(tmp_path):
    r = subprocess.run(
        [PY, MAIN, "--mode", "check"],
        cwd=str(tmp_path),
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert r.returncode == 0
    assert "No active pool found" in r.stdout + r.stderr

def test_log_file_written(tmp_path):
    log_file = tmp_path / "run.log"
    r = subprocess.run(
        [PY, MAIN, "--mode", "check", "--log-file", str(log_file)],
        cwd=str(tmp_path),
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert r.returncode == 0
    assert log_file.exists()
    assert "No active pool found" in log_file.read_text()
