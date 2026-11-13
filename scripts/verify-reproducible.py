#!/usr/bin/env python3
"""Verify that each committed host capture reproduces from its committed collector.

For every lab with a host collector, this re-runs the collector and exporter and
compares the fresh result against the committed evidence. Only the stable outcome
fields are compared, because some fields are inherently per-run: timestamps, raw
stdout/stderr, and ASLR-randomized addresses (Lab 06's leaked bases). What must
match is what the experiment measured — each observation's mode, return code,
signal and outcome flags, and the finding — so a collector can never drift from
the evidence it is supposed to produce while still passing the JSON-only checks
in tests/test_results_consistency.py.

Only `host` captures are reproducible locally; `modern` (VM) captures are left to
their own replication. Requires the lab build tools (gcc, gdb, nm, ...). Run from
the repository root:

    python3 scripts/verify-reproducible.py
"""
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# lab -> (collector, exporter). The evidence is each lab's committed export JSON.
LABS = {
    "labs/04-stack-canary": ("capture-stack-canary.py", "export-stack-canary.py"),
    "labs/05-return-address-overwrite": ("capture-return-overwrite.py", "export-return-overwrite.py"),
    "labs/06-pie-leak-bypass": ("capture-pie-leak.py", "export-pie-leak.py"),
    "labs/07-execution-permission": ("capture-wx.py", "export-wx.py"),
    "labs/08-code-reuse-chain": ("capture-code-reuse.py", "export-code-reuse.py"),
    "labs/09-relro-got": ("capture-relro.py", "export-relro.py"),
}

# Per-run fields that must not be compared. Everything else in an observation is
# a measured outcome and must match.
VARIABLE_FIELDS = {
    "stdout", "stderr", "leak",
    "leaked_reference", "attacked_base", "stale_base",
}


def stable_observation(observation):
    return {k: v for k, v in observation.items() if k not in VARIABLE_FIELDS}


def committed_host_captures(evidence_dir):
    """Every committed host capture across the lab's evidence files. A lab may
    have several (Lab 04 records one per optimization level)."""
    host = []
    for path in sorted(evidence_dir.glob("*.json")):
        for capture in json.loads(path.read_text()).get("captures", []):
            if capture.get("environment", {}).get("label") == "host":
                host.append(capture)
    return host


def reproduce_capture(collector_path, exporter_path, committed):
    """Re-run the collector with the capture's recorded CFLAGS and compare the
    stable outcome fields. Returns None on success or an error string."""
    env = dict(os.environ)
    cflags = committed.get("environment", {}).get("CFLAGS")
    if cflags is not None:
        env["CFLAGS"] = cflags
    with tempfile.TemporaryDirectory(prefix="reproduce-") as directory:
        capture_dir = Path(directory) / "capture"
        export_json = Path(directory) / "fresh.json"
        run = subprocess.run([sys.executable, str(collector_path), "host", str(capture_dir)],
                             capture_output=True, text=True, timeout=180, env=env)
        if run.returncode != 0:
            return "collector failed: %s" % (run.stderr.strip() or run.stdout.strip())
        run = subprocess.run([sys.executable, str(exporter_path), str(capture_dir),
                              "--output", str(export_json)], capture_output=True, text=True, timeout=60)
        if run.returncode != 0:
            return "exporter failed: %s" % run.stderr.strip()
        fresh = json.loads(export_json.read_text())["captures"][0]

    fresh_obs = [stable_observation(o) for o in fresh["observations"]]
    committed_obs = [stable_observation(o) for o in committed["observations"]]
    if fresh_obs != committed_obs:
        return "observation outcomes differ from the committed evidence"
    if fresh.get("finding") != committed.get("finding"):
        return "finding differs from the committed evidence"
    return None


def reproduce(lab, collector, exporter):
    collector_path = ROOT / "scripts" / collector
    exporter_path = ROOT / "scripts" / exporter
    for path in (collector_path, exporter_path):
        if not path.exists():
            return ["%s: %s is missing" % (lab, path.name)]
    captures = committed_host_captures(ROOT / lab / "evidence")
    if not captures:
        return ["%s: no committed host capture" % lab]
    errors = []
    for committed in captures:
        error = reproduce_capture(collector_path, exporter_path, committed)
        if error:
            errors.append("%s (%s): %s" % (lab, committed.get("name", "?"), error))
    return errors


def main():
    failures = []
    for lab, (collector, exporter) in LABS.items():
        print("reproducing %s ..." % lab, flush=True)
        errors = reproduce(lab, collector, exporter)
        if errors:
            failures.extend(errors)
            for error in errors:
                print("  FAIL: " + error, file=sys.stderr)
        else:
            print("  ok", flush=True)
    if failures:
        print("\n%d lab(s) did not reproduce:" % len(failures), file=sys.stderr)
        for error in failures:
            print("  - " + error, file=sys.stderr)
        return 1
    print("\nAll host captures reproduced from their committed collectors.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
