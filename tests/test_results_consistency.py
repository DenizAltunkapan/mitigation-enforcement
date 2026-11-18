"""Guards committed RESULTS.md prose and evidence provenance against drift.

Several kinds of silent drift are checked, reading only committed JSON, Markdown
and source files — no build tools:

1. RESULTS.md toolchain versions (Labs 04-10) against each capture's recorded
   `versions` strings, one field per tool, so the prose cannot diverge from what
   was measured.
2. The trial count, operating system and saved-return offset stated in each
   RESULTS.md against the recorded observations, os-release and payload, so those
   measured numbers in the prose cannot go stale when the evidence is regenerated.
3. Each lab's recorded `collector_sha256` and committed `artifact_sha256` entries
   against the collector script and source/Makefile on disk, so evidence cannot
   claim to come from a script or source that has since changed.

The version checks are strict on purpose:

- Each table row is tied to one evidence field (compiler, debugger, ...), so a
  binutils number cannot be satisfied by the compiler's version and vice versa.
- Every version-like token in the cell, including a distribution package suffix
  such as ``15.2.0-16ubuntu1``, must appear verbatim in that field, so a wrong
  suffix is rejected, not ignored.
- A cell that states no version at all fails: a tool column must carry a version.
- Each environment column is checked against its own captures, so with several
  captures per environment none can mask another.

Expected values are read from the evidence, not hard-coded, so regenerating a
capture cannot leave a stale assertion that still passes. No build tools are
required; this reads only committed JSON, Markdown and source files.
"""
import hashlib
import json
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]
# A version token is x.y or x.y.z, optionally with a distribution package suffix
# (-16ubuntu1, ~deb13u3, +really...). The suffix is part of the claim and is
# matched verbatim against the evidence field.
TOKEN = re.compile(r"\d+\.\d+(?:\.\d+)?(?:[-~+][0-9A-Za-z.~+]+)?")
# Which evidence `versions` field each RESULTS table row is a claim about.
FIELD_FOR_ROW = {
    "Compiler": "compiler",
    "Debugger": "gdb-version",
    "Assembler / Linker": "binutils",
    "C library": "libc",
}
# Labs whose portable evidence records a collector hash, mapped to the committed
# collector that produced it. A new such lab must be added here, enforced by
# CollectorProvenanceTests.test_every_lab_with_recorded_evidence_is_mapped.
COLLECTOR_FOR_LAB = {
    "labs/04-stack-canary": "scripts/capture-stack-canary.py",
    "labs/05-return-address-overwrite": "scripts/capture-return-overwrite.py",
    "labs/06-pie-leak-bypass": "scripts/capture-pie-leak.py",
    "labs/07-execution-permission": "scripts/capture-wx.py",
    "labs/08-code-reuse-chain": "scripts/capture-code-reuse.py",
    "labs/09-relro-got": "scripts/capture-relro.py",
    "labs/10-format-string": "scripts/capture-format-string.py",
}


def captures_by_label(evidence_path):
    data = json.loads((ROOT / evidence_path).read_text())
    by_label = {}
    for capture in data["captures"]:
        by_label.setdefault(capture["environment"]["label"], []).append(capture)
    return by_label


def table_row(markdown, starts_with):
    for line in markdown.splitlines():
        stripped = line.lstrip()
        if stripped.startswith("| " + starts_with):
            return [cell.strip() for cell in stripped.strip().strip("|").split("|")]
    return None


class ResultsConsistencyTests(unittest.TestCase):
    def _assert_cell(self, lab, row_name, cell, captures):
        """Every version token in `cell` must appear in this row's evidence field
        of at least one of `captures` (the environment's captures)."""
        field = FIELD_FOR_ROW[row_name]
        tokens = TOKEN.findall(cell)
        self.assertTrue(
            tokens,
            f"{lab}: RESULTS row '{row_name}' cell {cell!r} states no version",
        )
        field_values = []
        for capture in captures:
            self.assertIn(field, capture["versions"],
                          f"{lab}: capture has no '{field}' version field")
            field_values.append(capture["versions"][field])
        for token in tokens:
            self.assertTrue(
                any(token in value for value in field_values),
                f"{lab}: RESULTS row '{row_name}' states {token!r}, absent from "
                f"the recorded '{field}' version(s): {field_values}",
            )

    def _check(self, lab, evidence_path, results_path, rows):
        """`rows` maps a table row prefix to {cell_index: evidence_label}."""
        by_label = captures_by_label(evidence_path)
        markdown = (ROOT / results_path).read_text()
        for prefix, columns in rows.items():
            cells = table_row(markdown, prefix)
            self.assertIsNotNone(cells, f"{lab}: table row '{prefix}' not found")
            # The row name used for the field mapping is the prefix itself for
            # property-per-row tables; Lab 04 passes it explicitly via `rows`.
            for index, (label, row_name) in columns.items():
                self.assertLess(index, len(cells), f"{lab}: '{prefix}' has no cell {index}")
                self.assertIn(label, by_label, f"{lab}: evidence has no '{label}' capture")
                self._assert_cell(lab, row_name, cells[index], by_label[label])

    def test_lab04_results_match_evidence(self):
        # Lab 04's environment row carries the environment in the first cell,
        # then Compiler (cell 1) and C library (cell 2).
        self._check(
            "Lab 04",
            "labs/04-stack-canary/evidence/2026-10-25.json",
            "labs/04-stack-canary/RESULTS.md",
            {
                "Ubuntu": {1: ("host", "Compiler"), 2: ("host", "C library")},
                "Debian": {1: ("modern", "Compiler"), 2: ("modern", "C library")},
            },
        )

    def test_lab05_results_match_evidence(self):
        # Property-per-row: host is cell 1, modern is cell 2.
        self._check(
            "Lab 05",
            "labs/05-return-address-overwrite/evidence/2026-11-03.json",
            "labs/05-return-address-overwrite/RESULTS.md",
            {name: {1: ("host", name), 2: ("modern", name)}
             for name in ("Compiler", "Assembler / Linker", "Debugger", "C library")},
        )

    def test_lab06_results_match_evidence(self):
        # Two columns: host is cell 1, modern VM is cell 2.
        self._check(
            "Lab 06",
            "labs/06-pie-leak-bypass/evidence/2026-11-18.json",
            "labs/06-pie-leak-bypass/RESULTS.md",
            {name: {1: ("host", name), 2: ("modern", name)}
             for name in ("Compiler", "Assembler / Linker", "C library", "Debugger")},
        )

    def test_lab07_results_match_evidence(self):
        # Two columns: host is cell 1, modern VM is cell 2; no debugger column.
        self._check(
            "Lab 07",
            "labs/07-execution-permission/evidence/2026-11-18.json",
            "labs/07-execution-permission/RESULTS.md",
            {name: {1: ("host", name), 2: ("modern", name)}
             for name in ("Compiler", "Assembler / Linker", "C library")},
        )

    def test_lab08_results_match_evidence(self):
        # Two columns: host is cell 1, modern VM is cell 2.
        self._check(
            "Lab 08",
            "labs/08-code-reuse-chain/evidence/2026-11-18.json",
            "labs/08-code-reuse-chain/RESULTS.md",
            {name: {1: ("host", name), 2: ("modern", name)}
             for name in ("Compiler", "Assembler / Linker", "C library", "Debugger")},
        )

    def test_lab09_results_match_evidence(self):
        # Two columns: host is cell 1, modern VM is cell 2; no debugger column.
        self._check(
            "Lab 09",
            "labs/09-relro-got/evidence/2026-11-18.json",
            "labs/09-relro-got/RESULTS.md",
            {name: {1: ("host", name), 2: ("modern", name)}
             for name in ("Compiler", "Assembler / Linker", "C library")},
        )

    def test_lab10_results_match_evidence(self):
        # Two columns: host is cell 1, modern VM is cell 2; no debugger column.
        self._check(
            "Lab 10",
            "labs/10-format-string/evidence/2026-11-18.json",
            "labs/10-format-string/RESULTS.md",
            {name: {1: ("host", name), 2: ("modern", name)}
             for name in ("Compiler", "Assembler / Linker", "C library")},
        )

    def test_results_trial_counts_match_the_recorded_observations(self):
        # Each RESULTS.md states how many trials were run. That number is the
        # total observations recorded in the evidence, so the prose must name it
        # next to "trials" or "observations". This catches a count that drifts
        # when the evidence is regenerated with a different number of runs.
        for lab in COLLECTOR_FOR_LAB:
            evidence = sorted((ROOT / lab / "evidence").glob("*.json"))
            self.assertTrue(evidence, lab + " has no committed evidence")
            total = sum(
                len(capture["observations"])
                for path in evidence
                for capture in json.loads(path.read_text())["captures"]
            )
            results = (ROOT / lab / "RESULTS.md").read_text()
            pattern = re.compile(r"\b%d\b[^.\n]*?\b(?:trials|observations)\b" % total)
            self.assertRegex(
                results, pattern,
                "%s/RESULTS.md does not state the recorded total of %d trials; "
                "update the prose or regenerate the evidence" % (lab, total),
            )

    def test_results_name_the_recorded_operating_system(self):
        # Where a capture records os-release, the RESULTS environment table must
        # name that distribution and version, so a host/VM change cannot leave the
        # prose claiming the old OS. Labs whose export omits os-release are skipped.
        distribution = re.compile(r"Ubuntu \d+\.\d+|Debian GNU/Linux \d+")
        checked = 0
        for lab in COLLECTOR_FOR_LAB:
            results = (ROOT / lab / "RESULTS.md").read_text()
            for path in sorted((ROOT / lab / "evidence").glob("*.json")):
                for capture in json.loads(path.read_text())["captures"]:
                    os_release = capture.get("os_release")
                    if not os_release:
                        continue
                    pretty = next(
                        (line.split("=", 1)[1].strip().strip('"')
                         for line in os_release.splitlines()
                         if line.startswith("PRETTY_NAME")),
                        None,
                    )
                    self.assertIsNotNone(pretty, path.name + " has no PRETTY_NAME")
                    match = distribution.match(pretty)
                    self.assertIsNotNone(match, "unrecognized os-release: " + pretty)
                    self.assertIn(
                        match.group(0), results,
                        "%s/RESULTS.md does not name the recorded OS %r"
                        % (lab, match.group(0)),
                    )
                    checked += 1
        self.assertGreater(checked, 0, "no os-release was checked")

    def test_results_state_the_recorded_saved_return_offset(self):
        # The saved-return offset is the central measured constant of the
        # overwrite labs. Where a capture records it, RESULTS.md must state that
        # number next to the word "offset", so the prose cannot keep an old value
        # after the layout (and the evidence) changes. Labs without the field,
        # such as Lab 07, are skipped.
        checked = 0
        for lab in COLLECTOR_FOR_LAB:
            results = (ROOT / lab / "RESULTS.md").read_text()
            for path in sorted((ROOT / lab / "evidence").glob("*.json")):
                for capture in json.loads(path.read_text())["captures"]:
                    payload = capture.get("payload", {})
                    offset = payload.get("saved_return_offset") or payload.get("padding_bytes")
                    if offset is None:
                        continue
                    pattern = re.compile(
                        r"offset[^.\n]*?\b%d\b|\b%d\b[^.\n]*?offset" % (offset, offset)
                    )
                    self.assertRegex(
                        results, pattern,
                        "%s/RESULTS.md does not state the recorded saved-return "
                        "offset of %d; update the prose or regenerate the evidence"
                        % (lab, offset),
                    )
                    checked += 1
        self.assertGreater(checked, 0, "no saved-return offset was checked")


class CellCheckGuaranteesTests(unittest.TestCase):
    """Pins the strictness of the cell check against drift in the check itself,
    using a synthetic capture so it never depends on the real RESULTS files."""

    CAPTURE = {"versions": {
        "compiler": "gcc (Ubuntu 15.2.0-16ubuntu1) 15.2.0",
        "gdb-version": "GNU gdb (Ubuntu 17.1-2ubuntu1) 17.1",
        "binutils": "GNU readelf (GNU Binutils for Ubuntu) 2.46",
        "libc": "glibc 2.43",
    }}

    def check(self, row, cell):
        ResultsConsistencyTests()._assert_cell("synthetic", row, cell, [self.CAPTURE])

    def test_accepts_the_recorded_version_with_suffix(self):
        self.check("Compiler", "GCC 15.2.0 (Ubuntu 15.2.0-16ubuntu1)")

    def test_rejects_a_wrong_package_suffix(self):
        with self.assertRaises(AssertionError):
            self.check("Compiler", "GCC 15.2.0 (Ubuntu 15.2.0-999bogus)")

    def test_rejects_another_tools_number_in_this_field(self):
        # The compiler's version must not satisfy the binutils row.
        with self.assertRaises(AssertionError):
            self.check("Assembler / Linker", "GNU Binutils 15.2.0")

    def test_rejects_a_cell_without_any_version(self):
        with self.assertRaises(AssertionError):
            self.check("Compiler", "unrecorded compiler")

    def test_rejects_a_drifted_number(self):
        with self.assertRaises(AssertionError):
            self.check("C library", "glibc 2.99")


# Each lab's portable evidence records the SHA-256 of the collector that produced
# it and of its committed source files. If either is changed without regenerating
# the evidence, the recorded hash goes stale while every other check still passes.
# These cases tie the recorded hashes back to the committed files on disk.
class CollectorProvenanceTests(unittest.TestCase):
    def test_every_lab_with_recorded_evidence_is_mapped(self):
        # A new lab that records a collector hash must be added here, so the
        # provenance check can never silently skip it.
        for evidence_dir in sorted(ROOT.glob("labs/*/evidence")):
            files = list(evidence_dir.glob("*.json"))
            if not files:
                continue
            records_hash = any(
                "collector_sha256" in capture
                for path in files
                for capture in json.loads(path.read_text()).get("captures", [])
            )
            if records_hash:
                lab = evidence_dir.parent.relative_to(ROOT).as_posix()
                self.assertIn(lab, COLLECTOR_FOR_LAB,
                              lab + " records a collector hash but is not mapped here")

    def test_recorded_collector_hash_matches_the_committed_script(self):
        for lab, script in COLLECTOR_FOR_LAB.items():
            collector = ROOT / script
            self.assertTrue(collector.exists(), script + " is missing")
            on_disk = hashlib.sha256(collector.read_bytes()).hexdigest()
            evidence = sorted((ROOT / lab / "evidence").glob("*.json"))
            self.assertTrue(evidence, lab + " has no committed evidence")
            for path in evidence:
                for capture in json.loads(path.read_text())["captures"]:
                    self.assertEqual(
                        capture["collector_sha256"], on_disk,
                        "%s: recorded collector hash does not match %s; "
                        "regenerate the evidence after changing the collector"
                        % (path.relative_to(ROOT), script),
                    )

    def test_recorded_source_hashes_match_the_committed_lab_files(self):
        # The evidence hashes the lab's committed source and Makefile. Only those
        # are checked: the generated binaries are git-ignored and rebuild to a
        # different hash, so a locally present one must not be compared. Editing a
        # committed source without regenerating the evidence is therefore caught.
        checked = 0
        for lab in COLLECTOR_FOR_LAB:
            for path in sorted((ROOT / lab / "evidence").glob("*.json")):
                for capture in json.loads(path.read_text())["captures"]:
                    for name, digest in capture.get("artifact_sha256", {}).items():
                        if not (name.startswith("src/") or name == "Makefile"):
                            continue  # a git-ignored build product
                        artifact = ROOT / lab / name
                        self.assertTrue(artifact.exists(),
                                        "%s: committed artifact %s is missing"
                                        % (lab, name))
                        self.assertEqual(
                            hashlib.sha256(artifact.read_bytes()).hexdigest(), digest,
                            "%s: recorded hash of %s does not match the committed "
                            "file; regenerate the evidence after changing it"
                            % (path.relative_to(ROOT), name),
                        )
                        checked += 1
        self.assertGreater(checked, 0, "no committed artifacts were checked")


if __name__ == "__main__":
    unittest.main()
