#!/usr/bin/env python3
"""Run vendored proposal reference models without modifying checked-in fixtures."""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MODELS = Path(__file__).resolve().parent
VECTORS = ROOT / "tests" / "vectors"


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(script: str, cwd: Path, *args: str) -> None:
    subprocess.run([sys.executable, str(cwd / script), *args], cwd=cwd, check=True)


def compare_json(generated: Path, checked_in: Path) -> None:
    with generated.open(encoding="utf-8") as source:
        actual = json.load(source)
    with checked_in.open(encoding="utf-8") as expected:
        wanted = json.load(expected)
    if actual != wanted:
        raise SystemExit(
            f"reference model output differs from {checked_in.relative_to(ROOT)}"
        )


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="cygnus-reference-models-") as temp:
        work = Path(temp)
        for path in MODELS.glob("*.py"):
            shutil.copy2(path, work / path.name)
        for path in VECTORS.glob("*.json"):
            shutil.copy2(path, work / path.name)
        shutil.copy2(VECTORS / "dmls" / "dmls_tree_math_vectors.json", work)

        # Appendix A/B and C executable oracle, including expected-gap checks.
        run("pid_ref.py", work)
        compare_json(work / "pid_vectors.json", VECTORS / "pid_vectors.json")
        run("pid_pdu.py", work)
        compare_json(work / "pid_pdu_vectors.json", VECTORS / "pid_pdu_vectors.json")

        # Open Problem 2 stays an explicitly separate experimental test suite.
        run("pid_cutover.py", work)

        # DMLS/device_root bridge tests are also experimental, not 00FC core
        # conformance. The script regenerates its derived JSON and trace.
        run(
            "test_dmls.py",
            work,
            "--emit-jsonl",
            str(work / "dmls-fork-resolution.jsonl"),
        )
        compare_json(work / "dmls_vectors.json", VECTORS / "dmls" / "dmls_vectors.json")
        actual_trace = [
            json.loads(line)
            for line in (work / "dmls-fork-resolution.jsonl").read_text().splitlines()
        ]
        expected_trace = [
            json.loads(line)
            for line in (VECTORS / "dmls" / "dmls-fork-resolution.jsonl")
            .read_text()
            .splitlines()
        ]
        if actual_trace != expected_trace:
            raise SystemExit(
                "DMLS fork-resolution trace differs from the vendored fixture"
            )

        # Protect both model code and fixtures from silent upstream drift.
        manifest = json.loads((VECTORS / "provenance.json").read_text(encoding="utf-8"))
        for relative, expected in manifest.items():
            path = ROOT / relative
            actual = sha256(path)
            if actual != expected:
                raise SystemExit(
                    f"SHA-256 mismatch for {relative}: {actual} != {expected}"
                )

    print("MSC00FC and DMLS reference-model checks passed")


if __name__ == "__main__":
    main()
