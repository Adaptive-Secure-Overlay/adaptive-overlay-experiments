#!/usr/bin/env python3
"""Fail-closed validator for remarks-closure-20260903 outputs."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
from pathlib import Path
from typing import Any


REQUIRED_PASSPORT_MARKERS = (
    "Гипотеза:",
    "Параметры:",
    "Стенд и версии:",
    "Число прогонов:",
    "Критерий успеха:",
    "Сырой артефакт:",
    "Агрегат:",
)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest().upper()


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8-sig", newline="") as stream:
        return list(csv.DictReader(stream))


def require(condition: bool, message: str, checks: list[dict[str, Any]]) -> None:
    checks.append({"check": message, "pass": bool(condition)})


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    args = parser.parse_args()
    root = args.root.resolve()
    checks: list[dict[str, Any]] = []

    required = [
        root / "PLAN.md",
        root / "FINAL-REPORT.md",
        root / "manifest.json",
        root / "01-threshold-calibration" / "PASSPORT.md",
        root / "01-threshold-calibration" / "raw-counts.csv",
        root / "01-threshold-calibration" / "aggregate.csv",
        root / "01-threshold-calibration" / "result.json",
        root / "02-cascade-length" / "PASSPORT.md",
        root / "02-cascade-length" / "raw-trials.csv",
        root / "02-cascade-length" / "aggregate-by-hops.csv",
        root / "02-cascade-length" / "result.json",
        root / "03-trust-registry-negative" / "PASSPORT.md",
        root / "03-trust-registry-negative" / "raw-negative-cases.csv",
        root / "03-trust-registry-negative" / "result.json",
        root / "04-concurrent-starts" / "PASSPORT.md",
        root / "04-concurrent-starts" / "raw-normalized.csv",
        root / "04-concurrent-starts" / "aggregate-by-scenario.csv",
        root / "04-concurrent-starts" / "result.json",
    ]
    for path in required:
        require(path.is_file() and path.stat().st_size > 0, f"required file: {path.relative_to(root)}", checks)

    for subdir in (
        "01-threshold-calibration",
        "02-cascade-length",
        "03-trust-registry-negative",
        "04-concurrent-starts",
    ):
        passport = (root / subdir / "PASSPORT.md").read_text(encoding="utf-8")
        for marker in REQUIRED_PASSPORT_MARKERS:
            require(marker in passport, f"{subdir} passport marker {marker}", checks)

    threshold_raw = read_csv(root / "01-threshold-calibration" / "raw-counts.csv")
    threshold_agg = read_csv(root / "01-threshold-calibration" / "aggregate.csv")
    require(len(threshold_raw) == 16, "threshold raw has 16 boundary rows", checks)
    require(len(threshold_agg) == 8, "threshold aggregate has 8 cases", checks)
    require(all(int(row["trials"]) == 50_000 for row in threshold_raw), "threshold trials are 50000 per boundary", checks)
    require(all(row["error_le_0_01"].lower() == "true" for row in threshold_raw), "threshold Monte Carlo error <= 0.01", checks)
    require(all(row["threshold_crossing_exact"].lower() == "true" for row in threshold_agg), "threshold exact crossing holds", checks)

    cascade_raw = read_csv(root / "02-cascade-length" / "raw-trials.csv")
    cascade_agg = read_csv(root / "02-cascade-length" / "aggregate-by-hops.csv")
    counts = {h: sum(1 for row in cascade_raw if int(row["hops"]) == h) for h in (3, 4, 5)}
    require(len(cascade_raw) == 1200, "cascade raw has 1200 trials", checks)
    require(counts == {3: 400, 4: 400, 5: 400}, "cascade has 400 trials per H", checks)
    require(len(cascade_agg) == 3, "cascade aggregate has H=3/4/5", checks)
    require(all(row["success"].lower() == "true" for row in cascade_raw), "cascade all trials succeeded", checks)
    loss_by_h = {
        h: sum(int(row["ping_transmitted"]) - int(row["ping_received"]) for row in cascade_raw if int(row["hops"]) == h)
        for h in (3, 4, 5)
    }
    require(sum(int(row["ping_transmitted"]) for row in cascade_raw) == 2400, "cascade has 2400 transmitted ping packets", checks)
    require(sum(int(row["ping_received"]) for row in cascade_raw) == 2394, "cascade has 2394 received ping packets", checks)
    require(loss_by_h == {3: 0, 4: 1, 5: 5}, "cascade observed losses are preserved by H", checks)

    trust_raw = read_csv(root / "03-trust-registry-negative" / "raw-negative-cases.csv")
    trust_result = json.loads((root / "03-trust-registry-negative" / "result.json").read_text(encoding="utf-8"))
    require(len(trust_raw) == 4, "trust registry has four negative cases", checks)
    require(all(row["criterion_pass"].lower() == "true" for row in trust_raw[:3]), "three local trust guards reject bad input", checks)
    require(trust_raw[3]["observed"] == "accept", "remote key substitution gap is observed", checks)
    require(trust_result["status"] == "blocked_product_gap" and trust_result["criterion_pass"] is False, "protected trust registry remains fail-closed blocker", checks)

    concurrent_raw = read_csv(root / "04-concurrent-starts" / "raw-normalized.csv")
    concurrent_agg = read_csv(root / "04-concurrent-starts" / "aggregate-by-scenario.csv")
    require(len(concurrent_raw) == 27, "concurrent raw has 27 rows", checks)
    require(len(concurrent_agg) == 4, "concurrent aggregate has four scenarios", checks)
    require(all(row["success"].lower() == "true" for row in concurrent_raw), "concurrent all rows succeeded", checks)
    require(all(float(row["packet_loss_pct"]) == 0.0 for row in concurrent_raw), "concurrent all rows have zero loss", checks)
    require(all(int(row["direct_final_ab_ike_packets"]) == 0 for row in concurrent_raw), "concurrent direct final A/B IKE is zero", checks)

    manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
    require(manifest["network_actions"] is False and manifest["eve_ng_live_run"] is False, "manifest records offline-only execution", checks)
    manifest_entries = {entry["relative_path"]: entry for entry in manifest["generated_files"]}
    for path in required:
        rel = str(path.relative_to(root))
        if rel == "manifest.json":
            continue
        entry = manifest_entries.get(rel)
        require(entry is not None and entry["sha256"] == sha256(path), f"manifest hash: {rel}", checks)

    # Redaction gate: generated text/JSON/CSV must not contain obvious secret material.
    secret_pattern = re.compile(r"(?i)(private[_ -]?key\s*[:=]\s*[0-9a-fA-Z+/]{24,}|password\s*[:=]\s*\S+|BEGIN [A-Z ]*PRIVATE KEY)")
    redaction_ok = True
    for path in root.rglob("*"):
        if not path.is_file() or path.name == "validation.json" or path.suffix.lower() not in {".md", ".json", ".csv", ".py"}:
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        if secret_pattern.search(text):
            redaction_ok = False
            break
    require(redaction_ok, "generated artifacts contain no obvious private-key/password material", checks)

    passed = sum(bool(check["pass"]) for check in checks)
    result = {
        "status": "pass" if passed == len(checks) else "fail",
        "passed": passed,
        "total": len(checks),
        "checks": checks,
    }
    (root / "validation.json").write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"status": result["status"], "passed": passed, "total": len(checks)}, ensure_ascii=False))
    return 0 if result["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
