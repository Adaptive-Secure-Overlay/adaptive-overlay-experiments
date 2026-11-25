#!/usr/bin/env python3
"""Accepted backend gate: manifest checks plus fresh live-preflight checks."""
from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import harness


def preflight_blockers(
    checkpoint: dict[str, Any], checkpoint_path: Path
) -> list[str]:
    reference = checkpoint.get("preflight_ref")
    expected_digest = checkpoint.get("preflight_sha256")
    if not isinstance(reference, str) or not reference:
        return ["preflight: evidence reference required"]
    preflight_path = checkpoint_path.parent / reference
    try:
        resolved = preflight_path.resolve(strict=True)
        resolved.relative_to(checkpoint_path.parent.resolve(strict=True))
    except (OSError, ValueError):
        return ["preflight: referenced file must exist inside run directory"]

    blockers: list[str] = []
    if harness.sha256_file(resolved) != expected_digest:
        blockers.append("preflight: evidence hash mismatch")
    try:
        preflight = harness.read_json(resolved)
    except ValueError as exc:
        return blockers + [f"preflight: {exc}"]

    checked_at = preflight.get("checked_at")
    try:
        checked = datetime.fromisoformat(str(checked_at).replace("Z", "+00:00"))
        if checked.tzinfo is None:
            raise ValueError
        age = datetime.now(timezone.utc) - checked.astimezone(timezone.utc)
        if age.total_seconds() < -300 or age.total_seconds() > 86400:
            blockers.append("preflight: evidence must be fresh within 24 hours")
    except ValueError:
        blockers.append("preflight.checked_at: timezone-aware ISO-8601 required")

    local = preflight.get("local")
    if not isinstance(local, dict) or local.get("runner_matches") != 0:
        blockers.append("preflight.local.runner_matches: zero required")
    eve = preflight.get("eve")
    if not isinstance(eve, dict):
        blockers.append("preflight.eve: object required")
    else:
        required = {
            "vm_running": True,
            "ssh_reachable": True,
            "dev_kvm_ready": True,
            "selected_nodes_ready": True,
            "remote_runner_matches": 0,
        }
        for key, expected in required.items():
            if eve.get(key) != expected:
                blockers.append(f"preflight.eve.{key}: {expected!r} required")
        free_bytes = eve.get("remote_disk_free_bytes")
        if (
            not isinstance(free_bytes, int)
            or isinstance(free_bytes, bool)
            or free_bytes <= 0
        ):
            blockers.append(
                "preflight.eve.remote_disk_free_bytes: positive integer required"
            )
    decision = preflight.get("decision")
    if not isinstance(decision, dict) or decision.get("state") != "ready":
        blockers.append("preflight.decision.state: ready required")
    if not harness.no_secrets(preflight):
        blockers.append("preflight: secret-pattern detected")
    return blockers


def gate(
    checkpoint_path: Path, manifest_path: Path
) -> tuple[dict[str, Any], list[str]]:
    checkpoint = harness.load_checkpoint(checkpoint_path)
    manifest_path = manifest_path.resolve(strict=True)
    manifest = harness.read_json(manifest_path)
    blockers = harness.manifest_blockers(manifest)
    blockers += preflight_blockers(checkpoint, checkpoint_path)
    checkpoint["updated_at"] = harness.now()
    checkpoint["blockers"] = blockers
    completed = checkpoint["counts"]["completed"]
    checkpoint["state"] = (
        "blocked" if blockers
        else "completed" if completed == 27
        else "running" if completed
        else "ready"
    )
    checkpoint["backend_gate"] = {
        "checked_at": harness.now(),
        "manifest_sha256": harness.sha256_file(manifest_path),
        "ready": not blockers,
        "preflight_enforced": True,
    }
    harness.validate_checkpoint_data(checkpoint)
    harness.atomic_json(checkpoint_path, checkpoint)
    return checkpoint, blockers


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--checkpoint", required=True, type=Path)
    parser.add_argument("--manifest", required=True, type=Path)
    args = parser.parse_args()
    checkpoint, blockers = gate(args.checkpoint, args.manifest)
    print(json.dumps({
        "checkpoint": str(args.checkpoint),
        "state": checkpoint["state"],
        "counts": checkpoint["counts"],
        "blockers": blockers,
    }, indent=2))
    return 0 if not blockers else 2


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ValueError as exc:
        print(f"ERROR: {exc}")
        raise SystemExit(2)
