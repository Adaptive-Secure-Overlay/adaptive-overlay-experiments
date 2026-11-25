from __future__ import annotations

import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import harness
import safe_gate


class SafeGateTests(unittest.TestCase):
    def test_preflight_requires_live_ready_state(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            preflight = root / "preflight.json"
            preflight.write_text(json.dumps({
                "checked_at": datetime.now(timezone.utc).isoformat(),
                "local": {"runner_matches": 0},
                "eve": {"vm_running": False, "ssh_reachable": False},
                "decision": {"state": "blocked"},
            }), encoding="utf-8")
            checkpoint_path = root / "checkpoint.json"
            checkpoint = harness.new_checkpoint(preflight, checkpoint_path)
            blockers = safe_gate.preflight_blockers(checkpoint, checkpoint_path)
            self.assertTrue(blockers)
            self.assertTrue(any("vm_running" in item for item in blockers))

    def test_preflight_accepts_complete_fresh_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            preflight = root / "preflight.json"
            preflight.write_text(json.dumps({
                "checked_at": datetime.now(timezone.utc).isoformat(),
                "local": {"runner_matches": 0},
                "eve": {
                    "vm_running": True,
                    "ssh_reachable": True,
                    "dev_kvm_ready": True,
                    "selected_nodes_ready": True,
                    "remote_runner_matches": 0,
                    "remote_disk_free_bytes": 1,
                },
                "decision": {"state": "ready"},
            }), encoding="utf-8")
            checkpoint_path = root / "checkpoint.json"
            checkpoint = harness.new_checkpoint(preflight, checkpoint_path)
            self.assertEqual(
                [], safe_gate.preflight_blockers(checkpoint, checkpoint_path)
            )


if __name__ == "__main__":
    unittest.main()
