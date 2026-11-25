from __future__ import annotations

import copy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import harness


def valid_result(case: dict[str, str]) -> dict[str, object]:
    events = []
    chain = ["CAPTURE", "ROUTE_READY", "SEND", "ARRIVE", "INJECT"]
    for message_type in (1, 2, 3):
        events.extend(
            {"event": event, "message_type": message_type, "capture_id": "cap-1"}
            for event in chain
        )
    events.append({"event": "DIRECT", "message_type": 4, "capture_id": "cap-1"})
    return {
        "schema_version": 1,
        "suite": case["suite"],
        "case_id": case["case_id"],
        "src": case["src"],
        "dst": case["dst"],
        "conn": f"{case['src']}->{case['dst']}",
        "ok": True,
        "status": "pass",
        "wg_up_code": 0,
        "handshake_ok": True,
        "ping_ok": True,
        "wg_data_packets": 2,
        "direct_wg_control_packets": 0,
        "wg_up_seconds": 0.25,
        "route": [case["src"], "relay-a", "relay-b", case["dst"]],
        "x1": "relay-a",
        "x2": "relay-b",
        "conn_id": case["case_id"],
        "x1_is_dst": False,
        "x2_is_src": False,
        "x2_is_dst": False,
        "abab": True,
        "up_tail": "activation ok",
        "ping_tail": "ping ok",
        "criteria": {
            "handshake_fresh": True,
            "useful_traffic_ok": True,
            "control_types_overlay_only": True,
            "transport_type4_direct_only": True,
            "reverse_route_ok": True,
            "redaction_confirmed": True,
        },
        "metrics_ms": {
            "route_setup_ms": 1.0,
            "handshake_ms": 2.0,
            "first_data_ms": 3.0,
        },
        "evidence": {"events": events},
    }


def create_manifest(root: Path) -> dict[str, object]:
    def material(name: str, text: str = "evidence") -> Path:
        path = root / name
        path.write_text(text, encoding="utf-8")
        return path

    backend = material("backend.exe", "binary")
    configs = {
        endpoint: str(material(f"{endpoint}.conf", "wireguard-reference"))
        for endpoint in sorted(harness.ENDPOINTS)
    }
    nodes = [
        {
            "logical_id": endpoint,
            "eve_name": f"EVE-{endpoint}",
            "role": "endpoint",
            "scope": "isolated-eve-lab",
        }
        for endpoint in sorted(harness.ENDPOINTS)
    ]
    nodes.extend(
        {
            "logical_id": relay,
            "eve_name": f"EVE-{relay}",
            "role": "relay",
            "scope": "isolated-eve-lab",
        }
        for relay in sorted(harness.RELAYS)
    )
    return {
        "format": 1,
        "backend_artifact": str(backend),
        "backend_sha256": hashlib.sha256(backend.read_bytes()).hexdigest(),
        "backend_version": "1.0.0",
        "endpoint_configs": configs,
        "nodes": nodes,
        "daemon_binding": {
            "protocol": "wireguard",
            "send_entrypoint": "send_protocol_datagram",
            "deliver_entrypoint": "deliver_protocol_datagram",
            "evidence_path": str(material("binding-proof.txt")),
        },
        "scope": {
            "namespace": "wg-eve-isolated",
            "interface": "wg-test0",
            "udp_ports": [51820],
            "proof_path": str(material("scope-proof.txt")),
        },
        "capabilities": {name: True for name in harness.CAPABILITIES},
        "rollback": {
            "original_state_snapshot": str(material("original-state.txt")),
            "scope_proof": str(material("rollback-scope.txt")),
            "restore_procedure": str(material("restore-procedure.txt")),
            "verification_evidence": str(material("rollback-verified.txt")),
            "verified_at": "2026-08-25T00:00:00Z",
        },
    }


class HarnessTests(unittest.TestCase):
    def test_canonical_plan_has_exact_27(self) -> None:
        plan = harness.canonical_plan()
        self.assertEqual(27, len(plan))
        self.assertEqual(27, len({item["case_id"] for item in plan}))
        self.assertEqual(
            {"bidir12": 2, "disjoint5": 5, "ring10": 10, "reverse5": 10},
            {
                suite: sum(item["suite"] == suite for item in plan)
                for suite in harness.SUITES
            },
        )

    def test_result_validator_accepts_contract_and_rejects_drift(self) -> None:
        result = valid_result(harness.canonical_plan()[0])
        self.assertEqual([], harness.validate_result(result))

        extra = copy.deepcopy(result)
        extra["unexpected"] = True
        self.assertTrue(harness.validate_result(extra))

        bad_metric = copy.deepcopy(result)
        bad_metric["metrics_ms"]["first_data_ms"] = -1
        self.assertTrue(harness.validate_result(bad_metric))

        bad_case = copy.deepcopy(result)
        bad_case["case_id"] = "not-canonical"
        self.assertTrue(harness.validate_result(bad_case))

        bad_event = copy.deepcopy(result)
        bad_event["evidence"]["events"][0]["extra"] = "not allowed"
        self.assertTrue(harness.validate_result(bad_event))

    def test_manifest_gate_is_exact_and_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest = create_manifest(root)
            self.assertEqual([], harness.manifest_blockers(manifest))

            wrong_hash = copy.deepcopy(manifest)
            wrong_hash["backend_sha256"] = "0" * 64
            self.assertTrue(harness.manifest_blockers(wrong_hash))

            extra = copy.deepcopy(manifest)
            extra["private_key"] = "material"
            self.assertTrue(harness.manifest_blockers(extra))

            missing_node = copy.deepcopy(manifest)
            missing_node["nodes"] = missing_node["nodes"][:-1]
            self.assertTrue(harness.manifest_blockers(missing_node))

    def test_atomic_checkpoint_resume_idempotence_conflict_and_completion(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            preflight = root / "preflight.json"
            preflight.write_text('{"status":"checked"}', encoding="utf-8")
            checkpoint_path = root / "checkpoint.json"
            cp = harness.new_checkpoint(preflight, checkpoint_path)
            cp["state"] = "ready"
            cp["blockers"] = []
            harness.atomic_json(checkpoint_path, cp)

            first_case = harness.canonical_plan()[0]
            first_path = root / "results" / f"{first_case['case_id']}.json"
            first_path.parent.mkdir()
            first_path.write_text(
                json.dumps(valid_result(first_case)), encoding="utf-8"
            )
            cp, changed = harness.record_result(checkpoint_path, first_path)
            self.assertTrue(changed)
            self.assertEqual({"completed": 1, "total": 27}, cp["counts"])
            self.assertEqual("running", cp["state"])

            cp, changed = harness.record_result(checkpoint_path, first_path)
            self.assertFalse(changed)
            self.assertEqual(1, cp["counts"]["completed"])

            conflicting = valid_result(first_case)
            conflicting["up_tail"] = "different valid evidence"
            first_path.write_text(json.dumps(conflicting), encoding="utf-8")
            with self.assertRaises(ValueError):
                harness.record_result(checkpoint_path, first_path)

            for case in harness.canonical_plan()[1:]:
                result_path = root / "results" / f"{case['case_id']}.json"
                result_path.write_text(
                    json.dumps(valid_result(case)), encoding="utf-8"
                )
                harness.record_result(checkpoint_path, result_path)
            final = harness.load_checkpoint(checkpoint_path)
            self.assertEqual("completed", final["state"])
            self.assertEqual({"completed": 27, "total": 27}, final["counts"])


if __name__ == "__main__":
    unittest.main()
