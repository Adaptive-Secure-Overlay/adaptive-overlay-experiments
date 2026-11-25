#!/usr/bin/env python3
"""Local-only, fail-closed WireGuard EVE-NG test orchestration scaffold."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

STATES = {"blocked", "ready", "running", "completed", "failed"}
SUITES = {"bidir12", "disjoint5", "ring10", "reverse5"}
ENDPOINTS = {f"n{index}" for index in range(1, 11)}
RELAYS = {"x1", "x2"}
CAPABILITIES = {
    "capture", "inject", "preserve_tuple", "type4_direct_bypass",
    "events", "redaction", "loop_prevention",
}
SECRET_RE = re.compile(
    r"(?:private[ _-]?key|preshared[ _-]?key|password|\bsecret\b)", re.I
)
PLACEHOLDER_RE = re.compile(
    r"(?:placeholder|example|template|todo|change[-_ ]?me)", re.I
)

RESULT_KEYS = {
    "schema_version", "suite", "case_id", "src", "dst", "conn", "ok",
    "status", "wg_up_code", "handshake_ok", "ping_ok", "wg_data_packets",
    "direct_wg_control_packets", "wg_up_seconds", "route", "x1", "x2",
    "conn_id", "x1_is_dst", "x2_is_src", "x2_is_dst", "abab",
    "up_tail", "ping_tail", "criteria", "metrics_ms", "evidence",
}
CRITERIA_KEYS = {
    "handshake_fresh", "useful_traffic_ok", "control_types_overlay_only",
    "transport_type4_direct_only", "reverse_route_ok", "redaction_confirmed",
}
METRICS_REQUIRED = {"route_setup_ms", "handshake_ms", "first_data_ms"}
METRICS_ALLOWED = METRICS_REQUIRED | {"rekey_ms"}
EVENT_KEYS = {"event", "message_type", "capture_id"}
EVENT_NAMES = {
    "CAPTURE", "ROUTE_READY", "SEND", "ARRIVE", "INJECT", "DIRECT", "DROP"
}
MANIFEST_KEYS = {
    "format", "backend_artifact", "backend_sha256", "backend_version",
    "endpoint_configs", "nodes", "daemon_binding", "scope",
    "capabilities", "rollback",
}


def now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def canonical_plan() -> list[dict[str, str]]:
    plan: list[dict[str, str]] = []

    def add(suite: str, src: int, dst: int) -> None:
        plan.append({
            "case_id": f"{suite}-{src}-to-{dst}",
            "suite": suite,
            "src": f"n{src}",
            "dst": f"n{dst}",
            "state": "pending",
        })

    add("bidir12", 1, 2)
    add("bidir12", 2, 1)
    for src, dst in ((1, 3), (2, 5), (4, 7), (6, 9), (8, 10)):
        add("disjoint5", src, dst)
    for src in range(1, 11):
        add("ring10", src, 1 if src == 10 else src + 1)
    for left, right in ((1, 6), (2, 7), (3, 8), (4, 9), (5, 10)):
        add("reverse5", left, right)
        add("reverse5", right, left)
    assert len(plan) == 27 and len({item["case_id"] for item in plan}) == 27
    return plan


def plan_index() -> dict[str, dict[str, str]]:
    return {item["case_id"]: item for item in canonical_plan()}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def atomic_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(
        prefix=path.name + ".", suffix=".tmp", dir=path.parent
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(value, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def read_json(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"invalid JSON at {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise ValueError(f"JSON object required: {path}")
    return data


def no_secrets(value: Any) -> bool:
    if isinstance(value, str):
        return SECRET_RE.search(value) is None
    if isinstance(value, list):
        return all(no_secrets(item) for item in value)
    if isinstance(value, dict):
        return all(
            no_secrets(key) and no_secrets(item) for key, item in value.items()
        )
    return True


def safe_relative(path: Path, parent: Path, label: str) -> str:
    try:
        return path.resolve(strict=True).relative_to(
            parent.resolve(strict=True)
        ).as_posix()
    except (OSError, ValueError) as exc:
        raise ValueError(f"{label} must exist inside {parent}") from exc


def new_checkpoint(
    preflight: Path | None, checkpoint_path: Path
) -> dict[str, Any]:
    preflight_ref: str | None = None
    preflight_sha256: str | None = None
    blockers = ["backend manifest has not been verified"]
    if preflight is not None:
        preflight_ref = safe_relative(
            preflight, checkpoint_path.parent, "preflight"
        )
        preflight_data = read_json(preflight)
        if not no_secrets(preflight_data):
            raise ValueError("preflight contains a secret-pattern")
        preflight_sha256 = sha256_file(preflight)
    else:
        blockers.append("preflight evidence reference is missing")
    created = now()
    return {
        "format": 1,
        "created_at": created,
        "updated_at": created,
        "state": "blocked",
        "plan": canonical_plan(),
        "blockers": blockers,
        "results": {},
        "counts": {"completed": 0, "total": 27},
        "preflight_ref": preflight_ref,
        "preflight_sha256": preflight_sha256,
        "backend_gate": None,
    }


def validate_checkpoint_data(cp: dict[str, Any]) -> None:
    if cp.get("format") != 1 or cp.get("state") not in STATES:
        raise ValueError("unsupported checkpoint format/state")
    plan = cp.get("plan")
    if not isinstance(plan, list) or len(plan) != 27:
        raise ValueError("checkpoint plan must contain 27 cases")
    expected = plan_index()
    seen: set[str] = set()
    completed: set[str] = set()
    for item in plan:
        if (
            not isinstance(item, dict)
            or set(item) != {"case_id", "suite", "src", "dst", "state"}
        ):
            raise ValueError("checkpoint plan item shape is invalid")
        case_id = item.get("case_id")
        if case_id not in expected or case_id in seen:
            raise ValueError("checkpoint plan identity is invalid or duplicated")
        if any(
            item.get(key) != expected[case_id][key]
            for key in ("suite", "src", "dst")
        ):
            raise ValueError("checkpoint plan differs from canonical plan")
        if item.get("state") not in {"pending", "completed"}:
            raise ValueError("checkpoint case state is invalid")
        seen.add(case_id)
        if item["state"] == "completed":
            completed.add(case_id)
    results = cp.get("results")
    if not isinstance(results, dict) or set(results) != completed:
        raise ValueError("checkpoint results must match completed cases")
    for case_id, record in results.items():
        if (
            not isinstance(record, dict)
            or set(record) != {"result_ref", "sha256", "recorded_at"}
            or not isinstance(record.get("result_ref"), str)
            or not re.fullmatch(r"[0-9a-f]{64}", str(record.get("sha256")))
            or not isinstance(record.get("recorded_at"), str)
        ):
            raise ValueError(f"checkpoint result record is invalid: {case_id}")
    counts = cp.get("counts")
    if counts != {"completed": len(completed), "total": 27}:
        raise ValueError("checkpoint counts are inconsistent")
    if cp.get("state") == "completed" and len(completed) != 27:
        raise ValueError("completed checkpoint must contain 27 results")


def load_checkpoint(path: Path) -> dict[str, Any]:
    cp = read_json(path)
    validate_checkpoint_data(cp)
    return cp


def is_placeholder_text(value: str) -> bool:
    return not value.strip() or PLACEHOLDER_RE.search(value) is not None


def existing_path(
    value: Any, label: str, *, file_required: bool = True
) -> tuple[list[str], Path | None]:
    if not isinstance(value, str) or not value:
        return [f"{label}: absolute non-empty path required"], None
    path = Path(value)
    if (
        not path.is_absolute()
        or not path.exists()
        or PLACEHOLDER_RE.search(path.name) is not None
        or (file_required and not path.is_file())
        or (path.is_file() and path.stat().st_size == 0)
    ):
        return [f"{label}: real non-placeholder existing path required"], None
    return [], path


def exact_keys(value: Any, expected: set[str], label: str) -> list[str]:
    if not isinstance(value, dict):
        return [f"{label}: object required"]
    missing = expected - set(value)
    extra = set(value) - expected
    errors: list[str] = []
    if missing:
        errors.append(f"{label}: missing fields {sorted(missing)}")
    if extra:
        errors.append(f"{label}: unexpected fields {sorted(extra)}")
    return errors


def manifest_blockers(manifest: dict[str, Any]) -> list[str]:
    blockers = exact_keys(manifest, MANIFEST_KEYS, "manifest")
    if blockers:
        return blockers
    if manifest.get("format") != 1:
        blockers.append("format: 1 required")
    if not no_secrets(manifest):
        blockers.append("manifest: secret-pattern detected")

    path_errors, backend = existing_path(
        manifest.get("backend_artifact"), "backend_artifact"
    )
    blockers += path_errors
    digest = manifest.get("backend_sha256")
    if (
        not isinstance(digest, str)
        or re.fullmatch(r"[0-9a-fA-F]{64}", digest) is None
    ):
        blockers.append("backend_sha256: 64 hexadecimal characters required")
    elif backend is not None and sha256_file(backend) != digest.lower():
        blockers.append("backend_sha256: does not match backend_artifact")
    version = manifest.get("backend_version")
    if not isinstance(version, str) or is_placeholder_text(version):
        blockers.append("backend_version: real non-placeholder version required")

    configs = manifest.get("endpoint_configs")
    if not isinstance(configs, dict) or set(configs) != ENDPOINTS:
        blockers.append("endpoint_configs: exact n1..n10 path map required")
    else:
        for endpoint in sorted(ENDPOINTS):
            blockers += existing_path(
                configs[endpoint], f"endpoint_configs.{endpoint}"
            )[0]

    nodes = manifest.get("nodes")
    expected_nodes = ENDPOINTS | RELAYS
    observed: dict[str, dict[str, Any]] = {}
    if not isinstance(nodes, list) or len(nodes) != len(expected_nodes):
        blockers.append("nodes: exact n1..n10,x1,x2 isolated inventory required")
    else:
        for index, node in enumerate(nodes):
            if (
                not isinstance(node, dict)
                or set(node) != {"logical_id", "eve_name", "role", "scope"}
            ):
                blockers.append(
                    f"nodes[{index}]: exact logical_id/eve_name/role/scope required"
                )
                continue
            logical_id = node.get("logical_id")
            if not isinstance(logical_id, str) or logical_id in observed:
                blockers.append(f"nodes[{index}]: unique logical_id required")
                continue
            observed[logical_id] = node
            expected_role = "relay" if logical_id in RELAYS else "endpoint"
            if (
                logical_id not in expected_nodes
                or node.get("role") != expected_role
                or node.get("scope") != "isolated-eve-lab"
                or not isinstance(node.get("eve_name"), str)
                or is_placeholder_text(node["eve_name"])
            ):
                blockers.append(f"nodes[{index}]: invalid isolated logical mapping")
        if set(observed) != expected_nodes:
            blockers.append("nodes: logical IDs must be exactly n1..n10,x1,x2")

    binding = manifest.get("daemon_binding")
    blockers += exact_keys(
        binding,
        {"protocol", "send_entrypoint", "deliver_entrypoint", "evidence_path"},
        "daemon_binding",
    )
    if isinstance(binding, dict):
        if binding.get("protocol") != "wireguard":
            blockers.append("daemon_binding.protocol: wireguard required")
        if binding.get("send_entrypoint") != "send_protocol_datagram":
            blockers.append(
                "daemon_binding.send_entrypoint: send_protocol_datagram required"
            )
        if binding.get("deliver_entrypoint") != "deliver_protocol_datagram":
            blockers.append(
                "daemon_binding.deliver_entrypoint: deliver_protocol_datagram required"
            )
        blockers += existing_path(
            binding.get("evidence_path"), "daemon_binding.evidence_path"
        )[0]

    scope = manifest.get("scope")
    blockers += exact_keys(
        scope, {"namespace", "interface", "udp_ports", "proof_path"}, "scope"
    )
    if isinstance(scope, dict):
        for key in ("namespace", "interface"):
            if (
                not isinstance(scope.get(key), str)
                or is_placeholder_text(scope[key])
            ):
                blockers.append(f"scope.{key}: real non-placeholder value required")
        ports = scope.get("udp_ports")
        if (
            not isinstance(ports, list)
            or not ports
            or any(
                not isinstance(port, int)
                or isinstance(port, bool)
                or port < 1
                or port > 65535
                for port in ports
            )
            or len(set(ports)) != len(ports)
        ):
            blockers.append("scope.udp_ports: unique UDP ports 1..65535 required")
        blockers += existing_path(scope.get("proof_path"), "scope.proof_path")[0]

    capabilities = manifest.get("capabilities")
    blockers += exact_keys(capabilities, CAPABILITIES, "capabilities")
    if isinstance(capabilities, dict):
        for capability in sorted(CAPABILITIES):
            if capabilities.get(capability) is not True:
                blockers.append(f"capabilities.{capability}: true required")

    rollback = manifest.get("rollback")
    rollback_keys = {
        "original_state_snapshot", "scope_proof", "restore_procedure",
        "verification_evidence", "verified_at",
    }
    blockers += exact_keys(rollback, rollback_keys, "rollback")
    if isinstance(rollback, dict):
        for key in rollback_keys - {"verified_at"}:
            blockers += existing_path(rollback.get(key), f"rollback.{key}")[0]
        verified_at = rollback.get("verified_at")
        if not isinstance(verified_at, str) or is_placeholder_text(verified_at):
            blockers.append("rollback.verified_at: verified timestamp required")
        else:
            try:
                datetime.fromisoformat(verified_at.replace("Z", "+00:00"))
            except ValueError:
                blockers.append("rollback.verified_at: ISO-8601 timestamp required")
    return blockers


def typed(result: dict[str, Any], key: str, expected: type) -> bool:
    value = result.get(key)
    return isinstance(value, expected) and not (
        expected is int and isinstance(value, bool)
    )


def valid_string(
    value: Any, *, minimum: int = 1, maximum: int = 128
) -> bool:
    return isinstance(value, str) and minimum <= len(value) <= maximum


def valid_number(value: Any, *, minimum: float = 0) -> bool:
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and value >= minimum
    )


def validate_result(result: dict[str, Any]) -> list[str]:
    errors = exact_keys(result, RESULT_KEYS, "result")
    if errors:
        return errors
    for key in (
        "suite", "case_id", "src", "dst", "conn", "x1", "x2", "conn_id"
    ):
        if not valid_string(result.get(key)):
            errors.append(f"{key}: string length 1..128 required")
    for key in ("up_tail", "ping_tail"):
        if not valid_string(result.get(key), minimum=0, maximum=4096):
            errors.append(f"{key}: string length 0..4096 required")
    for key in (
        "ok", "handshake_ok", "ping_ok", "x1_is_dst", "x2_is_src",
        "x2_is_dst", "abab",
    ):
        if not typed(result, key, bool):
            errors.append(f"{key}: boolean required")
    for key in (
        "schema_version", "wg_up_code", "wg_data_packets",
        "direct_wg_control_packets",
    ):
        if not typed(result, key, int):
            errors.append(f"{key}: integer required")
    if not valid_number(result.get("wg_up_seconds")):
        errors.append("wg_up_seconds: nonnegative number required")
    if errors:
        return errors

    expected = plan_index().get(result["case_id"])
    if (
        expected is None
        or result["suite"] != expected["suite"]
        or result["src"] != expected["src"]
        or result["dst"] != expected["dst"]
    ):
        errors.append(
            "case_id/suite/src/dst must match one canonical 27-case entry"
        )
    if result["schema_version"] != 1 or result["suite"] not in SUITES:
        errors.append("schema_version/suite invalid")
    if result.get("status") not in {"pass", "fail"}:
        errors.append("status: pass or fail required")
    if result["status"] != "pass" or result["ok"] is not True:
        errors.append("only status=pass and ok=true accepted")
    if (
        result["wg_up_code"] != 0
        or result["handshake_ok"] is not True
        or result["ping_ok"] is not True
        or result["wg_data_packets"] < 2
        or result["direct_wg_control_packets"] != 0
    ):
        errors.append(
            "WG activation, handshake, ping, data, or direct-control criterion failed"
        )

    route = result.get("route")
    if (
        not isinstance(route, list)
        or len(route) != 4
        or any(not valid_string(hop) for hop in route)
        or route != [result["src"], result["x1"], result["x2"], result["dst"]]
        or len(set(route)) != 4
    ):
        errors.append("route must be four distinct hops src -> x1 -> x2 -> dst")

    criteria = result.get("criteria")
    errors += exact_keys(criteria, CRITERIA_KEYS, "criteria")
    if isinstance(criteria, dict) and any(
        criteria.get(key) is not True for key in CRITERIA_KEYS
    ):
        errors.append("criteria flags must all be true")

    metrics = result.get("metrics_ms")
    if not isinstance(metrics, dict):
        errors.append("metrics_ms: object required")
    else:
        missing = METRICS_REQUIRED - set(metrics)
        extra = set(metrics) - METRICS_ALLOWED
        if missing:
            errors.append(f"metrics_ms: missing fields {sorted(missing)}")
        if extra:
            errors.append(f"metrics_ms: unexpected fields {sorted(extra)}")
        if any(not valid_number(value) for value in metrics.values()):
            errors.append("metrics_ms: all values must be nonnegative numbers")

    evidence = result.get("evidence")
    errors += exact_keys(evidence, {"events"}, "evidence")
    events = evidence.get("events") if isinstance(evidence, dict) else None
    if not isinstance(events, list) or not events:
        errors.append("evidence.events required")
    else:
        for index, event in enumerate(events):
            if not isinstance(event, dict):
                errors.append(f"evidence.events[{index}]: object required")
                continue
            missing = {"event", "message_type"} - set(event)
            extra = set(event) - EVENT_KEYS
            if missing:
                errors.append(
                    f"evidence.events[{index}]: missing fields {sorted(missing)}"
                )
            if extra:
                errors.append(
                    f"evidence.events[{index}]: unexpected fields {sorted(extra)}"
                )
            if event.get("event") not in EVENT_NAMES:
                errors.append(f"evidence.events[{index}]: invalid event")
            if event.get("message_type") not in {1, 2, 3, 4}:
                errors.append(f"evidence.events[{index}]: invalid message_type")
            if "capture_id" in event and not valid_string(
                event["capture_id"], minimum=0, maximum=128
            ):
                errors.append(f"evidence.events[{index}]: invalid capture_id")
        chain = ["CAPTURE", "ROUTE_READY", "SEND", "ARRIVE", "INJECT"]
        for message_type in (1, 2, 3):
            seen = [
                event.get("event")
                for event in events
                if isinstance(event, dict)
                and event.get("message_type") == message_type
            ]
            if seen != chain:
                errors.append(
                    f"type {message_type}: exact overlay event chain required"
                )
        type4 = [
            event for event in events
            if isinstance(event, dict) and event.get("message_type") == 4
        ]
        if not type4 or any(event.get("event") != "DIRECT" for event in type4):
            errors.append("type 4 must be DIRECT_BYPASS only")
        if any(
            isinstance(event, dict)
            and event.get("event") == "DIRECT"
            and event.get("message_type") != 4
            for event in events
        ):
            errors.append("DIRECT is reserved for type 4")
    if not no_secrets(result):
        errors.append("secret-pattern detected in result")
    return errors


def record_result(
    checkpoint_path: Path, result_path: Path
) -> tuple[dict[str, Any], bool]:
    cp = load_checkpoint(checkpoint_path)
    if cp["state"] not in {"ready", "running"}:
        raise ValueError("checkpoint must be ready or running before recording")
    result = read_json(result_path)
    errors = validate_result(result)
    if errors:
        raise ValueError("result rejected: " + "; ".join(errors))
    result_ref = safe_relative(result_path, checkpoint_path.parent, "result")
    digest = sha256_file(result_path)
    case_id = result["case_id"]
    existing = cp["results"].get(case_id)
    if existing is not None:
        if existing["sha256"] == digest and existing["result_ref"] == result_ref:
            return cp, False
        raise ValueError(f"conflicting result already recorded for {case_id}")
    cp["results"][case_id] = {
        "result_ref": result_ref,
        "sha256": digest,
        "recorded_at": now(),
    }
    for item in cp["plan"]:
        if item["case_id"] == case_id:
            item["state"] = "completed"
            break
    completed = len(cp["results"])
    cp["counts"] = {"completed": completed, "total": 27}
    cp["state"] = "completed" if completed == 27 else "running"
    cp["updated_at"] = now()
    cp["blockers"] = []
    validate_checkpoint_data(cp)
    atomic_json(checkpoint_path, cp)
    return cp, True


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("plan")
    init = sub.add_parser("init")
    init.add_argument("--checkpoint", required=True, type=Path)
    init.add_argument("--preflight", type=Path)
    gate = sub.add_parser("gate")
    gate.add_argument("--checkpoint", required=True, type=Path)
    gate.add_argument("--manifest", required=True, type=Path)
    accept = sub.add_parser("accept")
    accept.add_argument("--result", required=True, type=Path)
    record = sub.add_parser("record")
    record.add_argument("--checkpoint", required=True, type=Path)
    record.add_argument("--result", required=True, type=Path)
    status = sub.add_parser("status")
    status.add_argument("--checkpoint", required=True, type=Path)
    args = parser.parse_args()

    if args.command == "plan":
        print(json.dumps(canonical_plan(), indent=2))
        return 0
    if args.command == "accept":
        errors = validate_result(read_json(args.result))
        print(json.dumps({"accepted": not errors, "errors": errors}, indent=2))
        return 0 if not errors else 2
    if args.command == "record":
        cp, changed = record_result(args.checkpoint, args.result)
        print(json.dumps({
            "changed": changed, "state": cp["state"], "counts": cp["counts"]
        }, indent=2))
        return 0
    if args.command == "status":
        cp = load_checkpoint(args.checkpoint)
        print(json.dumps({
            "state": cp["state"], "counts": cp["counts"],
            "blockers": cp["blockers"],
        }, indent=2))
        return 0
    if args.command == "init":
        if args.checkpoint.exists():
            raise ValueError("checkpoint already exists")
        cp = new_checkpoint(args.preflight, args.checkpoint)
        validate_checkpoint_data(cp)
        atomic_json(args.checkpoint, cp)
        print(json.dumps({
            "checkpoint": str(args.checkpoint), "state": cp["state"],
            "blockers": cp["blockers"],
        }, indent=2))
        return 0

    cp = load_checkpoint(args.checkpoint)
    manifest_path = args.manifest.resolve(strict=True)
    manifest = read_json(manifest_path)
    blockers = manifest_blockers(manifest)
    if cp.get("preflight_ref") is None:
        blockers.append("checkpoint: preflight evidence reference required")
    cp["updated_at"] = now()
    cp["blockers"] = blockers
    completed = cp["counts"]["completed"]
    cp["state"] = (
        "blocked" if blockers
        else "completed" if completed == 27
        else "running" if completed
        else "ready"
    )
    cp["backend_gate"] = {
        "checked_at": now(),
        "manifest_sha256": sha256_file(manifest_path),
        "ready": not blockers,
    }
    validate_checkpoint_data(cp)
    atomic_json(args.checkpoint, cp)
    print(json.dumps({
        "checkpoint": str(args.checkpoint), "state": cp["state"],
        "blockers": blockers,
    }, indent=2))
    return 0 if not blockers else 2


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(2)
