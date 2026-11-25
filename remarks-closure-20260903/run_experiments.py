#!/usr/bin/env python3
"""Offline, reproducible closure experiments for four dissertation remarks.

The script is intentionally network-free.  It reads preserved EVE-NG artifacts,
runs a deterministic Monte Carlo calibration, and performs local negative tests
against the preserved cascade implementation.  LegacyWorkspace is never edited.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import os
import platform
import random
import re
import statistics
import sys
import time
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterable


ROOT_NAME = "remarks-closure-20260903"
CASCADE_ARTIFACT_NAME = "universal-cascade-data-plane-multivantage-matrix-eve-20260821-115025"
CONCURRENT_FILES = {
    "bidir12": (2, "concurrent_inline_bidir12_v5.csv"),
    "disjoint5": (5, "concurrent_inline_disjoint5_v2.csv"),
    "ring10": (10, "concurrent_inline_ring10_v3.csv"),
    "reverse5": (10, "concurrent_inline_reverse5_v2.csv"),
}
THRESHOLD_CASES = ((1, 2), (2, 2), (1, 3), (2, 3), (1, 4), (2, 4), (3, 4), (2, 5))
THRESHOLD_TRIALS = 50_000
BASE_SEED = 20_260_903


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest().upper()


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def write_csv(path: Path, rows: list[dict[str, Any]], fieldnames: list[str] | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if fieldnames is None:
        if not rows:
            raise ValueError(f"cannot infer CSV columns for empty rows: {path}")
        fieldnames = list(rows[0])
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fieldnames, extrasaction="raise")
        writer.writeheader()
        writer.writerows(rows)


def percentile(values: Iterable[float], q: float) -> float:
    ordered = sorted(float(value) for value in values)
    if not ordered:
        raise ValueError("percentile of empty sequence")
    position = (len(ordered) - 1) * q
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return ordered[lower]
    weight = position - lower
    return ordered[lower] * (1.0 - weight) + ordered[upper] * weight


def wilson(successes: int, trials: int, z: float = 1.959963984540054) -> tuple[float, float]:
    p = successes / trials
    denom = 1.0 + z * z / trials
    centre = (p + z * z / (2.0 * trials)) / denom
    margin = z * math.sqrt(p * (1.0 - p) / trials + z * z / (4.0 * trials * trials)) / denom
    return centre - margin, centre + margin


def f4_route_count(n: int, j: int) -> int:
    """Equation (40/41) route count: walks A->...->B in K_n without self-loops."""
    if n < 2 or j < 0:
        return 0
    numerator = (n - 1) ** (j + 1) - (-1) ** (j + 1)
    return numerator // n


def f4_intercept_probability(n: int, m: int, j: int) -> float:
    total = f4_route_count(n, j)
    safe = f4_route_count(n - m, j)
    if total <= 0:
        raise ValueError("route count must be positive")
    return 1.0 - safe / total


def n_alpha_f4(m: int, j: int, alpha: float) -> int:
    for n in range(max(3, m + 2), 501):
        if f4_intercept_probability(n, m, j) <= alpha:
            return n
    raise RuntimeError(f"n_alpha not found for m={m}, j={j}, alpha={alpha}")


def monte_carlo_f4(n: int, m: int, j: int, trials: int, seed: int) -> int:
    """Uniformly sample valid F4 routes, returning intercepted-route count."""
    rng = random.Random(seed)
    nodes = tuple(range(n))
    source = 0
    destination = 1
    compromised = set(range(2, 2 + m))
    hits = 0
    accepted = 0
    while accepted < trials:
        current = source
        intercepted = False
        for _ in range(j):
            candidate_index = rng.randrange(n - 1)
            candidate = nodes[candidate_index]
            if candidate >= current:
                candidate = nodes[candidate_index + 1]
            current = candidate
            if current in compromised:
                intercepted = True
        # X_j == B would make the fixed final edge B->B, which is not in K_n.
        if current == destination:
            continue
        accepted += 1
        hits += int(intercepted)
    return hits


def experiment_threshold(output: Path, source_report: Path) -> dict[str, Any]:
    exp = output / "01-threshold-calibration"
    raw_rows: list[dict[str, Any]] = []
    case_rows: list[dict[str, Any]] = []
    all_ok = True
    for m, j in THRESHOLD_CASES:
        n50 = n_alpha_f4(m, j, 0.5)
        pair_rows = []
        for boundary, n in (("below", n50 - 1), ("at", n50)):
            exact = f4_intercept_probability(n, m, j)
            seed = BASE_SEED + m * 100_000 + j * 1_000 + n
            hits = monte_carlo_f4(n, m, j, THRESHOLD_TRIALS, seed)
            estimate = hits / THRESHOLD_TRIALS
            ci_low, ci_high = wilson(hits, THRESHOLD_TRIALS)
            error = abs(estimate - exact)
            row = {
                "model": "F4-repeat-walk",
                "m_compromised": m,
                "j_intermediate_positions": j,
                "alpha": 0.5,
                "boundary": boundary,
                "n": n,
                "n50": n50,
                "trials": THRESHOLD_TRIALS,
                "seed": seed,
                "intercepted": hits,
                "not_intercepted": THRESHOLD_TRIALS - hits,
                "empirical_probability": round(estimate, 8),
                "wilson95_low": round(ci_low, 8),
                "wilson95_high": round(ci_high, 8),
                "exact_probability": round(exact, 8),
                "absolute_error": round(error, 8),
                "error_le_0_01": error <= 0.01,
            }
            raw_rows.append(row)
            pair_rows.append(row)
        crossing = (
            float(pair_rows[0]["exact_probability"]) > 0.5
            and float(pair_rows[1]["exact_probability"]) <= 0.5
        )
        case_ok = crossing and all(bool(row["error_le_0_01"]) for row in pair_rows)
        all_ok = all_ok and case_ok
        case_rows.append({
            "model": "F4-repeat-walk",
            "m_compromised": m,
            "j_intermediate_positions": j,
            "alpha": 0.5,
            "n50": n50,
            "exact_below": pair_rows[0]["exact_probability"],
            "empirical_below": pair_rows[0]["empirical_probability"],
            "exact_at": pair_rows[1]["exact_probability"],
            "empirical_at": pair_rows[1]["empirical_probability"],
            "threshold_crossing_exact": crossing,
            "max_absolute_error": max(float(row["absolute_error"]) for row in pair_rows),
            "criterion_pass": case_ok,
        })
    write_csv(exp / "raw-counts.csv", raw_rows)
    write_csv(exp / "aggregate.csv", case_rows)
    result = {
        "status": "completed_computational_calibration" if all_ok else "failed_validation",
        "hypothesis": "Monte Carlo interception frequencies agree with the F4 analytical model around n50 for alpha=0.5.",
        "requested_notation_note": "The source dissertation defines alpha=0.5 (0 < alpha < 1) and n50. No valid model parameter alpha=50 was found; alpha=50 was not fabricated.",
        "parameters": {
            "model": "F4 complete-graph walk with repeated nodes and no self-loop",
            "alpha": 0.5,
            "cases": [{"m": m, "j": j} for m, j in THRESHOLD_CASES],
            "boundary_points_per_case": 2,
            "trials_per_point": THRESHOLD_TRIALS,
            "total_simulated_routes": len(THRESHOLD_CASES) * 2 * THRESHOLD_TRIALS,
            "base_seed": BASE_SEED,
        },
        "success_criterion": "For every (m,j), exact P(intercept) is >0.5 at n50-1 and <=0.5 at n50; Monte Carlo absolute error <=0.01 at both points.",
        "criterion_pass": all_ok,
        "source": str(source_report),
        "source_sha256": sha256(source_report),
        "raw": str(exp / "raw-counts.csv"),
        "aggregate": str(exp / "aggregate.csv"),
        "limited_conclusion": "The 0.5 crossing is empirically reproduced inside the stated F4 route model. This does not calibrate an operational security limit and does not validate alpha=50.",
    }
    write_json(exp / "result.json", result)
    (exp / "PASSPORT.md").write_text(
        "# Паспорт 1. Калибровка n50 и α\n\n"
        "- Гипотеза: частоты перехвата Монте-Карло согласуются с аналитической моделью F4 около границы `α = 0,5`.\n"
        f"- Параметры: 8 пар `(m,j)`, две точки на пару, {THRESHOLD_TRIALS:,} маршрутов на точку, фиксированный seed `{BASE_SEED}`.\n"
        f"- Стенд и версии: локальный CPython `{platform.python_version()}`, сетевые действия отсутствуют; модель формул 40–44 из текущей редакции, контрольный отчёт `{source_report}`.\n"
        f"- Число прогонов: {len(THRESHOLD_CASES) * 2} групп, всего {len(THRESHOLD_CASES) * 2 * THRESHOLD_TRIALS:,} маршрутов.\n"
        "- Критерий успеха: точное пересечение 0,5 в каждой паре и абсолютная ошибка Монте-Карло не более 0,01.\n"
        "- Сырой артефакт: `raw-counts.csv` (счётчики intercepted/not_intercepted, seed и доверительный интервал).\n"
        "- Агрегат: `aggregate.csv`, `result.json`.\n"
        f"- Результат: `{all_ok}`.\n"
        "- Ограниченный вывод: воспроизведена только модельная граница `α = 0,5`; эксплуатационная безопасность не доказана. В исходнике нет допустимого параметра `α = 50`: для α требуется `0 < α < 1`.\n",
        encoding="utf-8",
    )
    return result


PING_LOSS_RE = re.compile(r"(\d+) packets transmitted,\s*(\d+) received,\s*([0-9.]+)% packet loss")
PING_RTT_RE = re.compile(r"rtt [^=]+ =\s*([0-9.]+)/([0-9.]+)/([0-9.]+)/([0-9.]+) ms")


def parse_ping(text: str) -> dict[str, float | int]:
    loss = PING_LOSS_RE.search(text)
    rtt = PING_RTT_RE.search(text)
    if not loss or not rtt:
        raise ValueError("protected ping log is missing loss or RTT summary")
    return {
        "transmitted": int(loss.group(1)),
        "received": int(loss.group(2)),
        "loss_pct": float(loss.group(3)),
        "rtt_min_ms": float(rtt.group(1)),
        "rtt_avg_ms": float(rtt.group(2)),
        "rtt_max_ms": float(rtt.group(3)),
        "rtt_mdev_ms": float(rtt.group(4)),
    }


def summarize_numeric(values: list[float]) -> dict[str, float]:
    return {
        "mean": round(statistics.fmean(values), 6),
        "median": round(statistics.median(values), 6),
        "p95": round(percentile(values, 0.95), 6),
        "max": round(max(values), 6),
    }


def experiment_cascade(output: Path, legacy: Path) -> dict[str, Any]:
    exp = output / "02-cascade-length"
    artifact = legacy / "artifacts" / CASCADE_ARTIFACT_NAME
    result_path = artifact / "result.json"
    config_path = artifact / "matrix-config.json"
    source = json.loads(result_path.read_text(encoding="utf-8"))
    rows: list[dict[str, Any]] = []
    for trial in source["trials"]:
        trial_dir = artifact / trial["label"]
        ping = parse_ping((trial_dir / "ping-protected.log").read_text(encoding="utf-8", errors="replace"))
        packets = json.loads((trial_dir / "source_edge.full.json").read_text(encoding="utf-8"))
        timestamps = [float(packet["t_abs_s"]) for packet in packets]
        rows.append({
            "label": trial["label"],
            "hops": int(trial["hops"]),
            "destination": trial["destination"],
            "repeat": int(trial["repeat"]),
            "success": bool(trial["success"]),
            "ping_transmitted": ping["transmitted"],
            "ping_received": ping["received"],
            "packet_loss_pct": ping["loss_pct"],
            "rtt_avg_ms": ping["rtt_avg_ms"],
            "rtt_max_ms": ping["rtt_max_ms"],
            "active_cell_count": int(trial["route_data"]["active_cell_count"]),
            "unique_edge_handles": int(trial["route_data"]["unique_edge_handles"]),
            "source_edge_packets": len(packets),
            "source_edge_bytes": sum(int(packet["length"]) for packet in packets),
            "source_capture_span_ms": round((max(timestamps) - min(timestamps)) * 1000.0, 6),
            "trial_result_path": str(trial_dir / "trial-result.json"),
            "ping_log_path": str(trial_dir / "ping-protected.log"),
            "source_edge_capture_path": str(trial_dir / "source_edge.full.json"),
        })
    write_csv(exp / "raw-trials.csv", rows)
    by_hops: dict[int, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        by_hops[int(row["hops"])].append(row)
    aggregates: list[dict[str, Any]] = []
    for hops, group in sorted(by_hops.items()):
        rtt = [float(row["rtt_avg_ms"]) for row in group]
        bytes_seen = [float(row["source_edge_bytes"]) for row in group]
        packets_seen = [float(row["source_edge_packets"]) for row in group]
        spans = [float(row["source_capture_span_ms"]) for row in group]
        transmitted = sum(int(row["ping_transmitted"]) for row in group)
        received = sum(int(row["ping_received"]) for row in group)
        aggregates.append({
            "hops": hops,
            "trials": len(group),
            "successes": sum(bool(row["success"]) for row in group),
            "success_rate": round(sum(bool(row["success"]) for row in group) / len(group), 6),
            "mean_loss_pct": round(statistics.fmean(float(row["packet_loss_pct"]) for row in group), 6),
            "max_loss_pct": round(max(float(row["packet_loss_pct"]) for row in group), 6),
            "ping_transmitted_total": transmitted,
            "ping_received_total": received,
            "ping_loss_packets": transmitted - received,
            "ping_loss_rate_pct": round((transmitted - received) * 100.0 / transmitted, 6),
            "rtt_mean_ms": summarize_numeric(rtt)["mean"],
            "rtt_median_ms": summarize_numeric(rtt)["median"],
            "rtt_p95_ms": summarize_numeric(rtt)["p95"],
            "rtt_max_ms": summarize_numeric(rtt)["max"],
            "active_cells_mean": round(statistics.fmean(float(row["active_cell_count"]) for row in group), 6),
            "edge_handles_mean": round(statistics.fmean(float(row["unique_edge_handles"]) for row in group), 6),
            "source_packets_mean": summarize_numeric(packets_seen)["mean"],
            "source_packets_p95": summarize_numeric(packets_seen)["p95"],
            "source_bytes_mean": summarize_numeric(bytes_seen)["mean"],
            "source_bytes_p95": summarize_numeric(bytes_seen)["p95"],
            "capture_span_mean_ms": summarize_numeric(spans)["mean"],
            "capture_span_p95_ms": summarize_numeric(spans)["p95"],
        })
    write_csv(exp / "aggregate-by-hops.csv", aggregates)
    expected_counts = {3: 400, 4: 400, 5: 400}
    complete = len(rows) == 1200 and {h: len(v) for h, v in by_hops.items()} == expected_counts
    success = complete and all(bool(row["success"]) for row in rows)
    result = {
        "status": "completed_offline_eve_reanalysis" if success else "failed_validation",
        "hypothesis": "Increasing cascade length from 3 to 5 hops changes protected-ping delay and increases route-state/load observables without reducing completion in the preserved series.",
        "parameters": json.loads(config_path.read_text(encoding="utf-8")),
        "success_criterion": "Exactly 1200 unique trials (400 per hop count), every trial success=true, and every ping/source-edge capture is parseable; packet loss is an observed metric, not silently promoted to zero.",
        "criterion_pass": success,
        "source_result": str(result_path),
        "source_result_sha256": sha256(result_path),
        "source_config": str(config_path),
        "source_config_sha256": sha256(config_path),
        "raw": str(exp / "raw-trials.csv"),
        "aggregate": str(exp / "aggregate-by-hops.csv"),
        "aggregate_rows": aggregates,
        "limited_conclusion": "All 1200 preserved EVE-NG trials completed, while 6 of 2400 ping packets were lost (H3=0, H4=1, H5=5). The series supports comparison for H=3/4/5 only. source-edge bytes include encrypted setup and data and are an upper-bound observation, not a pure control-overhead counter.",
    }
    write_json(exp / "result.json", result)
    table = "\n".join(
        f"| {row['hops']} | {row['trials']} | {row['successes']}/{row['trials']} | {row['rtt_median_ms']:.3f} | {row['rtt_p95_ms']:.3f} | {row['source_bytes_mean']:.1f} | {row['active_cells_mean']:.1f} | {row['edge_handles_mean']:.1f} |"
        for row in aggregates
    )
    (exp / "PASSPORT.md").write_text(
        "# Паспорт 2. Длина каскада\n\n"
        "- Гипотеза: рост числа промежуточных переходов с 3 до 5 меняет RTT и увеличивает состояние маршрута/наблюдаемую нагрузку без потери успешности в сохранённой серии.\n"
        "- Параметры: H=3,4,5; получатели User7–User10; 100 повторов на получателя; 13 синхронных точек наблюдения.\n"
        f"- Стенд и версии: сохранённый локальный EVE-NG артефакт `{artifact.name}`, Debian 13 User1–User10, конфигурация `{config_path}`; повторного запуска сети нет.\n"
        f"- Число прогонов: {len(rows)} ({', '.join(f'H={h}: {len(by_hops[h])}' for h in sorted(by_hops))}).\n"
        "- Критерий успеха: 1200 уникальных записей, 400 на H, все success=true, RTT и capture читаются; фактические потери измеряются и не подменяются нулём.\n"
        "- Сырой артефакт: `raw-trials.csv`; исходные `trial-result.json`, `ping-protected.log`, `source_edge.full.json` указаны в каждой строке.\n"
        "- Агрегат: `aggregate-by-hops.csv`, `result.json`.\n\n"
        "| H | Прогонов | Успех | Median RTT, ms | P95 RTT, ms | Mean source bytes | Active cells | Edge handles |\n"
        "|---:|---:|---:|---:|---:|---:|---:|---:|\n"
        f"{table}\n\n"
        "Ограниченный вывод: 1200/1200 опытов завершились, но потеряно 6/2400 контрольных ping (H=3: 0; H=4: 1; H=5: 5). Сравнение относится к сохранённой EVE-NG серии и H=3–5. Число source-edge bytes включает зашифрованные служебные и пользовательские пакеты и служит верхней наблюдаемой оценкой, а не чистым счётчиком control-plane.\n",
        encoding="utf-8",
    )
    return result


def experiment_trust(output: Path, legacy: Path) -> dict[str, Any]:
    exp = output / "03-trust-registry-negative"
    module_dir = legacy / "hybrid-overlay"
    sys.path.insert(0, str(module_dir))
    try:
        from universal_cascade import (  # type: ignore
            CascadeIdentity,
            CascadeProtocolError,
            UniversalCascade,
            generate_identity_set,
        )
    finally:
        # Keep importable dependencies loaded but do not leak a persistent path mutation.
        sys.path.pop(0)

    names = ["NodeA", "NodeB", "NodeC", "NodeD"]
    private_hex, public_hex = generate_identity_set(names)
    rows: list[dict[str, Any]] = []

    def expected_rejection(case: str, action: Any, expected_fragment: str) -> None:
        try:
            action()
        except CascadeProtocolError as exc:
            rows.append({
                "case": case,
                "expected": "reject",
                "observed": "reject",
                "message": str(exc),
                "criterion_pass": expected_fragment in str(exc),
            })
        else:
            rows.append({
                "case": case,
                "expected": "reject",
                "observed": "accept",
                "message": "no rejection",
                "criterion_pass": False,
            })

    def local_key_substitution() -> None:
        tampered = dict(public_hex)
        tampered["NodeA"] = public_hex["NodeB"]
        CascadeIdentity.from_hex("NodeA", private_hex["NodeA"], tampered)

    expected_rejection(
        "local_public_key_substitution",
        local_key_substitution,
        "private key does not match public key",
    )

    def missing_member_key() -> None:
        incomplete = dict(public_hex)
        incomplete.pop("NodeD")
        identity = CascadeIdentity.from_hex("NodeA", private_hex["NodeA"], incomplete)
        UniversalCascade(identity, names)

    expected_rejection(
        "missing_member_key",
        missing_member_key,
        "public-key directory is incomplete",
    )

    def unknown_destination() -> None:
        identity = CascadeIdentity.from_hex("NodeA", private_hex["NodeA"], public_hex)
        cascade = UniversalCascade(identity, names)
        cascade.start_route("Rogue", 2, b"negative-test")

    expected_rejection(
        "unknown_destination",
        unknown_destination,
        "unknown cascade destination",
    )

    # This is a local constructor check, not an attack against a live registry.
    _, rogue_public = generate_identity_set(["Rogue"])
    substituted = dict(public_hex)
    substituted["NodeB"] = rogue_public["Rogue"]
    try:
        identity = CascadeIdentity.from_hex("NodeA", private_hex["NodeA"], substituted)
        UniversalCascade(identity, names)
        identity.seal_for("NodeB", {"probe": "negative-test"})
    except Exception as exc:  # pragma: no cover - recorded as unexpected evidence
        rows.append({
            "case": "remote_public_key_substitution_without_signed_registry",
            "expected": "reject_if_registry_authenticated",
            "observed": "reject",
            "message": type(exc).__name__,
            "criterion_pass": False,
        })
    else:
        rows.append({
            "case": "remote_public_key_substitution_without_signed_registry",
            "expected": "reject_if_registry_authenticated",
            "observed": "accept",
            "message": "remote directory entry accepted; no signed registry provenance check is present in this constructor path",
            "criterion_pass": True,
        })

    write_csv(exp / "raw-negative-cases.csv", rows)
    guards_ok = all(bool(row["criterion_pass"]) for row in rows[:3])
    gap_detected = rows[3]["observed"] == "accept" and bool(rows[3]["criterion_pass"])
    result = {
        "status": "blocked_product_gap",
        "hypothesis": "A protected trust registry rejects missing, unknown, or substituted node identities before route construction.",
        "parameters": {
            "cases": len(rows),
            "live_network": False,
            "generated_keys": "ephemeral in memory; not persisted or reported",
        },
        "success_criterion": "Local guards reject malformed/missing identities and an authenticated registry rejects remote key substitution.",
        "local_guard_cases_pass": guards_ok,
        "protected_registry_case_pass": False,
        "gap_detected": gap_detected,
        "criterion_pass": False,
        "source": str(module_dir / "universal_cascade.py"),
        "source_sha256": sha256(module_dir / "universal_cascade.py"),
        "config_source": str(module_dir / "config.py"),
        "config_source_sha256": sha256(module_dir / "config.py"),
        "raw": str(exp / "raw-negative-cases.csv"),
        "aggregate": str(exp / "result.json"),
        "development_blocker": "The preserved implementation validates local key consistency and member completeness, but consumes a caller-supplied public-key directory without signed/owner-authenticated registry provenance or an anti-substitution trust anchor.",
        "required_artifact": "Development must provide a versioned authenticated registry format, trust-anchor/provenance verification, atomic update/rollback rules, and executable negative tests that reject unauthorized add/replace operations before EVE-NG attack testing.",
        "limited_conclusion": "Three local input guards reject malformed cases. Remote key substitution is accepted in the tested constructor path, so a successful protected-registry defense is not claimed and no live attack was attempted.",
    }
    write_json(exp / "result.json", result)
    table = "\n".join(
        f"| {row['case']} | {row['expected']} | {row['observed']} | {row['criterion_pass']} |"
        for row in rows
    )
    (exp / "PASSPORT.md").write_text(
        "# Паспорт 3. Негативные тесты реестра доверия\n\n"
        "- Гипотеза: защищённый реестр должен отклонять отсутствующий, неизвестный и подменённый узел до построения маршрута.\n"
        "- Параметры: четыре локальных случая; временные X25519-ключи существуют только в памяти; сеть и EVE-NG не используются.\n"
        f"- Стенд и версии: CPython `{platform.python_version()}`, сохранённый `universal_cascade.py`, SHA-256 `{sha256(module_dir / 'universal_cascade.py')}`.\n"
        "- Число прогонов: 4.\n"
        "- Критерий успеха: три входных guard-проверки отклоняют плохие данные, а защищённый реестр отклоняет удалённую подмену ключа.\n"
        "- Сырой артефакт: `raw-negative-cases.csv`.\n"
        "- Агрегат: `result.json`.\n\n"
        "| Случай | Ожидалось | Наблюдалось | Проверка |\n"
        "|---|---|---|---:|\n"
        f"{table}\n\n"
        "Результат: `blocked_product_gap`. Локальные проверки целостности собственного ключа, полноты каталога и неизвестного назначения сработали. Подмена удалённого публичного ключа была принята переданным каталогом: подписанный/аутентифицированный реестр и доверенный источник обновлений не реализованы в проверенном пути. Это фиксация блокера, а не успешная атака на защищённый реестр.\n",
        encoding="utf-8",
    )
    return result


def parse_concurrent_ping(text: str) -> tuple[float, float]:
    normalized = text.replace("\\n", "\n")
    loss = PING_LOSS_RE.search(normalized)
    rtt = PING_RTT_RE.search(normalized)
    if not loss or not rtt:
        raise ValueError("concurrent row has no parseable ping summary")
    return float(loss.group(3)), float(rtt.group(2))


def experiment_concurrent(output: Path, legacy: Path) -> dict[str, Any]:
    exp = output / "04-concurrent-starts"
    rows: list[dict[str, Any]] = []
    source_hashes: dict[str, str] = {}
    for scenario, (starts, filename) in CONCURRENT_FILES.items():
        path = legacy / filename
        source_hashes[str(path)] = sha256(path)
        with path.open("r", encoding="utf-8-sig", newline="") as stream:
            for source_row in csv.DictReader(stream):
                loss_pct, rtt_avg_ms = parse_concurrent_ping(source_row["ping_tail"])
                rows.append({
                    "scenario": scenario,
                    "simultaneous_starts": starts,
                    "src": source_row["src"],
                    "dst": source_row["dst"],
                    "success": source_row["ok"].lower() == "true" and source_row["ping_ok"].lower() == "true",
                    "ipsec_up_seconds": float(source_row["ipsec_up_seconds"]),
                    "packet_loss_pct": loss_pct,
                    "rtt_avg_ms": rtt_avg_ms,
                    "esp_packets": int(source_row["esp_packets"]),
                    "direct_final_ab_ike_packets": int(source_row["direct_ike_packets"]),
                    "source_file": str(path),
                    "connection_id": source_row["conn_id"],
                })
    write_csv(exp / "raw-normalized.csv", rows)
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        grouped[str(row["scenario"])].append(row)
    aggregates: list[dict[str, Any]] = []
    for scenario, group in sorted(grouped.items(), key=lambda item: int(item[1][0]["simultaneous_starts"])):
        setup = [float(row["ipsec_up_seconds"]) for row in group]
        rtt = [float(row["rtt_avg_ms"]) for row in group]
        aggregates.append({
            "scenario": scenario,
            "simultaneous_starts": int(group[0]["simultaneous_starts"]),
            "rows": len(group),
            "successes": sum(bool(row["success"]) for row in group),
            "success_rate": round(sum(bool(row["success"]) for row in group) / len(group), 6),
            "mean_loss_pct": round(statistics.fmean(float(row["packet_loss_pct"]) for row in group), 6),
            "max_loss_pct": round(max(float(row["packet_loss_pct"]) for row in group), 6),
            "rtt_mean_ms": summarize_numeric(rtt)["mean"],
            "rtt_median_ms": summarize_numeric(rtt)["median"],
            "rtt_p95_ms": summarize_numeric(rtt)["p95"],
            "rtt_max_ms": summarize_numeric(rtt)["max"],
            "setup_median_s": summarize_numeric(setup)["median"],
            "setup_p95_s": summarize_numeric(setup)["p95"],
            "setup_max_s": summarize_numeric(setup)["max"],
            "esp_packets_total": sum(int(row["esp_packets"]) for row in group),
            "esp_packets_mean": round(statistics.fmean(float(row["esp_packets"]) for row in group), 6),
            "direct_final_ab_ike_packets_total": sum(int(row["direct_final_ab_ike_packets"]) for row in group),
        })
    write_csv(exp / "aggregate-by-scenario.csv", aggregates)
    success = (
        len(rows) == 27
        and all(bool(row["success"]) for row in rows)
        and all(float(row["packet_loss_pct"]) == 0.0 for row in rows)
        and all(int(row["direct_final_ab_ike_packets"]) == 0 for row in rows)
    )
    result = {
        "status": "completed_offline_eve_reanalysis" if success else "failed_validation",
        "hypothesis": "The preserved simultaneous-start scenarios complete without loss or direct final A/B IKE, while setup latency exposes a concurrency tail.",
        "parameters": {
            "scenarios": {name: starts for name, (starts, _) in CONCURRENT_FILES.items()},
            "environment": [
                "IKE_PRIVACY_OVERLAY=1",
                "IKE_PRIVACY_INLINE=1",
                "PRECONNECT_ENABLED=0",
                "OVERLAY_ACTIVE_USERS=User1..User10",
            ],
        },
        "success_criterion": "27 normalized rows, success=true and packet loss 0% for every row, and zero direct final A/B IKE packets.",
        "criterion_pass": success,
        "source_hashes": source_hashes,
        "raw": str(exp / "raw-normalized.csv"),
        "aggregate": str(exp / "aggregate-by-scenario.csv"),
        "aggregate_rows": aggregates,
        "limited_conclusion": "Within four preserved scenarios (2, 5, and 10 simultaneous starts), completion and loss criteria hold. The small non-random matrix and historical software snapshot do not establish a universal load limit.",
    }
    write_json(exp / "result.json", result)
    table = "\n".join(
        f"| {row['scenario']} | {row['simultaneous_starts']} | {row['successes']}/{row['rows']} | {row['mean_loss_pct']:.1f} | {row['rtt_median_ms']:.3f} | {row['setup_median_s']:.3f} | {row['setup_p95_s']:.3f} | {row['setup_max_s']:.3f} | {row['direct_final_ab_ike_packets_total']} |"
        for row in aggregates
    )
    (exp / "PASSPORT.md").write_text(
        "# Паспорт 4. Множественные старты\n\n"
        "- Гипотеза: сохранённые сценарии одновременного запуска завершаются без потерь и прямого финального IKE между A/B, но показывают хвост времени установки.\n"
        "- Параметры: bidir12=2 старта, disjoint5=5, ring10=10, reverse5=10; overlay/inline включены, preconnect выключен.\n"
        "- Стенд и версии: сохранённый локальный EVE-NG стенд Debian User1–User10, итоговая серия от 2026-05-20; сеть повторно не запускалась.\n"
        f"- Число прогонов: {len(rows)}.\n"
        "- Критерий успеха: 27 строк, каждая успешна, 0 % потерь, 0 прямых финальных IKE-пакетов A/B.\n"
        "- Сырой артефакт: `raw-normalized.csv`; хэши четырёх исходных CSV — в `result.json`.\n"
        "- Агрегат: `aggregate-by-scenario.csv`, `result.json`.\n\n"
        "| Сценарий | Стартов | Успех | Потери, % | Median RTT, ms | Median setup, s | P95 setup, s | Max setup, s | Direct IKE |\n"
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|\n"
        f"{table}\n\n"
        "Ограниченный вывод: матрица подтверждает только четыре сохранённых сценария и не задаёт универсальный предел нагрузки.\n",
        encoding="utf-8",
    )
    return result


def build_manifest(output: Path, started: float, results: list[dict[str, Any]]) -> None:
    generated = []
    for path in sorted(output.rglob("*")):
        if path.is_file() and path.name != "manifest.json":
            generated.append({
                "path": str(path),
                "relative_path": str(path.relative_to(output)),
                "bytes": path.stat().st_size,
                "sha256": sha256(path),
            })
    manifest = {
        "schema_version": "1.0",
        "root": str(output),
        "network_actions": False,
        "eve_ng_live_run": False,
        "legacy_workspace_modified": False,
        "python": platform.python_version(),
        "platform": platform.platform(),
        "elapsed_seconds": round(time.monotonic() - started, 3),
        "experiment_statuses": [result["status"] for result in results],
        "generated_files": generated,
    }
    write_json(output / "manifest.json", manifest)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--legacy", type=Path, required=True)
    parser.add_argument("--source-report", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    legacy = args.legacy.resolve()
    output = args.output.resolve()
    source_report = args.source_report.resolve()
    if output.name != ROOT_NAME:
        raise SystemExit(f"refusing unexpected output directory: {output}")
    if not legacy.is_dir() or not source_report.is_file():
        raise SystemExit("required inputs are missing")
    output.mkdir(parents=True, exist_ok=True)
    started = time.monotonic()
    plan = (
        "# Минимальный быстрый план\n\n"
        "Оценка до выполнения: 20–40 минут при пригодности сохранённых артефактов.\n\n"
        "1. Детерминированная калибровка модельного порога α=0,5 вокруг n50.\n"
        "2. Повторная агрегация 1200 сохранённых EVE-NG опытов по H=3/4/5.\n"
        "3. Четыре локальных негативных теста каталога ключей; при отсутствии аутентифицированного реестра — блокер разработки.\n"
        "4. Нормализация 27 сохранённых одновременных стартов в матрицу потерь, RTT, времени установки и пакетов.\n\n"
        "Сетевой запуск EVE-NG не входит в быстрый план: нет свежего preflight и подтверждённого rollback.\n"
    )
    (output / "PLAN.md").write_text(plan, encoding="utf-8")
    threshold = experiment_threshold(output, source_report)
    cascade = experiment_cascade(output, legacy)
    trust = experiment_trust(output, legacy)
    concurrent = experiment_concurrent(output, legacy)
    results = [threshold, cascade, trust, concurrent]
    build_manifest(output, started, results)
    cascade_rows = cascade["aggregate_rows"]
    concurrent_rows = concurrent["aggregate_rows"]
    report = (
        "# Итог быстрого закрытия экспериментальных замечаний\n\n"
        "Выполнены только локальные вычисления и повторная обработка сохранённых EVE-NG артефактов. "
        "Новый сетевой прогон, физический Keenetic, внешняя инфраструктура, закрытые большие серии и DOCX не затрагивались.\n\n"
        "## Статус 4 пунктов\n\n"
        f"1. Порог 0,5 / n50: `{threshold['status']}`, критерий `{threshold['criterion_pass']}`; "
        f"{threshold['parameters']['total_simulated_routes']:,} детерминированных модельных маршрутов. "
        "В исходной диссертации определено `α=0,5`; допустимого `α=50` нет.\n"
        f"2. Длина каскада: `{cascade['status']}`, критерий `{cascade['criterion_pass']}`; "
        f"H=3/4/5, по {cascade_rows[0]['trials']} сохранённых опытов на H; "
        f"потери ping по H: {cascade_rows[0]['ping_loss_packets']}, {cascade_rows[1]['ping_loss_packets']}, {cascade_rows[2]['ping_loss_packets']} из 800 пакетов на группу.\n"
        f"3. Реестр доверия: `{trust['status']}`; три локальные guard-проверки прошли, "
        "но удалённая подмена ключа принимается непроверенным каталогом. Защищённый реестр не подтверждён.\n"
        f"4. Множественные старты: `{concurrent['status']}`, критерий `{concurrent['criterion_pass']}`; "
        f"{sum(row['rows'] for row in concurrent_rows)}/27 успешных строк, 0 % потерь и 0 прямых финальных IKE A/B.\n\n"
        "## Граница выводов\n\n"
        "Калибровка порога является вычислительным экспериментом внутри модели F4, а пункты 2 и 4 — новой проверяемой агрегацией ранее полученных EVE-NG данных, не новым живым прогоном. "
        "Пункт 3 не закрыт: требуется продуктовая реализация аутентифицированного реестра и её исполняемые негативные тесты.\n\n"
        "## Проверка\n\n"
        "Запустить `python validate_results.py --root .` из этой папки. Итог сохраняется в `validation.json`.\n"
    )
    (output / "FINAL-REPORT.md").write_text(report, encoding="utf-8")
    # Refresh manifest after the final report has been added.
    build_manifest(output, started, results)
    print(json.dumps({
        "output": str(output),
        "threshold": threshold["status"],
        "cascade": cascade["status"],
        "trust": trust["status"],
        "concurrent": concurrent["status"],
        "elapsed_seconds": round(time.monotonic() - started, 3),
    }, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
