"""Pure checks reused by the clone controller and offline report."""
import json
import math
import statistics
from legacy_checks import normalize_config

CONFIG_KEYS = ('queues', 'types', 'tree_config', 'simple_config')

def canonical(item):
    assert not item.get('error') and item.get('license_level') == 'p-unlimited'
    result = {k: normalize_config(item['commands'][k]) for k in CONFIG_KEYS}
    # active-queue is derived runtime state, not configured interface queue.
    result['queues'] = sorted([sorted((k, v) for k, v in row if k != 'active-queue') for row in result['queues']])
    return json.loads(json.dumps(result))

def verify_queues(snapshot, expected):
    assert set(snapshot) == set(expected), 'Router inventory differs from sealed baseline'
    for nid, value in snapshot.items():
        assert canonical(value) == expected[nid], 'Queue configuration drift on router ' + nid
    return {'passed': True, 'routers': len(snapshot), 'queue_changes': 0, 'max_limit_unchanged': True}

def describe(values):
    assert all(isinstance(x, (int, float)) and math.isfinite(x) and x >= 0 for x in values)
    if not values:
        return {'n': 0, 'median_s': None, 'p95_s': None, 'min_s': None, 'max_s': None}
    return {'n': len(values), 'median_s': statistics.median(values),
            'p95_s': statistics.quantiles(values, n=100, method='inclusive')[94] if len(values) >= 2 else values[0],
            'min_s': min(values), 'max_s': max(values)}

def summarize(results, planned=100):
    ids = [v['attempt']['id'] for v in results]
    assert len(ids) == len(set(ids)), 'Duplicate result'
    good = [v for v in results if v['success']]
    pairs = {}
    for value in results:
        attempt = value['attempt']; key = attempt['initiator'] + '→' + attempt['receiver']
        pairs.setdefault(key, []).append(value)
    return {'planned': planned, 'completed': len(results), 'successful': len(good),
            'failed': len(results) - len(good), 'timeouts': sum(v['up'].get('timeout', False) for v in results),
            'native_successful': describe([v['up']['elapsed_seconds'] for v in good]),
            'ssh_successful': describe([v['ssh_elapsed_s'] for v in good]),
            'all_attempt_elapsed': describe([v['up']['elapsed_seconds'] for v in results]),
            'percentile_method': 'statistics.quantiles(n=100, method=inclusive); linear at (n-1)*0.95',
            'population_p95_claimed': False,
            'empirical_p95_qualified': len(good) >= 95 and len(results) == planned,
            'unconditional_p95_censored': sum(v['up'].get('timeout', False) for v in results) > 0.05 * planned,
            'pairs': {k: {'completed': len(rows), 'successful': sum(v['success'] for v in rows),
                          'native_successful': describe([v['up']['elapsed_seconds'] for v in rows if v['success']]),
                          'pair_p95_qualified': False} for k, rows in sorted(pairs.items())}}
