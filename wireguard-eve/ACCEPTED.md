# Accepted entrypoints

Use these files as one fail-closed unit:

- `harness.py` for `plan`, `init`, `status`, `accept`, and `record`;
- `safe_gate.py` for the backend gate.

Do not call `harness.py gate` directly. That lower-level library command checks
the product manifest but does not enforce live-preflight freshness. The accepted
`safe_gate.py` adds the mandatory checks: no second runner, running EVE VM,
reachable SSH, available `/dev/kvm`, positive remote free space, ready selected
nodes, no remote runner, a fresh timestamp, and `decision.state=ready`.

The current run remains blocked because both the live-preflight and product
backend gates fail. No entrypoint executes EVE, SSH, a backend, or rollback.
