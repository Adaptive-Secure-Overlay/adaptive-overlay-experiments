# WireGuard EVE-NG testing gate

This is the accepted test-owned, local-only orchestration layer for the
WireGuard reference package. It does not implement or execute kernel capture,
packet injection, nftables, SSH, VM lifecycle, or the product backend.

The harness is fail-closed. A real EVE-NG baseline, smoke, or 27-case matrix
cannot start until Development supplies a complete backend manifest, the lab
owner supplies verified rollback evidence, and a fresh live preflight passes.

## Accepted commands

Run from `.\Testing-EVE-NG\wireguard-eve`:

```powershell
python .\harness.py plan
python .\harness.py init --checkpoint .\runs\STAMP\checkpoint.json --preflight .\runs\STAMP\preflight.json
python .\safe_gate.py --checkpoint .\runs\STAMP\checkpoint.json --manifest C:\path\to\real-backend-manifest.json
python .\harness.py status --checkpoint .\runs\STAMP\checkpoint.json
python .\harness.py accept --result .\runs\STAMP\results\CASE.json
python .\harness.py record --checkpoint .\runs\STAMP\checkpoint.json --result .\runs\STAMP\results\CASE.json
```

Do not call the lower-level `harness.py gate` command. The accepted
`safe_gate.py` combines product-manifest validation with fresh live-preflight
checks. All accepted commands perform local file operations only; none starts a
backend or contacts EVE-NG.

`record` accepts only a passing canonical result, stores its relative path and
SHA-256, is idempotent for an identical result, rejects conflicts, and atomically
advances the checkpoint to `completed` only after all 27 distinct cases.

The supplied `backend-manifest.example.json` is deliberately invalid and must
produce a `blocked` checkpoint.

## Required handoff from Development

The real manifest must contain no keys, credentials, PSK, payloads, or full
configuration material. It must provide:

- an existing executable backend artifact, version, and matching SHA-256;
- ten existing endpoint configuration references for `n1..n10`;
- exact isolated EVE inventory for endpoints `n1..n10` and relays `x1,x2`;
- proof of daemon binding to `send_protocol_datagram` and
  `deliver_protocol_datagram` for protocol `wireguard`;
- concrete namespace, interface, UDP ports, and an existing scope-proof file;
- capture, inject, tuple-preservation, type-4 bypass, event, redaction, and
  loop-prevention capabilities;
- original-state snapshot, scope proof, restore procedure, rollback verification
  evidence, and an ISO-8601 verification timestamp.

Paths must be absolute, existing, non-empty, and non-placeholder. The gate
checks them but never executes the backend or rollback procedure.

## Fresh live-preflight contract

The evidence referenced by a checkpoint must be no older than 24 hours and
must confirm:

- zero matching local and remote runners;
- running EVE VM and reachable SSH;
- `/dev/kvm` ready and positive remote free space;
- selected isolated nodes ready;
- `decision.state=ready` and no credential-pattern material.

## Result acceptance

Each result must match the package `eve-result.schema.json`, one exact canonical
case identity, and all EVE-NG test criteria:

- activation code `0`, fresh handshake, successful ping;
- at least two WG data packets and zero direct WG control packets;
- four distinct hops `src -> x1 -> x2 -> dst` and confirmed reverse route;
- exact type 1/2/3 event chain
  `CAPTURE -> ROUTE_READY -> SEND -> ARRIVE -> INJECT`;
- type 4 represented only by `DIRECT` / `DIRECT_BYPASS` semantics;
- nonnegative timing metrics and confirmed redaction;
- no unexpected JSON properties or credential-pattern material.

## Current stop condition

The reference package contains an in-memory adapter and a non-executable
nftables design template, but no executable capture/inject backend, real
endpoint configuration, EVE inventory, daemon binding, or verified rollback.
The current checkpoint therefore remains `blocked` at `0/27`.
