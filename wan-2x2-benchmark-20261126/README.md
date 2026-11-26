# Live 4-Node Geo-Distributed WAN Verification (`2×2` Factorial Matrix, Dual NAT)

This experiment suite archives the anonymized dataset, comparative analysis, and zero-dependency `pcap` verification utility for the live 4-node geographically distributed WAN benchmark comparing all four cells of the **`{Python, Rust} × {IPsec, WireGuard}`** matrix under identical dual-NAT network conditions.

## Related Implementations

- **Rust workspace (IPsec + Userspace WireGuard `boringtun`):** [`Adaptive-Secure-Overlay/cascade-control-overlay`](https://github.com/Adaptive-Secure-Overlay/cascade-control-overlay) (`docs/BENCHMARKS.md`, Section 6)
- **Python IPsec core + Dual-NAT Docker adapter + `notrack` fix:** [`Adaptive-Secure-Overlay/adaptive-ipsec-overlay`](https://github.com/Adaptive-Secure-Overlay/adaptive-ipsec-overlay) (`platforms/linux/docker-wan-nat/`, `scripts/ike_proxy_nft_apply.sh`)
- **Python WireGuard MCC + Linux Kernel `wg0` backend:** [`Adaptive-Secure-Overlay/adaptive-wireguard-overlay`](https://github.com/Adaptive-Secure-Overlay/adaptive-wireguard-overlay) (`linux-kernel-wg-backend/`)

## Anonymized 4-Node WAN Topology & Methodology

All four configurations were executed on the **exact same 4 physical/virtual WAN hosts** using isolated Docker Compose stacks (Python relays bound to `UDP/19001` in parallel with Rust relays on `UDP/19000`; zero modifications to host routing tables or existing services):

- **Logical path:** `Node A` (behind residential NAT) `->` `Node X1` (City-1 public relay) `->` `Node X2` (City-2 public relay) `->` `Node B` (City-3 behind NAT router with UDP port forwarding).
- **Measured underlay RTT baseline:** `A <-> X1` `8.7 ms`, `X1 <-> X2` `11.1–12.2 ms`, `X2 <-> B` `21.9 ms`, direct `A <-> B` `~21–25 ms`.
- **Shared cryptographic & MCC profile:** Ed25519 signed `Trust Registry v2`, X25519 + HKDF-SHA256 + AES-256-GCM MCC capsules (`mode=first`, `x1=2, x2=2, ike=1`), authenticated NAT endpoint roaming, `nftables` `output_raw` `notrack` rules for direct data-plane packets, and host-interface `tcpdump -i any` captures at both endpoints `A` and `B`.
- **Privacy & sanitization:** All real IP addresses, hostnames, cities, ISPs, and secret keys are strictly omitted. Documentation templates use RFC 5737 addresses (`192.0.2.x`, `198.51.100.x`, `203.0.113.x`).

## Full `2×2` WAN Comparison Table (`results.json`)

| Metric (Same 4-Node Dual-NAT WAN) | Python + Kernel IPsec (`CPython 3.14.10` + `strongSwan 6.0.1`) | Python + Kernel WG (`CPython 3.14.10` + Linux `wg0`) | Rust + Kernel IPsec (`cco` + `strongSwan 5.9.8`) | 100% Rust Userspace WG (`cco wg-tunnel` / `boringtun 0.7.1`) |
| :--- | :---: | :---: | :---: | :---: |
| Control plane over MCC (`A -> X1 -> X2 -> B`) | IKEv2 (`500`/`4500` Non-ESP) + `PRIV_BKEY` | WG `Type 1/2/3` + `PRIV_BKEY` | IKEv2 (`500`/`4500` Non-ESP) | WG `Noise_IKpsk2` (`Type 1/2/3`) |
| Data plane direct (`A <-> B`) | Kernel XFRM `ESP-in-UDP` (`4500`) | Kernel `wg0` `Type 4` (`4500`) | Kernel XFRM `ESP-in-UDP` (`4500`) | Userspace `boringtun` `Type 4` (`4500`) |
| Container privileges / runtime stack | `CPython` + `strongSwan` + `nftables` + `NET_ADMIN`/`NET_RAW` | `CPython` + kernel `wg.ko` + `nftables` + `NET_ADMIN`/`NET_RAW` | `cco` + `strongSwan` + `nftables` + `NET_ADMIN`/`NET_RAW` | **Single `cco` binary + `/dev/net/tun` (`NET_ADMIN`, zero `nftables`)** |
| Container image size (relay / endpoint) | `217 MB` / `247 MB` | `217 MB` / `248 MB` | `150 MB` / `159 MB` | `150 MB` / **`151 MB`** |
| Peak overlay RAM (`VmHWM`, relay / endpoint) | `41.9–42.3 MB` / `41.1–43.1 MB` (`+ 9.4–11.2 MB charon`) | `41.9–42.3 MB` / `41.7–42.4 MB` | **`8.46–8.74 MB`** / **`9.40–10.33 MB`** (`+ 10.6–10.8 MB charon`) | **`2.57–4.94 MiB`** total (**no `charon`**, `8.5–16×` less RAM) |
| **Cold start** (`PRECONNECT=0`, lazy `MGMT`) | `36,109.8 ms` (`36.1 s` — sync `recv` self-deadlock) | Requires `PRECONNECT=1` (same sync `recv` loop) | **`529.0 ms`** (`68.3×` faster than Python) | **`128.0 ms`** (**`4.1×` faster** than Rust IPsec, 1-RTT) |
| **Warm start** (`MGMT` sessions ready) | `234.6 / 247.5 / 354.0 ms` (median `247.5 ms`, 3-hop) | `~146 ms` (`167.243 ms` incl. 1st `Type 4` ICMP reply) | `316.2 / 336.5 ms` (4-hop, 2-RTT IKEv2) | **`128.0 ms`** (4-hop, 1-RTT `Noise_IKpsk2`) |
| Overlay UDP packets / handshake (`A` host capture) | `~546 pkts` (`1,638` / 3 runs; `PRIV_BKEY` + `LINK_FRAG`) | `354 pkts` (`168` `X1` + `186` `X2`; `PRIV_BKEY`) | **`~112 pkts`** (`4.9×` fewer than Python IPsec) | **`~188 pkts`** (`1.9×` fewer than Python WG) |
| Direct control leakage (`tcpdump` on `A` & `B`) | **`0`** (`500=0`, `4500 Non-ESP=0`, `OV_AB=0`) | **`0`** (`Type 1/2/3 = 0`, `OV_AB=0`) | **`0`** (`500=0`, `4500 Non-ESP=0`) | **`0`** (`Type 1/2/3 = 0`) |
| Steady-state tunnel ICMP RTT (10 probes, `0%` loss) | `23.10 / 23.94 / 24.43 ms` | **`20.65 / 21.03 / 21.76 ms`** | `23.38 / 24.46 / 31.63 ms` | `23.58 / 25.45 / 29.82 ms` |
| `iperf3` TCP 1-stream `A -> B` (`10 s`, recv / send) | `70.8 / 72.8 Mbps` | **`71.1 / 73.1 Mbps`** | `70.1 / 71.9 Mbps` | `67.1 / 69.7 Mbps` |
| `iperf3` TCP 4-streams `A -> B` (`10 s`, recv / send) | `71.0 / 72.6 Mbps` | **`71.9 / 74.1 Mbps`** | `69.2 / 70.8 Mbps` | `70.3 / 72.9 Mbps` (`97.8%` of kernel `wg0`) |
| `iperf3` TCP 4-streams reverse `B -> A` (`10 s`, recv / send) | `87.3 / 90.8 Mbps` | **`88.0 / 91.2 Mbps`** | `86.6 / 89.3 Mbps` | `86.0 / 88.6 Mbps` (`97.7%` of kernel `wg0`) |
| Encrypted payload transferred during throughput run | `> 307.8 MB` (`314,050` ESP pkts) | `> 306.3 MiB` (`wg0` `Type 4`) | `> 301 MB` (`305,157` ESP pkts) | `> 309 MB` (`307,975` `Type 4` pkts) |
| Live rekey over MCC overlay (under continuous ping) | `CHILD 132.4 ms`, `IKE 88.4 ms` (3-hop) | Auto `121 s` PFS rekey | `CHILD 203.7–275.2 ms`, `IKE 111.9–258.1 ms` (4-hop) | Auto `120 s` PFS rekey (4-hop) |
| Packet loss during live rekey | **`0 / 40` (`0.0%`)**, avg `24.10 ms` | **`0 / 75` (`0.0%`)**, avg `21.13 ms` | **`0 / 40` (`0.0%`)**, avg `23.66 ms` | **`0 / 62` (`0.0%`)**, avg `24.60 ms` |
| Direct control leakage during live rekey (`tcpdump`) | **`0`** (`240` direct ESP pkts) | **`0`** (`453` direct `Type 4` pkts) | **`0`** (`80` direct ESP pkts) | **`0`** (`132` direct `Type 4` pkts) |

## Same-VPS Cryptographic Microbenchmark (`City-2`, Linux x86_64, `200` Iterations)

| Primitive / Operation | Python (`CPython 3.14.10` + `cryptography 50.0.2`) | Rust (`cco`, `--release`) | Rust Speedup |
| :--- | :---: | :---: | :---: |
| `Ed25519` sign + verify | `244.1 µs` (`64.08 + 180.02 µs`) | **`130.2 µs`** | **`1.87×`** |
| `X25519 + HKDF-SHA256 + AES-256-GCM` capsule (seal + open) | `589.1 µs` (`228.14 + 361.0 µs`) | **`201.2 µs`** | **`2.93×`** |
| Python `mcc_signed_message` / `mcc_verify_signed` | `342.7 µs` / `562.35 µs` | — | — |
| Python durable SQLite anti-replay (`3-tx` commit) | `9.64 ms` (p95 `19.25 ms`) | — | — |

## Five Engineering Conclusions

1. **Cold-start self-deadlock in synchronous Python (`36.1 s` vs `529 ms` in Rust):** The single-threaded `serve_forever()` receive loop in Python blocks inside `handle_MCC_START() -> ensure_session().wait(2.0)` when `PRECONNECT_ENABLED=0`, stalling the same loop that must read `MGMT_INIT_RESP` (`68.3×` slower than Rust). Python IPsec and Python WireGuard therefore require `PRECONNECT_ENABLED=1` ($O(N^2)$ background mesh), while Rust `tokio` handles lazy on-demand sessions natively in `529 ms` (IPsec) / `128 ms` (WireGuard).
2. **`4.2–16×` lower peak RAM and `1.9–4.9×` fewer relay packets in Rust:** Peak overlay RSS drops from `41.1–43.1 MB` (Python) to `8.46–10.33 MB` (Rust IPsec) and `2.57–4.94 MiB` total (userspace Rust WireGuard without `charon`). Eliminating Python's legacy `PRIV_BKEY` locator round-trip reduces per-handshake overlay packets from `~546` to `~112` (IPsec) and `354` to `~188` (WireGuard).
3. **1-RTT WireGuard converges `2–4×` faster than 2-RTT IKEv2 in both languages:** Standard IKEv2 requires two sequential round-trips (`IKE_SA_INIT` + `IKE_AUTH`) before kernel XFRM installs `CHILD_SA`, whereas WireGuard `Noise_IKpsk2` completes in 1 RTT (`~146 ms` warm Python + `wg0`; **`128.0 ms`** Rust `boringtun`). Single-RTT IKEv2 `CREATE_CHILD_SA` rekey matches WireGuard's 1-RTT latency (`88.4–203.7 ms`).
4. **Userspace Rust `boringtun` reaches `97.7–97.8%` of native kernel `wg0` WAN throughput:** `70.3 / 86.0 Mbps` vs `71.9 / 88.0 Mbps` on the exact same WAN link while eliminating `wireguard.ko`, `strongSwan`, `nftables`, and `CAP_NET_RAW`.
5. **Zero-loss live PFS rekeying & Dual-NAT `notrack` rule:** All 4 cells rotated keys under continuous ping with `0.0%` loss (`40/40`, `75/75`, `40/40`, `62/62`) and `0` direct control packets, enabled on kernel backends by `nftables` `output_raw` `notrack` rules for direct `ESP-in-UDP` and `WireGuard Type 4`.

## Follow-Up Live WAN `m`-Hop Scaling (`UniversalCascade` `F4`, `K = 2`, `m = 3, 5, 10`)

Using the same 4-node Dual-NAT WAN testbed and constant `3,584 B` padded `CASCADE_*` frames (Rust `cco`), `UniversalCascade` (`--route-mode cascade --hop-model f4 --parallel-chains 2`) was verified across `m = 3, 5, 10` hops:

| Protocol (`F4`, `K = 2`) | `m` | Handshake Latency | Tunnel Ping (`0%` loss) | `iperf3` 4-Stream (`A->B` / `B->A`, recv) | Direct Control (`tcpdump` A & B) | Peak RAM (`VmHWM`) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| Rust Userspace WG (`boringtun`) | `3` | **`192 ms`** | `23.93 ms` (`10/10`) | — | **`0`** (`T1/T2/T3 = 0`) | `9.09 MiB` |
| Rust Userspace WG (`boringtun`) | `5` | **`152 ms`** *(1st try; `5.3 s` w/ 1 retry)* | `24.58 ms` (`10/10`) | — | **`0`** (`T1/T2/T3 = 0`) | `8.57 MiB` |
| Rust Userspace WG (`boringtun`) | `10` | **`566 ms`** *(1st try)* | `24.41 ms` (`10/10`) | **`69.2 / 87.3 Mbps`** (`214,207` `T4` pkts) | **`0`** (`T1/T2/T3 = 0`) | `8.95 MiB` |
| Rust + Kernel IPsec (`strongSwan`) | `3` | `1,472 ms` (cold, `--no-preconnect`) | `24.00 ms` (`5/5`) | — | **`0`** (`ike500=0`, `ov_ab=0`) | `9.24 MiB` |
| Rust + Kernel IPsec (`strongSwan`) | `5` | **`~185 ms`** (warm, `prerouting_raw` fix) | `0%` loss | — | **`0`** (`ike500=0`, `ike4500=0`, `ov_ab=0`) | `8.67 MiB` |
| Rust + Kernel IPsec (`strongSwan`) | `10` | 1st RTT ok; 2nd RTT hit `11`-frag/hop UDP loss | — | — | **`0`** (`ike500=0`, `ike4500=0`, `ov_ab=0`) | `8.50 MiB` |

## Reproducible `pcap` Audit Utility (`audit_wan_pcap.py`)

`audit_wan_pcap.py` parses standard `pcap` captures (Ethernet `DLT=1`, Linux SLL v1 `DLT=113`, Linux SLL v2 `DLT=276` produced by `tcpdump -i any`, and Raw IPv4 `DLT=101`) using only Python's standard library and exits with code `0` iff zero direct control-plane packets and zero direct overlay `A <-> B` packets are present.

```bash
# Audit an IPsec capture (RFC 5737 example endpoints)
python3 audit_wan_pcap.py --pcap capture.pcap --mode ipsec \
  --endpoint-a 192.0.2.10 --endpoint-b 192.0.2.13 --overlay-port 19000 --json

# Audit a WireGuard capture
python3 audit_wan_pcap.py --pcap capture.pcap --mode wg \
  --endpoint-a 192.0.2.10 --endpoint-b 192.0.2.13 --wg-port 4500 --overlay-port 19001 --json

# Run unit tests for Ethernet, Linux SLL v1, and Linux SLL v2 captures
python3 -m unittest discover -s . -p "test_*.py" -v
```
