#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Zero-dependency pcap auditor for Adaptive Secure Overlay WAN captures.

Supports standard libpcap files in Ethernet (DLT=1), Raw IPv4 (DLT=101),
Linux cooked SLL v1 (DLT=113), and Linux cooked SLL v2 (DLT=276, default for
`tcpdump -i any` on modern kernels).

Verifies two core security invariants on host captures:
1. Direct control-plane leakage between endpoints A and B is strictly zero:
   - IPsec mode: UDP/500 == 0 and UDP/4500 Non-ESP (4 zero bytes) == 0.
   - WireGuard mode: WireGuard handshake Type 1/2/3 == 0.
2. Direct overlay A <-> B UDP traffic on --overlay-port is strictly zero
   (control plane must traverse intermediate relays X1 / X2).
"""

from __future__ import annotations

import argparse
import json
import socket
import struct
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterator, Optional, Tuple

PCAP_MAGICS = {
    0xA1B2C3D4: "<",
    0xD4C3B2A1: ">",
    0xA1B23C4D: "<",  # nanosecond pcap
    0x4D3CB2A1: ">",
}

DLT_EN10MB = 1
DLT_RAW = 101
DLT_LINUX_SLL = 113
DLT_LINUX_SLL2 = 276

ETH_P_IP = 0x0800
ETH_P_8021Q = 0x8100
ETH_P_8021AD = 0x88A8

IPPROTO_UDP = 17
IPPROTO_ESP = 50

WG_TYPE_INITIATION = 1
WG_TYPE_RESPONSE = 2
WG_TYPE_COOKIE = 3
WG_TYPE_TRANSPORT = 4


@dataclass
class AuditReport:
    pcap: str
    mode: str
    linktype: int
    total_frames: int = 0
    ipv4_packets: int = 0
    direct_ike_500: int = 0
    direct_ike_4500_nonesp: int = 0
    direct_esp_in_udp_4500: int = 0
    direct_natt_keepalive_4500: int = 0
    direct_esp_proto50: int = 0
    direct_wg_type1: int = 0
    direct_wg_type2: int = 0
    direct_wg_type3: int = 0
    direct_wg_type4: int = 0
    direct_overlay_ab: int = 0
    relayed_overlay_packets: int = 0

    @property
    def direct_control_leakage(self) -> int:
        if self.mode == "ipsec":
            return self.direct_ike_500 + self.direct_ike_4500_nonesp
        return self.direct_wg_type1 + self.direct_wg_type2 + self.direct_wg_type3

    @property
    def direct_data_packets(self) -> int:
        if self.mode == "ipsec":
            return self.direct_esp_in_udp_4500 + self.direct_esp_proto50
        return self.direct_wg_type4

    @property
    def passed(self) -> bool:
        return self.direct_control_leakage == 0 and self.direct_overlay_ab == 0

    def to_dict(self) -> dict:
        data = asdict(self)
        data["direct_control_leakage"] = self.direct_control_leakage
        data["direct_data_packets"] = self.direct_data_packets
        data["passed"] = self.passed
        return data


def _extract_ipv4_payload(linktype: int, frame: bytes) -> Optional[bytes]:
    if linktype == DLT_EN10MB:
        if len(frame) < 14:
            return None
        ethertype = struct.unpack_from("!H", frame, 12)[0]
        offset = 14
        while ethertype in (ETH_P_8021Q, ETH_P_8021AD):
            if len(frame) < offset + 4:
                return None
            ethertype = struct.unpack_from("!H", frame, offset + 2)[0]
            offset += 4
        if ethertype != ETH_P_IP:
            return None
        return frame[offset:]

    if linktype == DLT_LINUX_SLL:
        if len(frame) < 16:
            return None
        proto = struct.unpack_from("!H", frame, 14)[0]
        if proto != ETH_P_IP:
            return None
        return frame[16:]

    if linktype == DLT_LINUX_SLL2:
        if len(frame) < 20:
            return None
        proto = struct.unpack_from("!H", frame, 0)[0]
        if proto != ETH_P_IP:
            return None
        return frame[20:]

    if linktype == DLT_RAW:
        if len(frame) < 20 or (frame[0] >> 4) != 4:
            return None
        return frame

    return None


def iter_pcap_frames(path: Path) -> Tuple[int, Iterator[bytes]]:
    raw = path.read_bytes()
    if len(raw) < 24:
        raise ValueError(f"pcap file too short ({len(raw)} bytes): {path}")

    magic = struct.unpack_from("<I", raw, 0)[0]
    endian = PCAP_MAGICS.get(magic)
    if endian is None:
        raise ValueError(f"unsupported pcap magic 0x{magic:08x} (pcapng not supported directly)")

    _ver_maj, _ver_min, _thiszone, _sigfigs, _snaplen, linktype = struct.unpack_from(
        f"{endian}HHiiii", raw, 4
    )

    def _gen() -> Iterator[bytes]:
        offset = 24
        total = len(raw)
        while offset + 16 <= total:
            _ts_sec, _ts_usec, incl_len, _orig_len = struct.unpack_from(
                f"{endian}IIII", raw, offset
            )
            offset += 16
            if offset + incl_len > total:
                break
            yield raw[offset:offset + incl_len]
            offset += incl_len

    return int(linktype), _gen()


def _parse_ipv4(ip_bytes: bytes) -> Optional[Tuple[int, str, str, bytes]]:
    if len(ip_bytes) < 20:
        return None
    ver_ihl = ip_bytes[0]
    if (ver_ihl >> 4) != 4:
        return None
    ihl = (ver_ihl & 0x0F) * 4
    if ihl < 20 or len(ip_bytes) < ihl:
        return None
    total_len = struct.unpack_from("!H", ip_bytes, 2)[0]
    if total_len < ihl:
        return None
    proto = ip_bytes[9]
    src_ip = socket.inet_ntoa(ip_bytes[12:16])
    dst_ip = socket.inet_ntoa(ip_bytes[16:20])
    payload = ip_bytes[ihl:min(len(ip_bytes), total_len)]
    return proto, src_ip, dst_ip, payload


def audit_pcap(
    pcap_path: Path,
    mode: str,
    endpoint_a: str,
    endpoint_b: str,
    overlay_port: int = 19000,
    wg_port: int = 4500,
) -> AuditReport:
    if mode not in ("ipsec", "wg"):
        raise ValueError(f"unsupported mode {mode!r}; expected 'ipsec' or 'wg'")

    linktype, frames = iter_pcap_frames(pcap_path)
    report = AuditReport(pcap=str(pcap_path), mode=mode, linktype=linktype)
    direct_pair = {endpoint_a, endpoint_b}

    for frame in frames:
        report.total_frames += 1
        ip_bytes = _extract_ipv4_payload(linktype, frame)
        if ip_bytes is None:
            continue
        parsed = _parse_ipv4(ip_bytes)
        if parsed is None:
            continue
        report.ipv4_packets += 1
        proto, src_ip, dst_ip, l4 = parsed
        is_direct_ab = {src_ip, dst_ip} == direct_pair

        if proto == IPPROTO_ESP:
            if is_direct_ab:
                report.direct_esp_proto50 += 1
            continue

        if proto != IPPROTO_UDP or len(l4) < 8:
            continue

        src_port, dst_port, udp_len, _cksum = struct.unpack_from("!HHHH", l4, 0)
        udp_payload = l4[8:min(len(l4), udp_len)] if udp_len >= 8 else l4[8:]

        if overlay_port > 0 and (src_port == overlay_port or dst_port == overlay_port):
            if is_direct_ab:
                report.direct_overlay_ab += 1
            else:
                report.relayed_overlay_packets += 1

        if not is_direct_ab:
            continue

        if mode == "ipsec":
            if src_port == 500 or dst_port == 500:
                report.direct_ike_500 += 1
            elif src_port == 4500 or dst_port == 4500:
                if len(udp_payload) == 1 and udp_payload == b"\xff":
                    report.direct_natt_keepalive_4500 += 1
                elif len(udp_payload) >= 4 and udp_payload[:4] == b"\x00\x00\x00\x00":
                    report.direct_ike_4500_nonesp += 1
                elif len(udp_payload) >= 4:
                    report.direct_esp_in_udp_4500 += 1
        else:
            if src_port == wg_port or dst_port == wg_port:
                if len(udp_payload) >= 4 and udp_payload[1:4] == b"\x00\x00\x00":
                    msg_type = udp_payload[0]
                    if msg_type == WG_TYPE_INITIATION and len(udp_payload) == 148:
                        report.direct_wg_type1 += 1
                    elif msg_type == WG_TYPE_RESPONSE and len(udp_payload) == 92:
                        report.direct_wg_type2 += 1
                    elif msg_type == WG_TYPE_COOKIE and len(udp_payload) == 64:
                        report.direct_wg_type3 += 1
                    elif msg_type == WG_TYPE_TRANSPORT and len(udp_payload) >= 32:
                        report.direct_wg_type4 += 1

    return report


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(
        description="Audit host-interface pcap captures for zero direct control-plane leakage."
    )
    ap.add_argument("--pcap", required=True, help="Path to libpcap (.pcap) file")
    ap.add_argument("--mode", required=True, choices=("ipsec", "wg"))
    ap.add_argument("--endpoint-a", required=True, help="IPv4 address of Endpoint A")
    ap.add_argument("--endpoint-b", required=True, help="IPv4 address of Endpoint B")
    ap.add_argument("--overlay-port", type=int, default=19000, help="Overlay UDP port (default: 19000)")
    ap.add_argument("--wg-port", type=int, default=4500, help="WireGuard UDP port (default: 4500)")
    ap.add_argument("--json", action="store_true", help="Print machine-readable JSON output")
    args = ap.parse_args(argv)

    report = audit_pcap(
        pcap_path=Path(args.pcap),
        mode=args.mode,
        endpoint_a=args.endpoint_a,
        endpoint_b=args.endpoint_b,
        overlay_port=args.overlay_port,
        wg_port=args.wg_port,
    )
    if args.json:
        print(json.dumps(report.to_dict(), indent=2, sort_keys=True))
    else:
        status = "PASS" if report.passed else "FAIL"
        print(
            f"[{status}] mode={report.mode} linktype={report.linktype} "
            f"frames={report.total_frames} direct_control={report.direct_control_leakage} "
            f"direct_overlay_ab={report.direct_overlay_ab} "
            f"relayed_overlay={report.relayed_overlay_packets} "
            f"direct_data={report.direct_data_packets}"
        )
    return 0 if report.passed else 2


if __name__ == "__main__":
    raise SystemExit(main())
