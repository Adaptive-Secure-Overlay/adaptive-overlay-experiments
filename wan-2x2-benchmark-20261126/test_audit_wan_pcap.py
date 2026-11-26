# -*- coding: utf-8 -*-
"""Unit tests for the zero-dependency WAN pcap auditor (Ethernet, SLL v1, SLL v2)."""

from __future__ import annotations

import json
import socket
import struct
import tempfile
import unittest
from pathlib import Path

from audit_wan_pcap import (
    DLT_EN10MB,
    DLT_LINUX_SLL,
    DLT_LINUX_SLL2,
    IPPROTO_ESP,
    IPPROTO_UDP,
    audit_pcap,
    main,
)

ENDPOINT_A = "192.0.2.10"
RELAY_X1 = "192.0.2.11"
ENDPOINT_B = "192.0.2.13"


def _build_ipv4_packet(src_ip: str, dst_ip: str, proto: int, payload: bytes) -> bytes:
    total_len = 20 + len(payload)
    return struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        total_len,
        1,
        0,
        64,
        proto,
        0,
        socket.inet_aton(src_ip),
        socket.inet_aton(dst_ip),
    ) + payload


def _build_udp_packet(
    src_ip: str,
    src_port: int,
    dst_ip: str,
    dst_port: int,
    payload: bytes,
) -> bytes:
    udp = struct.pack("!HHHH", src_port, dst_port, 8 + len(payload), 0) + payload
    return _build_ipv4_packet(src_ip, dst_ip, IPPROTO_UDP, udp)


def _wrap_frame(linktype: int, ipv4_pkt: bytes) -> bytes:
    if linktype == DLT_EN10MB:
        return b"\x00" * 12 + struct.pack("!H", 0x0800) + ipv4_pkt
    if linktype == DLT_LINUX_SLL:
        return b"\x00" * 14 + struct.pack("!H", 0x0800) + ipv4_pkt
    if linktype == DLT_LINUX_SLL2:
        return struct.pack("!H", 0x0800) + b"\x00" * 18 + ipv4_pkt
    raise ValueError(f"unsupported linktype {linktype}")


def _write_pcap(path: Path, linktype: int, frames: list[bytes]) -> None:
    buf = bytearray(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, linktype))
    for idx, frame in enumerate(frames, 1):
        buf += struct.pack("<IIII", 1700000000 + idx, 0, len(frame), len(frame))
        buf += frame
    path.write_bytes(bytes(buf))


class AuditWanPcapTests(unittest.TestCase):
    def test_clean_ipsec_capture_passes_across_ethernet_sll1_and_sll2(self):
        esp_udp_payload = b"\xc1\x23\x45\x67" + b"\xaa" * 64
        natt_keepalive = b"\xff"
        overlay_pkt = _build_udp_packet(ENDPOINT_A, 19000, RELAY_X1, 19000, b'{"t":"MCC_START"}')
        direct_esp_udp = _build_udp_packet(ENDPOINT_A, 4500, ENDPOINT_B, 4500, esp_udp_payload)
        direct_keepalive = _build_udp_packet(ENDPOINT_A, 4500, ENDPOINT_B, 4500, natt_keepalive)
        direct_esp_raw = _build_ipv4_packet(ENDPOINT_A, ENDPOINT_B, IPPROTO_ESP, b"\x01\x02\x03\x04" + b"\xbb" * 32)

        for linktype in (DLT_EN10MB, DLT_LINUX_SLL, DLT_LINUX_SLL2):
            with tempfile.TemporaryDirectory() as tmp:
                pcap_path = Path(tmp) / f"ipsec_{linktype}.pcap"
                frames = [
                    _wrap_frame(linktype, overlay_pkt),
                    _wrap_frame(linktype, direct_esp_udp),
                    _wrap_frame(linktype, direct_keepalive),
                    _wrap_frame(linktype, direct_esp_raw),
                ]
                _write_pcap(pcap_path, linktype, frames)
                rep = audit_pcap(pcap_path, "ipsec", ENDPOINT_A, ENDPOINT_B, overlay_port=19000)
                self.assertTrue(rep.passed)
                self.assertEqual(rep.direct_control_leakage, 0)
                self.assertEqual(rep.direct_overlay_ab, 0)
                self.assertEqual(rep.relayed_overlay_packets, 1)
                self.assertEqual(rep.direct_esp_in_udp_4500, 1)
                self.assertEqual(rep.direct_natt_keepalive_4500, 1)
                self.assertEqual(rep.direct_esp_proto50, 1)

    def test_ipsec_detects_direct_ike_500_and_4500_nonesp_leakage(self):
        direct_ike500 = _build_udp_packet(ENDPOINT_A, 500, ENDPOINT_B, 500, b"\x11" * 120)
        direct_ike4500 = _build_udp_packet(ENDPOINT_A, 4500, ENDPOINT_B, 4500, b"\x00\x00\x00\x00" + b"\x22" * 80)

        with tempfile.TemporaryDirectory() as tmp:
            pcap_path = Path(tmp) / "ipsec_leak.pcap"
            _write_pcap(
                pcap_path,
                DLT_LINUX_SLL2,
                [
                    _wrap_frame(DLT_LINUX_SLL2, direct_ike500),
                    _wrap_frame(DLT_LINUX_SLL2, direct_ike4500),
                ],
            )
            rep = audit_pcap(pcap_path, "ipsec", ENDPOINT_A, ENDPOINT_B)
            self.assertFalse(rep.passed)
            self.assertEqual(rep.direct_ike_500, 1)
            self.assertEqual(rep.direct_ike_4500_nonesp, 1)
            self.assertEqual(rep.direct_control_leakage, 2)
            rc = main(
                [
                    "--pcap", str(pcap_path),
                    "--mode", "ipsec",
                    "--endpoint-a", ENDPOINT_A,
                    "--endpoint-b", ENDPOINT_B,
                ]
            )
            self.assertEqual(rc, 2)

    def test_clean_wireguard_capture_passes_and_detects_direct_handshake_or_overlay_ab(self):
        wg_t4 = b"\x04\x00\x00\x00" + b"\xcc" * 60
        wg_t1 = b"\x01\x00\x00\x00" + b"\xdd" * 144
        wg_t2 = b"\x02\x00\x00\x00" + b"\xee" * 88

        overlay_relayed = _build_udp_packet(ENDPOINT_A, 19001, RELAY_X1, 19001, b"{}")
        direct_t4 = _build_udp_packet(ENDPOINT_A, 4500, ENDPOINT_B, 4500, wg_t4)
        direct_t1 = _build_udp_packet(ENDPOINT_A, 4500, ENDPOINT_B, 4500, wg_t1)
        direct_t2 = _build_udp_packet(ENDPOINT_B, 4500, ENDPOINT_A, 4500, wg_t2)
        direct_overlay_ab = _build_udp_packet(ENDPOINT_A, 19001, ENDPOINT_B, 19001, b"{}")

        with tempfile.TemporaryDirectory() as tmp:
            clean_path = Path(tmp) / "wg_clean.pcap"
            _write_pcap(
                clean_path,
                DLT_LINUX_SLL2,
                [
                    _wrap_frame(DLT_LINUX_SLL2, overlay_relayed),
                    _wrap_frame(DLT_LINUX_SLL2, direct_t4),
                ],
            )
            clean_rep = audit_pcap(clean_path, "wg", ENDPOINT_A, ENDPOINT_B, overlay_port=19001, wg_port=4500)
            self.assertTrue(clean_rep.passed)
            self.assertEqual(clean_rep.direct_wg_type4, 1)
            self.assertEqual(clean_rep.direct_control_leakage, 0)
            self.assertEqual(clean_rep.relayed_overlay_packets, 1)

            leak_path = Path(tmp) / "wg_leak.pcap"
            _write_pcap(
                leak_path,
                DLT_LINUX_SLL2,
                [
                    _wrap_frame(DLT_LINUX_SLL2, direct_t1),
                    _wrap_frame(DLT_LINUX_SLL2, direct_t2),
                    _wrap_frame(DLT_LINUX_SLL2, direct_overlay_ab),
                ],
            )
            leak_rep = audit_pcap(leak_path, "wg", ENDPOINT_A, ENDPOINT_B, overlay_port=19001, wg_port=4500)
            self.assertFalse(leak_rep.passed)
            self.assertEqual(leak_rep.direct_wg_type1, 1)
            self.assertEqual(leak_rep.direct_wg_type2, 1)
            self.assertEqual(leak_rep.direct_control_leakage, 2)
            self.assertEqual(leak_rep.direct_overlay_ab, 1)

    def test_results_json_is_valid_and_zero_leakage_across_all_four_cells(self):
        results_path = Path(__file__).resolve().parent / "results.json"
        data = json.loads(results_path.read_text(encoding="utf-8"))
        self.assertTrue(data["anonymized"])
        self.assertEqual(set(data["cells"].keys()), {
            "python_kernel_ipsec",
            "python_kernel_wireguard",
            "rust_kernel_ipsec",
            "rust_userspace_wireguard",
        })
        for name, cell in data["cells"].items():
            for metric, val in cell["direct_control_leakage"].items():
                self.assertEqual(val, 0, f"{name}.{metric} must be 0")
            self.assertEqual(cell["live_rekey"]["ping_lost"], 0, f"{name} rekey loss must be 0")
            self.assertEqual(cell["live_rekey"]["direct_control_leakage"], 0, f"{name} rekey leakage must be 0")


if __name__ == "__main__":
    unittest.main()
