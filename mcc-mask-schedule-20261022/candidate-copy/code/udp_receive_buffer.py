"""Copy-only, bounded per-socket receive-buffer policy. No sysctl changes."""
import json
import os
import socket
import sys
from pathlib import Path

REQUEST_BYTES = 4 * 1024 * 1024
LINUX_EFFECTIVE_BYTES = 2 * REQUEST_BYTES

def configure_udp_receive(sock, receipt_path=None):
    if not sys.platform.startswith('linux'):
        raise RuntimeError('This experimental socket policy is Linux-only')
    before = sock.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, REQUEST_BYTES)
    normal = sock.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)
    method = 'SO_RCVBUF'
    if normal < LINUX_EFFECTIVE_BYTES:
        # Existing copied x86-64 Linux root process only. No capability changes.
        # Linux asm-generic/socket.h: SO_RCVBUFFORCE=33; bypass cap for this socket.
        sock.setsockopt(socket.SOL_SOCKET, getattr(socket, 'SO_RCVBUFFORCE', 33), REQUEST_BYTES)
        method = 'SO_RCVBUFFORCE'
    effective = sock.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)
    if effective < LINUX_EFFECTIVE_BYTES or effective <= before:
        raise RuntimeError('Receive buffer not increased to the sealed target')
    receipt = {'pid': os.getpid(), 'requested_bytes': REQUEST_BYTES,
               'before_bytes': before, 'normal_readback_bytes': normal,
               'effective_bytes': effective, 'method': method,
               'global_settings_changed': False}
    if receipt_path:
        with Path(receipt_path).open('x', encoding='utf-8') as stream:
            json.dump(receipt, stream)
    return receipt
