"""Copy-only fixed-rate authenticated cover transport. Not a production protocol.

Neither the codec nor the schedule accepts a recipient label. Native hop AEAD,
endpoint signatures, replay checks and the adaptive selection timer stay inside.
"""
import collections
import hashlib
import json
import struct
import threading
import time
import traceback
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

MAGIC = b'MSK1'
HEADER = struct.Struct('!4s16sI')
WIRE = 1124                 # IPv4 + UDP = 1152 bytes, no IP fragmentation.
MAX_INNER = 1060
PLAIN = WIRE - HEADER.size - 16
RECORDS = 1000              # Per peer, per direction; 8000 at A, 9,216,000 IP bytes.
INTERVAL = .002
WINDOW = RECORDS * INTERVAL
GUARD = .100
MAX_LATENESS = .020
MAX_QUEUE = RECORDS


class MaskError(RuntimeError):
    pass


def slots(peers):
    """One public phase per numeric peer, never per receiver or route."""
    ordered = sorted(peers, key=lambda p: int(p[4:]))
    if not ordered or len(set(ordered)) != len(ordered):
        raise ValueError('Invalid public group')
    return sorted(((i + (rank + .5) / len(ordered)) * INTERVAL, peer, i)
                  for rank, peer in enumerate(ordered) for i in range(RECORDS))


class Codec:
    def __init__(self, key, sid, source, destination, token):
        if len(token) != 16 or len(key) != 32 or source == destination:
            raise ValueError('Invalid cover context')
        context = json.dumps(['mcc-mask-pilot/v1', sid, source, destination],
                             separators=(',', ':')).encode()
        self.cipher = AESGCM(HKDF(algorithm=hashes.SHA256(), length=32,
                                 salt=token, info=context).derive(key))
        self.token = token
        self.seen = set()
        self.sent = set()

    def encode(self, seq, payload=b''):
        if type(seq) is not int or not 0 <= seq < RECORDS or seq in self.sent or not isinstance(payload, bytes) or len(payload) > MAX_INNER:
            raise ValueError('Cover budget exceeded')
        header = HEADER.pack(MAGIC, self.token, seq)
        plain = bytes([bool(payload)]) + len(payload).to_bytes(2, 'big') + payload
        plain += bytes(PLAIN - len(plain))
        wire = header + self.cipher.encrypt(bytes(8) + seq.to_bytes(4, 'big'), plain, header)
        self.sent.add(seq)
        return wire

    def decode(self, wire):
        if len(wire) != WIRE:
            raise ValueError('Cover size differs')
        magic, token, seq = HEADER.unpack(wire[:HEADER.size])
        if magic != MAGIC or token != self.token or seq >= RECORDS or seq in self.seen:
            raise ValueError('Cover context or replay')
        plain = self.cipher.decrypt(bytes(8) + seq.to_bytes(4, 'big'), wire[HEADER.size:], wire[:HEADER.size])
        kind, size = plain[0], int.from_bytes(plain[1:3], 'big')
        if kind not in (0, 1) or size > MAX_INNER or bool(size) != bool(kind) or any(plain[3 + size:]):
            raise ValueError('Noncanonical cover plaintext')
        self.seen.add(seq)  # Only authenticated, fully validated records consume replay state.
        return seq, plain[3:3 + size]


class Schedule:
    """Bounded queues; no extra send for data, no unscheduled fallback on failure."""
    def __init__(self, peers, encode, emit, finish, clock=time.monotonic):
        self.plan = slots(peers)
        self.queues = {p: collections.deque() for p in peers}
        self.encode, self.emit, self.finish, self.clock = encode, emit, finish, clock
        self.lock = threading.RLock()
        self.stop_event = threading.Event()
        self.started = self.done = False
        self.error = None
        self.anchor = None
        self.tx = {p: [] for p in peers}
        self.high_water = {p: 0 for p in peers}
        self.max_lateness = 0.
        self.failure = None

    def enqueue(self, peer, payload):
        with self.lock:
            if peer not in self.queues or not 0 < len(payload) <= MAX_INNER:
                raise MaskError('Invalid queued datagram')
            if self.done or self.error or len(self.queues[peer]) >= MAX_QUEUE:
                if not self.error:self.error = 'queue_after_fixed_end' if self.done else 'queue_overflow'
                raise MaskError(self.error)
            self.queues[peer].append(payload)
            self.high_water[peer] = max(self.high_water[peer], len(self.queues[peer]))

    def start(self, anchor=None):
        with self.lock:
            if self.started:
                return
            self.started = True
            self.anchor = self.clock() if anchor is None else anchor
            self.thread = threading.Thread(target=self.run, name='owned-mask-schedule', daemon=True)
            self.thread.start()

    def step(self, relative, peer, seq):
        with self.lock:
            lateness = self.clock() - self.anchor - relative
            self.max_lateness = max(self.max_lateness, lateness)
            if lateness > MAX_LATENESS or self.error:
                raise MaskError(self.error or 'slot_lateness_exceeded')
            payload = self.queues[peer].popleft() if self.queues[peer] else b''
            wire = self.encode(peer, seq, payload)
            self.emit(peer, wire)
            self.tx[peer].append([seq, hashlib.sha256(payload).hexdigest() if payload else None])

    def run(self):
        relative=peer=seq=None
        try:
            for relative, peer, seq in self.plan:
                delay = self.anchor + relative - self.clock()
                if delay > 0 and self.stop_event.wait(delay):
                    raise MaskError('cancelled')
                if self.stop_event.is_set():
                    raise MaskError('cancelled')
                self.step(relative, peer, seq)
            with self.lock:
                if any(self.queues.values()):
                    raise MaskError('unsent_real_data_at_fixed_end')
            self.stop_event.wait(max(0, self.anchor + WINDOW + GUARD - self.clock()))
            if self.stop_event.is_set():
                raise MaskError('cancelled')
            self.finish()
            self.done = True
        except Exception as exc:
            self.error = str(exc)[:100] if isinstance(exc, MaskError) else type(exc).__name__
            self.failure={'type':type(exc).__name__,'code':self.error,'relative':relative,'peer':peer,'seq':seq,
                          'at_relative_s':self.clock()-self.anchor,
                          'frames':[{'file':Path(f.filename).name,'line':f.lineno,'function':f.name} for f in traceback.extract_tb(exc.__traceback__)]}

    def close(self):
        self.stop_event.set()
        if self.started and threading.current_thread() is not self.thread:
            self.thread.join(timeout=2)

    def receipt(self):
        with self.lock:
            return {'started': self.started, 'done': self.done, 'error': self.error,
                    'failure': self.failure,
                    'window_s': WINDOW, 'guard_s': GUARD, 'max_lateness_s': self.max_lateness,
                    'queued': {p: len(q) for p, q in self.queues.items()},
                    'high_water': dict(self.high_water), 'tx': {p: list(v) for p, v in self.tx.items()}}
