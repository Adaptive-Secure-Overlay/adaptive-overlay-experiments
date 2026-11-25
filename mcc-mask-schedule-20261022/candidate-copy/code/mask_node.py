"""Copy-only integration, with internal diagnostics excluded from observer features."""
import hashlib
import json
import os
import signal
import threading
import time
import traceback
from pathlib import Path

import mask_gate
from mask_transport import Codec, MAGIC, Schedule, INTERVAL, RECORDS, WIRE, MaskError
from mask_sender import IsolatedSchedule


def atom(path,value):
    temporary=path.with_suffix('.tmp');temporary.write_text(json.dumps(value));temporary.replace(path)


def wrap(base):
    class MaskNode(base):
        def __init__(self,*args,**kw):
            super().__init__(*args,**kw)
            self.mask_root=Path(os.environ['MASK_ROOT'])
            self.mask_job=os.environ['MASK_JOB']
            self.mask_source=os.environ['MASK_SOURCE']
            self.mask_token=bytes.fromhex(os.environ['MASK_TOKEN'])
            group=['User6','User7','User8','User9','User10']
            assert self.name in group and self.mask_source in group and len(self.mask_token)==16
            self.mask_peers=[p for p in group if p!=self.name] if self.name==self.mask_source else [self.mask_source]
            self.mask_codecs={};self.mask_sids={};self.mask_rx={p:[] for p in self.mask_peers}
            self.mask_invalid=0;self.mask_plain_after_activation=0;self.mask_gate=None
            self.mask_fatal=None
            self.mask=IsolatedSchedule(self.mask_peers,self.mask_finish)
            self.mask_exit=threading.Event()
            self.mask_monitor=threading.Thread(target=self.mask_monitor_loop,name='owned-mask-receipt',daemon=True)
            self.mask_monitor.start()
            signal.signal(signal.SIGTERM,self.mask_shutdown)

        def mask_pair(self,peer):
            with self.lock:
                sess=self.sessions.get(peer)
                if not sess:raise MaskError('native_A_star_channel_not_ready')
                if peer in self.mask_sids and self.mask_sids[peer]!=sess.sid:
                    raise MaskError('native_A_star_session_rotated')
                if peer not in self.mask_codecs:
                    self.mask_codecs[peer]=(Codec(sess.key,sess.sid,self.name,peer,self.mask_token),
                                            Codec(sess.key,sess.sid,peer,self.name,self.mask_token))
                    self.mask_sids[peer]=sess.sid
                return self.mask_codecs[peer]

        def mask_encode(self,peer,seq,payload):
            # Both directional codecs are prepared before activation. The timed
            # sender must NEVER wait for the protocol handler's native lock.
            # Native SID validation remains in receive and real-data enqueue.
            if peer not in self.mask_codecs:raise MaskError('cover_key_not_prepared_before_activation')
            return self.mask_codecs[peer][0].encode(seq,payload)
        def mask_emit(self,peer,wire):super()._send_peer_raw(peer,wire)

        def mask_finish(self):
            self.mask_gate=mask_gate.release(self.mask_root,self.mask_job)
            if self.mask_gate['packets']:
                raise MaskError('early_ESP_was_dropped_by_experimental_barrier')

        def mask_public(self,ledger=False):
            value=self.mask.receipt()
            if not ledger:value.pop('tx')
            value.update(name=self.name,source=self.mask_source,job=self.mask_job,
                         fatal=self.mask_fatal,
                         gate=self.mask_gate,invalid_records=self.mask_invalid,
                         plaintext_after_activation=self.mask_plain_after_activation,
                         received_counts={p:len(v) for p,v in self.mask_rx.items()},
                         native_sids={p:s.sid for p,s in self.sessions.copy().items() if p in self.mask_peers})
            if ledger:value['rx']={p:list(v) for p,v in self.mask_rx.items()}
            return value

        def mask_monitor_loop(self):
            next_write=0;last_state=None
            try:
                while not self.mask_exit.is_set():
                    if not self.mask.ready:
                        with self.lock:
                            ready=all(p in self.sessions for p in self.mask_peers)
                            contexts={p:dict(key=self.sessions[p].key,sid=self.sessions[p].sid,source=self.name,
                                            destination=p,token=self.mask_token) for p in self.mask_peers} if ready else None
                        if ready:
                            for p in self.mask_peers:self.mask_pair(p)
                            self.mask.prepare(self.sock,contexts,{p:self.peer_addr(p) for p in self.mask_peers})
                    self.mask.poll(.02)
                    state=(self.mask.started,self.mask.done,self.mask.error)
                    if time.monotonic()>=next_write or state!=last_state:
                        atom(self.mask_root/(self.mask_job+'-MASK-READY.json'),self.mask_public())
                        next_write=time.monotonic()+.25;last_state=state
                    self.mask_exit.wait(.005)
            except Exception as exc:
                self.mask.error=type(exc).__name__
                atom(self.mask_root/(self.mask_job+'-MASK-READY.json'),self.mask_public())

        def mask_shutdown(self,*_):
            self.mask_exit.set();self.mask.close();self.mask_monitor.join(timeout=1)
            atom(self.mask_root/(self.mask_job+'-MASK-FINAL.json'),self.mask_public(ledger=True))
            self.stop()
            raise SystemExit(0)

        def serve_forever(self):
            try:
                return super().serve_forever()
            except Exception as exc:
                self.mask_fatal={'type':type(exc).__name__,
                    'frames':[{'file':Path(f.filename).name,'line':f.lineno,'function':f.name} for f in traceback.extract_tb(exc.__traceback__)]}
                # Sanitized diagnostics survive a failed packet handler; never dump keys/payloads.
                self.mask_exit.set();self.mask.close();self.mask_monitor.join(timeout=1)
                atom(self.mask_root/(self.mask_job+'-MASK-FINAL.json'),self.mask_public(ledger=True))
                self.stop()
                raise

        def send_peer(self,peer,payload):
            if self.name==self.mask_source and not self.mask.started:
                try:mtype=json.loads(payload).get('t')
                except (ValueError,AttributeError):mtype=None
                if mtype=='MCC_START':
                    # All four peers admitted before IKE, not selected from the actual route.
                    for p in self.mask_peers:self.mask_pair(p)
                    self.mask.start()
            return super().send_peer(peer,payload)

        def _send_peer_raw(self,peer,payload):
            if peer in self.mask_peers and self.mask.started:
                self.mask_pair(peer)
                return self.mask.enqueue(peer,payload)
            return super()._send_peer_raw(peer,payload)

        def recv_one(self):
            packet=super().recv_one()
            if packet is None:return None
            data,src=packet;peer=self.peer_from_src(src)
            if data.startswith(MAGIC):
                if peer not in self.mask_peers:
                    self.mask_invalid+=1;return None
                try:
                    seq,payload=self.mask_pair(peer)[1].decode(data)
                    if self.name!=self.mask_source and not self.mask.started:
                        peers=sorted([p for p in ('User6','User7','User8','User9','User10') if p!=self.mask_source],key=lambda p:int(p[4:]))
                        phase=(peers.index(self.name)+.5)/4
                        self.mask.start(time.monotonic()-(seq+phase)*INTERVAL)
                    elif not self.mask.started:
                        raise MaskError('peer_cover_before_A_activation')
                    self.mask_rx[peer].append([seq,hashlib.sha256(payload).hexdigest() if payload else None])
                    return (payload,src) if payload else None
                except Exception as exc:
                    self.mask_invalid+=1;self.mask.error=type(exc).__name__;return None
            if peer in self.mask_peers and self.mask.started:
                self.mask_plain_after_activation+=1
                self.mask.error='plaintext_after_activation';return None
            return packet
    return MaskNode
