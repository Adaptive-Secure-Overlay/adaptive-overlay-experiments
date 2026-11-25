"""Finite owned sender, isolated from protocol GIL/locks; no socket options.

The original Codec/Schedule and quotas are reused. No real-time priority,
spin loop, external service, kernel/qdisc changes or unscheduled fallback.
"""
import ctypes
import multiprocessing as mp
import os
import queue
import signal
import socket
import sys
import threading
import time
from pathlib import Path
from mask_transport import Codec,Schedule,MaskError,MAX_QUEUE,MAX_INNER,WINDOW,GUARD,MAX_LATENESS

MAX_LIFETIME=180.

def sender_main(control,inbox,sock,contexts,addresses,capacity,submitted,sent_real,parent_pid):
    scheduler=None;worst=[];last=None;cpu_begin=time.process_time();wall_begin=time.monotonic()
    try:
        if sys.platform=='linux':
            libc=ctypes.CDLL(None,use_errno=True)
            if libc.prctl(1,signal.SIGTERM,0,0,0)!=0:raise OSError('Owned sender parent-death guard unavailable')
        assert os.getppid()==parent_pid,'Actor parent changed during spawn'
        peers=list(contexts);index={p:i for i,p in enumerate(peers)}
        codecs={p:Codec(**context) for p,context in contexts.items()}
        buffer_before=(sock.getsockopt(socket.SOL_SOCKET,socket.SO_RCVBUF),sock.getsockopt(socket.SOL_SOCKET,socket.SO_SNDBUF))
        current=[None,None];stages={}
        def encode(peer,seq,payload):
            current[:]=[peer,bool(payload)]
            begin=time.monotonic();wire=codecs[peer].encode(seq,payload)
            stages['encode_wall_s']=time.monotonic()-begin;return wire
        def emit(peer,wire):
            begin=time.monotonic()
            assert sock.sendto(wire,addresses[peer])==len(wire),'Partial cover datagram'
            emitted=time.monotonic();stages.update(sendto_wall_s=emitted-begin,emitted_lateness_s=emitted-scheduler.anchor-stages['relative_s'])
            if current[1]:
                sent_real[index[peer]]+=1;capacity[index[peer]].release()
        scheduler=Schedule(peers,encode,emit,lambda:None)
        control.send({'kind':'ready','pid':os.getpid(),'socket_name':sock.getsockname(),
                      'buffer_values':buffer_before,'socket_inode':os.readlink('/proc/self/fd/'+str(sock.fileno())) if sys.platform=='linux' else None,'separate_interpreter':True})
        deadline=time.monotonic()+MAX_LIFETIME
        def stopped(wait=0):
            if time.monotonic()>deadline:raise MaskError('sender_lifetime_limit')
            if os.getppid()!=parent_pid:raise MaskError('actor_parent_gone')
            if control.poll(wait):
                command=control.recv()
                if command[0]=='stop':raise MaskError('cancelled')
                return command
            return None
        while True:
            command=stopped(.05)
            if command:
                assert command[0]=='start';scheduler.anchor=command[1];scheduler.started=True;break
        def drain():
            for _ in range(MAX_QUEUE*len(peers)):
                try:peer,payload=inbox.get_nowait()
                except queue.Empty:break
                scheduler.enqueue(peer,payload)
        last_wall=time.monotonic();last_cpu=time.thread_time()
        for relative,peer,seq in scheduler.plan:
            while True:
                if stopped():raise MaskError('unexpected_sender_command')
                drain()
                delay=scheduler.anchor+relative-time.monotonic()
                if delay<=0:break
                if stopped(min(delay,.001)):raise MaskError('unexpected_sender_command')
            wall=time.monotonic();cpu=time.thread_time()
            record={'relative_s':relative,'peer':peer,'seq':seq,'wake_lateness_s':wall-scheduler.anchor-relative,
                    'elapsed_since_previous_s':wall-last_wall,'cpu_since_previous_s':cpu-last_cpu}
            last=record
            stages={'relative_s':relative}
            before=time.monotonic();scheduler.step(relative,peer,seq);after=time.monotonic()
            record.update(step_wall_s=after-before,**stages)
            last=record;worst.append(record);worst=sorted(worst,key=lambda r:r['emitted_lateness_s'],reverse=True)[:8]
            scheduler.max_lateness=max(scheduler.max_lateness,record['emitted_lateness_s'])
            if record['emitted_lateness_s']>MAX_LATENESS:raise MaskError('emit_deadline_exceeded')
            last_wall=after;last_cpu=time.thread_time()
        while time.monotonic()<scheduler.anchor+WINDOW+GUARD:
            if stopped(min(.002,max(0,scheduler.anchor+WINDOW+GUARD-time.monotonic()))):raise MaskError('unexpected_sender_command')
            drain()
        assert not any(scheduler.queues.values()) and list(submitted)==list(sent_real),'Unsent real data at fixed end'
        scheduler.done=True
    except Exception as exc:
        if scheduler:
            scheduler.error=str(exc)[:100] if isinstance(exc,MaskError) else type(exc).__name__
            scheduler.failure={'type':type(exc).__name__,'code':scheduler.error,'last_stage':last,
                               'at_relative_s':time.monotonic()-scheduler.anchor if scheduler.anchor is not None else None}
    finally:
        result=scheduler.receipt() if scheduler else {'started':False,'done':False,'error':'sender_prepare_failed',
            'failure':{'type':'sender_prepare_failed'},'window_s':WINDOW,'guard_s':GUARD,'max_lateness_s':0,
            'queued':{},'high_water':{},'tx':{}}
        result['sender']={'pid':os.getpid(),'parent_pid':parent_pid,'separate_interpreter':True,
            'worst_slots':worst,'last_slot':last,'cpu_s':time.process_time()-cpu_begin,'wall_s':time.monotonic()-wall_begin,
            'buffer_options_changed':False,'socket_name':sock.getsockname()}
        try:
            sock.close();control.send({'kind':'final','value':result})
        finally:control.close()

class IsolatedSchedule:
    """Parent facade: bounded real-data IPC; no timed send in this interpreter."""
    def __init__(self,peers,finish):
        self.peers=list(peers);self.finish=finish;self.index={p:i for i,p in enumerate(self.peers)}
        self.lock=threading.RLock();self.started=False;self.anchor=None;self.done=False;self._error=None
        self.process=None;self.ready=None;self.final=None;self.capacity=None;self.inbox=None;self.control=None
        self.high_water={p:0 for p in peers};self.submitted=None;self.sent_real=None

    def prepare(self,sock,contexts,addresses):
        with self.lock:
            if self.process:return
            assert set(contexts)==set(addresses)==set(self.peers)
            if sys.platform=='win32':
                hidden=Path(sys.executable).with_name('pythonw.exe');assert hidden.is_file()
                mp.set_executable(str(hidden))
            ctx=mp.get_context('spawn')
            self.capacity=[ctx.BoundedSemaphore(MAX_QUEUE) for _ in self.peers]
            self.submitted=ctx.RawArray('i',len(self.peers));self.sent_real=ctx.RawArray('i',len(self.peers))
            self.inbox=ctx.Queue(maxsize=MAX_QUEUE*len(self.peers));parent,child=ctx.Pipe()
            self.control=parent
            self.process=ctx.Process(target=sender_main,args=(child,self.inbox,sock,contexts,addresses,self.capacity,
                self.submitted,self.sent_real,os.getpid()),name='owned-mask-sender',daemon=True)
            self.process.start();child.close()
            if not parent.poll(8):raise MaskError('sender_readiness_timeout')
            try:ready=parent.recv()
            except (EOFError,OSError):
                self.error='sender_bootstrap_channel_closed'
                raise MaskError(self.error) from None
            assert ready['kind']=='ready','Sender did not prepare'
            assert ready['socket_name']==sock.getsockname(),'Sender socket identity differs'
            assert tuple(ready['buffer_values'])==(sock.getsockopt(socket.SOL_SOCKET,socket.SO_RCVBUF),sock.getsockopt(socket.SOL_SOCKET,socket.SO_SNDBUF)),'Socket buffers changed during transfer'
            if sys.platform=='linux':assert ready['socket_inode']==os.readlink('/proc/self/fd/'+str(sock.fileno())),'Sender did not inherit same UDP socket'
            self.ready=ready

    @property
    def error(self):return self._error
    @error.setter
    def error(self,value):
        with self.lock:
            if not self._error:self._error=value

    def poll(self,timeout=0):
        if not self.process or self.final:return
        try:available=self.control.poll(timeout)
        except (EOFError,OSError):self.error='sender_channel_closed';return
        if not available:
            if not self.process.is_alive():self.error='sender_exit_without_final'
            return
        with self.lock:
            try:
                if self.final or not self.control.poll():return
                event=self.control.recv()
            except (EOFError,OSError):self.error='sender_channel_closed';return
            assert event['kind']=='final'
            self.final=event['value'];self._error=self._error or self.final['error']
            self.process.join(timeout=.5)
            if self.process.is_alive():self._error=self._error or 'sender_exit_unconfirmed'
            if self.final['done'] and not self._error:
                try:self.finish();self.done=True
                except Exception as exc:self._error=str(exc)[:100] if isinstance(exc,MaskError) else type(exc).__name__

    def start(self,anchor=None):
        with self.lock:
            if self.started:return
            if not self.ready or self.error:raise MaskError(self.error or 'sender_not_ready')
            self.anchor=time.monotonic() if anchor is None else anchor;self.started=True
            self.control.send(('start',self.anchor))

    def enqueue(self,peer,payload):
        with self.lock:
            if peer not in self.index or not isinstance(payload,bytes) or not 0<len(payload)<=MAX_INNER:raise MaskError('Invalid queued datagram')
            if self.error or self.done or not self.started or time.monotonic()>=self.anchor+WINDOW:
                self.error=self.error or 'queue_after_fixed_end';raise MaskError(self.error)
            index=self.index[peer]
            if not self.capacity[index].acquire(False):self.error='queue_overflow';raise MaskError(self.error)
            try:self.inbox.put_nowait((peer,payload))
            except Exception:
                self.capacity[index].release();self.error='sender_IPC_full';raise MaskError(self.error) from None
            self.submitted[index]+=1
            self.high_water[peer]=max(self.high_water[peer],self.submitted[index]-self.sent_real[index])

    def receipt(self):
        self.poll()
        with self.lock:
            result=dict(self.final) if self.final else {'started':self.started,'done':False,'error':self.error,
                'failure':None,'window_s':WINDOW,'guard_s':GUARD,'max_lateness_s':0,
                'queued':{p:self.submitted[i]-self.sent_real[i] if self.submitted is not None else 0 for p,i in self.index.items()},
                'high_water':dict(self.high_water),'tx':{p:[] for p in self.peers}}
            result.update(done=self.done,error=self.error,sender_ready=bool(self.ready),
                          sender_pid=self.process.pid if self.process else None,
                          sender_exited=bool(self.process and not self.process.is_alive()))
            return result

    def close(self):
        if self.process and self.process.pid is not None:
            if self.process.is_alive() and not self.final:
                try:self.control.send(('stop',None))
                except (BrokenPipeError,OSError):pass
                self.poll(.5)
            self.process.join(timeout=1)
            if self.process.is_alive():self.process.terminate();self.process.join(timeout=1);self.error='sender_forced_cleanup'
            assert not self.process.is_alive(),'Owned sender cleanup unconfirmed'
            self.inbox.cancel_join_thread();self.inbox.close()
