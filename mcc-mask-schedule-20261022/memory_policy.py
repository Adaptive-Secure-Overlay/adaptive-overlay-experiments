"""Staged memory admission; same48GiB physical and16GiB runtime reserves.

Only startup commit changes44->36. It permits preparation, NOT IKE. After
all nested nodes and capacity admission: fresh30s stable runtime proof required.
"""
import json,math,threading,time
from pathlib import Path
from win_memory import snapshot
GIB=1024**3
START_PHYSICAL_GIB=48
START_COMMIT_GIB=36
RUNTIME_GIB=16
STABLE_SECONDS=30

def evaluate(row,physical_gib,commit_gib):
    values=[row.get(k) for k in ('available_physical','system_available_commit','process_available_commit')]
    assert all(isinstance(v,int) and not isinstance(v,bool) and v>=0 for v in values),'Unknown memory metric; fail closed'
    return values[0]>=physical_gib*GIB and min(values[1:])>=commit_gib*GIB

def admit():
    row=snapshot()
    assert evaluate(row,START_PHYSICAL_GIB,START_COMMIT_GIB),'Staged startup memory gate not met (physical48/commit36GiB)'
    return {**row,'passed':True,'physical_floor_gib':START_PHYSICAL_GIB,'commit_floor_gib':START_COMMIT_GIB,
            'authorizes':'copy preparation only; IKE requires fresh full-load stability grant'}

class Monitor:
    def __init__(self,root,reader=snapshot,clock=time.monotonic):
        self.root=Path(root);self.reader=reader;self.clock=clock;self.rows=[];self.lock=threading.Lock()
        self.stop_event=threading.Event();self.pressure=threading.Event();self.error=None;self.thread=None
    def sample(self):
        try:
            row=self.reader();row['monotonic_s']=self.clock();row['passed']=evaluate(row,RUNTIME_GIB,RUNTIME_GIB)
            with self.lock:
                if len(self.rows)>=6000:raise RuntimeError('Memory telemetry cap reached')
                self.rows.append(row)
            if not row['passed']:self.pressure.set()
        except Exception as exc:self.error=type(exc).__name__;self.pressure.set()
    def start(self):
        self.sample();self.check()
        def loop():
            while not self.stop_event.wait(1):self.sample()
        self.thread=threading.Thread(target=loop,name='owned-memory-safety',daemon=True);self.thread.start()
    def check(self):
        assert not self.pressure.is_set(),'Runtime memory reserve below16GiB or telemetry failed; no IKE continuation'
        with self.lock:last=self.rows[-1]['monotonic_s'] if self.rows else None
        assert last is None or self.clock()-last<=2.5,'Memory telemetry is stale; no continuation'
    def stable(self,since):
        self.check()
        if self.clock()-since<STABLE_SECONDS:return None
        with self.lock:rows=[r for r in self.rows if r['monotonic_s']>=since]
        if len(rows)<30 or rows[-1]['monotonic_s']-rows[0]['monotonic_s']<29 or self.clock()-rows[-1]['monotonic_s']>2.5:return None
        assert all(r['passed'] for r in rows)
        return {'passed':True,'stage':'full_nested_load_before_IKE','samples':len(rows),'stable_span_s':rows[-1]['monotonic_s']-rows[0]['monotonic_s'],
                'runtime_floor_gib':RUNTIME_GIB,'min_physical':min(r['available_physical'] for r in rows),
                'min_system_commit':min(r['system_available_commit'] for r in rows),
                'min_process_commit':min(r['process_available_commit'] for r in rows)}
    def close(self):
        self.stop_event.set()
        if self.thread:self.thread.join(timeout=2);assert not self.thread.is_alive()
        with self.lock:rows=list(self.rows)
        value={'passed':bool(rows) and not self.pressure.is_set(),'samples':rows,'error_type':self.error,
               'minimum_physical':min((r['available_physical'] for r in rows),default=None),
               'minimum_system_commit':min((r['system_available_commit'] for r in rows),default=None),
               'runtime_floor_gib':RUNTIME_GIB,'sample_interval_s':1,'thread_stopped':True}
        path=self.root/'MEMORY-RUNTIME-PROFILE.json'
        with path.open('x',encoding='utf-8') as stream:json.dump(value,stream,indent=2)
        return {k:v for k,v in value.items() if k!='samples'}|{'sample_count':len(rows)}
