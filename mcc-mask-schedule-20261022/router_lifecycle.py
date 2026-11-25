"""Owned RouterOS lifecycle, not licensing changes. Strict fresh snapshots remain mandatory."""
import hashlib,json,re,shutil,subprocess,time
from pathlib import Path
import router_read as rr

def choose_restarts(snapshot):
    assert len(snapshot)==14,'Router inventory incomplete; no recovery'
    bad=[]
    for key,row in snapshot.items():
        assert not row.get('error') and row.get('logout_confirmed'), 'Unreadable router '+key
        level=row.get('license_level')
        assert level in ('free','p-unlimited'), 'Unknown license on '+row['name']
        if level=='free':bad.append(int(key))
    assert len(bad)<=2,'Multiple unexpected licensing failures; no cascading restarts'
    return bad

def shutdown_confirmed(raw):
    return bool(re.search(rb'(?i)shutdown[^\r\n]*\[y/n\][^\r\n]*\s*\Z',rr.view(raw)))

def request_shutdown(tn,timeout=8):
    # Reuse the established migration protocol; acknowledge ONLY this exact lifecycle prompt.
    tn.read();tn.write(b'/system shutdown\r\n');end=time.monotonic()+timeout;buf=b''
    while time.monotonic()<end:
        buf+=tn.read();assert len(buf)<=131072,'Shutdown buffer cap'
        value=rr.view(buf)
        if rr.TAIL_LOGIN.search(value) or rr.TAIL_PASSWORD.search(value):raise RuntimeError('Authentication changed before shutdown')
        if shutdown_confirmed(buf):tn.write(b'y\r\n');return
        time.sleep(.05)
    raise RuntimeError('Exact shutdown confirmation missing; no blind answer')

def alive(pid):
    path=Path('/proc')/str(pid)/'cmdline'
    try:return bool(path.read_bytes())
    except FileNotFoundError:return False

def graceful(router):
    assert router['console_verified_from_owned_qemu'],'Unowned router lifecycle denied'
    pid=router['console_proof']['qemu_pid'];assert alive(pid),'Router already stopped; reconcile'
    tn=rr.Console('127.0.0.1',router['console_port']);events=[]
    try:rr.login(tn,events);request_shutdown(tn)
    finally:tn.close()
    end=time.monotonic()+20
    while time.monotonic()<end and alive(pid):time.sleep(.2)
    assert not alive(pid),'Router did not complete guest OS shutdown'
    return {'passed':True,'qemu_pid':pid,'guest_os_shutdown_confirmed':True,'license_commands_written':0,'queue_commands_written':0}

def sha(p):
    h=hashlib.sha256()
    with p.open('rb') as f:
        for block in iter(lambda:f.read(1048576),b''):h.update(block)
    return h.hexdigest()

def recover_initial(snapshot,mapping,v,pc,root,state,status):
    bad=choose_restarts(snapshot);report={'nodes_selected':bad,'restarts':[],'acceptance_weakened':False,'licensing_commands_written':0}
    assert not state['started_ids'],'Readiness recovery forbidden after an IKE job starts'
    v.atom(root/'READINESS-RECOVERY.json',report)
    if not bad:return snapshot,mapping
    for node_id in bad:
        router=next(r for r in mapping['routers'] if r['node_id']==node_id)
        state.update(stage='one_cold_restart_for_unready_router',recovery_node=node_id);v.atom(status,state)
        receipt=graceful(router)
        subprocess.run(['/opt/unetlab/wrappers/unl_wrapper','-a','stop','-T','0','-F',str(v.LAB),'-D',str(node_id)],capture_output=True,timeout=30)
        runtime=Path('/opt/unetlab/tmp/0/542bfe9b-f14f-44ca-973b-7477f3850705')/str(node_id)/'hda.qcow2'
        assert runtime.is_file() and runtime.stat().st_size<=512*1024**2,'Bounded rollback disk unavailable'
        backup=root/f'router-{node_id}-before-cold-restart.qcow2';assert not backup.exists()
        receipt.update(node_id=node_id,disk_sha256=sha(runtime));shutil.copyfile(runtime,backup);assert sha(backup)==receipt['disk_sha256']
        receipt['backup']=backup.name;report['restarts'].append(receipt);v.atom(root/'READINESS-RECOVERY.json',report)
        subprocess.run(['/opt/unetlab/wrappers/unl_wrapper','-a','start','-T','0','-F',str(v.LAB),'-D',str(node_id)],check=True,capture_output=True,timeout=90)
        mapping=pc.discover(str(v.LAB),v.IDS)
        router=next(r for r in mapping['routers'] if r['node_id']==node_id)
        observations=[]
        for i in range(3):
            if i:time.sleep(5)
            tn=rr.Console('127.0.0.1',router['console_port']);events=[]
            try:
                rr.login(tn,events,timeout=45);text=rr.run(tn,'level','READ'+str(9000+i),timeout=25)
                found=re.findall(r'(?m)^LEVEL\|([^\r\n]+)',text);assert len(found)==1
                observations.append(found[0].strip());assert rr.logout(tn)
            finally:tn.close()
            receipt['level_observations']=observations;v.atom(root/'READINESS-RECOVERY.json',report)
            assert observations[-1]=='p-unlimited','Cold restart did not restore actual required level; no second restart'
    old={(t['node_id'],t['interface_id'],t['guest_mac'],t['bridge']) for t in json.loads((root/'PATH-MAPPING.json').read_text())['taps']}
    current={(t['node_id'],t['interface_id'],t['guest_mac'],t['bridge']) for t in mapping['taps']}
    assert current==old,'Interface mapping changed after lifecycle recovery'
    after=pc.routers_snapshot(mapping,static=True);report['recovery_reads_complete']=True
    v.atom(root/'READINESS-RECOVERY.json',report);return after,mapping

def shutdown_all(mapping,v):
    out={}
    for router in mapping['routers']:
        try:out[str(router['node_id'])]=graceful(router)
        except Exception as e:out[str(router['node_id'])]={'passed':False,'error_type':type(e).__name__,'error':str(e)[:180]}
    return out
