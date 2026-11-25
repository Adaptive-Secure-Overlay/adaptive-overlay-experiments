"""Finite clone-only series, read-only queues, bounded per-batch exports."""
import base64, hashlib, json, os, re, signal, subprocess, tarfile, time, traceback
from pathlib import Path
import guest_setup as v
import guest_setup_network as g
import path_capture as pathcap
import admission
import router_lifecycle
import capacity_gate
from selection_policy import validate as validate_policy
from queue_stats import loss_deltas
from series_common import verify_queues
from series_common import summarize
ROOT=Path(__file__).resolve().parent; STATUS=ROOT/'LIVE-STATUS.json'
def atom(p,x): v.atom(p,x)
def digest(p): return hashlib.sha256(p.read_bytes()).hexdigest()
def udp_snapshot():
    out={}
    for user in g.ENDPOINTS:
        cmd="/root/candidate-mcc-runtime3148-5002-restored-20261015/python/bin/python3.14 -B -c \"import sys,json;sys.path.insert(0,'"+str(ROOT)+"');import node_diag;print('PUBLIC_JSON='+json.dumps(node_diag.counters()))\""
        out[str(user)]=admission.remote_json(user,cmd)
    return out
def logs():
    result={}
    for user in g.ENDPOINTS:
        cmd="/root/candidate-mcc-runtime3148-5002-restored-20261015/python/bin/python3.14 -B -c \"import base64,json;from pathlib import Path;p=Path('"+str(ROOT/'code/logs')+"')/'User"+str(user)+".log';print('PUBLIC_JSON='+json.dumps({'log':base64.b64encode(p.read_bytes()[-65536:]).decode() if p.exists() else ''}))\""
        result[str(user)]=admission.remote_json(user,cmd)['log']
    return result
def export_tree(directory,name,exclude_children=False):
    files=[p for p in (directory.iterdir() if exclude_children else directory.rglob('*')) if p.is_file() and p.suffix in ('.json','.log','.pcap')]
    assert len(files)<=300 and sum(p.stat().st_size for p in files)<=192*1024**2, 'Per-batch export cap exceeded'
    archive=ROOT/(name+'.tar.gz'); assert not archive.exists()
    with tarfile.open(archive,'w:gz') as tf:
        for p in files:
            assert p.stat().st_size<=32*1024**2
            tf.add(p,arcname=str(p.relative_to(directory)),recursive=False)
    return {'name':name,'files':len(files),'bytes':sum(p.stat().st_size for p in files),'sha256':digest(archive)}
def stop_captures(captures,work):
    if not captures:return {}
    for p,stream,user in captures:
        if p.poll() is None:p.send_signal(signal.SIGINT)
    checks={}
    for p,stream,user in captures:
        p.wait(timeout=8);stream.close();cap=work/f'User{user}.pcap'
        match=re.search(r'(\d+) packets dropped by kernel',(work/f'User{user}.log').read_text())
        checks[str(user)]={'pcap':cap.name,'bytes':cap.stat().st_size,'sha256':digest(cap),'kernel_drops':int(match[1]) if match else None}
    assert sum(x['bytes'] for x in checks.values())<=64*1024**2, 'Per-connection capture cap exceeded'
    assert all(x['kernel_drops']==0 for x in checks.values()), 'Capture kernel loss; do not infer network loss'
    return checks
def main():
    assert not STATUS.exists(), 'Existing controller: reconcile, never replay'
    plan=json.loads((ROOT/'SEALED-CONTRACT.json').read_text()); expected=json.loads((ROOT/'EXPECTED-QUEUES.json').read_text())
    assert len(plan['attempts'])==19 and len(set(plan['execute_ids']))==19
    state={'stage':'precheck','started_node_ids':[],'started_ids':[],'completed_ids':[],'planned_attempts':19,
           'round_exports':[],'successful':0,'failed':0,'at_utc':g.now(),'progress':summarize([],19)};atom(STATUS,state)
    rolling=[]
    initialized=False;mapping=None;captures=[];current_work=None;batch_dir=None;batch_no=None;active_pair=None;consecutive=0;terminal='blocked'
    try:
        v.setup(state,plan);initialized=True
        state.update(stage='individual_key_admission',at_utc=g.now());atom(STATUS,state);admission.identity_provision()
        state.update(stage='verifying_rebooted_queues',at_utc=g.now());atom(STATUS,state)
        mapping=pathcap.discover(str(v.LAB),v.IDS);atom(ROOT/'PATH-MAPPING.json',mapping)
        assert len(mapping['routers'])==14 and len(mapping['taps'])==53
        initial=pathcap.routers_snapshot(mapping,static=True);atom(ROOT/'ROUTER-INITIAL.json',initial)
        initial=capacity_gate.run(mapping,initial,expected,state,STATUS)
        atom(ROOT/'PATH-MAPPING.json',mapping);atom(ROOT/'ROUTER-READY.json',initial)
        atom(ROOT/'QUEUE-REBOOT-ACCEPTANCE.json',verify_queues(initial,expected))
        state.update(stage='console_read_preflight',queue_reboot_accepted=True,at_utc=g.now());atom(STATUS,state)
        u10=next(r for r in mapping['routers'] if r['node_id']==21)
        checks=[pathcap.router_probe.snapshot(u10,False) for _ in range(10)]
        atom(ROOT/'CONSOLE-READ-PREFLIGHT.json',checks)
        assert all(not r.get('error') and r['interfaces'] and r.get('fresh_markers_verified')==2 and r.get('logout_confirmed') for r in checks), 'Strict read-only U10 preflight failed; no new connection'
        state['console_preflight_passed']=True;atom(STATUS,state)
        state.update(stage='awaiting_full_load_memory_admission',at_utc=g.now());atom(STATUS,state)
        memory_receipt=ROOT/'MEMORY-RUN-ADMISSION.json';memory_deadline=time.monotonic()+90
        while not memory_receipt.exists() and time.monotonic()<memory_deadline:time.sleep(.25)
        grant=json.loads(memory_receipt.read_text())
        assert grant['passed'] and grant['samples']>=30 and grant['stable_span_s']>=29 and grant['runtime_floor_gib']==16
        assert grant['contract_sha256']==digest(ROOT/'SEALED-CONTRACT.json'),'Host memory grant context differs'
        assert min(grant['min_physical'],grant['min_system_commit'],grant['min_process_commit'])>=16*1024**3
        endpoint_taps={u:next(t for t in mapping['taps'] if t['node_id']==2*u) for u in g.ENDPOINTS}
        for batch_no in range(1,6):
            batch_dir=ROOT/f'round-{batch_no:02d}';batch_dir.mkdir(mode=0o700)
            state.update(stage='batch_precheck',batch=batch_no,current_id=None,at_utc=g.now());atom(STATUS,state)
            before=pathcap.routers_snapshot(mapping);atom(batch_dir/'ROUTER-BEFORE.json',before)
            assert loss_deltas(before,before)['passed'], 'Unknown router counters'
            atom(batch_dir/'UDP-BEFORE.json',udp_snapshot());atom(batch_dir/'HOST-BEFORE.json',pathcap.host_counters(mapping))
            try:
                for attempt in [x for x in plan['attempts'] if x['batch']==batch_no]:
                    assert attempt['id'] in plan['execute_ids'] and attempt['id'] not in state['started_ids'], 'No replay of any prior or started job'
                    v.no_physical();job=attempt['id'];source=int(attempt['initiator'][4:]);receiver=int(attempt['receiver'][4:]);active_pair=(source,receiver)
                    current_work=batch_dir/job;current_work.mkdir(mode=0o700)
                    state.update(stage='preparing_connection',current_id=job,at_utc=g.now());atom(STATUS,state)
                    for user,peer in ((source,receiver),(receiver,source)):v.node(user,'down',peer=peer)
                    manifest=[];captures=[]
                    for user,(_,bridge,_) in g.ENDPOINTS.items():
                        stream=(current_work/f'User{user}.log').open('x')
                        p=subprocess.Popen(['tcpdump','-i',bridge,'-nn','-s','0','-B','4096','-U','-w',str(current_work/f'User{user}.pcap'),'ip and (udp or esp or icmp)'],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=stream)
                        captures.append((p,stream,user));manifest.append({'pcap':f'User{user}.pcap',**endpoint_taps[user], 'capture_interface':bridge,'capture_scope':'endpoint_bridge'})
                    atom(current_work/'path-capture.json',{'format':'per_tap_ethernet','captures':manifest})
                    actors={str(u):v.node(u,'protected',job=job,mask_source=attempt['initiator'],mask_token=attempt['mask_token']) for u in g.ENDPOINTS}
                    assert all(validate_policy(a['selection_policy']) for a in actors.values())
                    assert {a['code_sha256'] for a in actors.values()}=={plan['candidate_files']['node_daemon.py']}
                    assert {a['transport_sha256'] for a in actors.values()}=={plan['candidate_files']['link_transport.py']}
                    assert all(a['compact_wire']=={'LINK_CIPHER_VERSION':2,'LINK_FRAG_MAX_WIRE':1060,'LINK_FRAG_CHUNK_BYTES':714} for a in actors.values()),'Mixed compact wire versions; no IKE launch'
                    assert all(a['udp_receive_buffer']['effective_bytes']>=8388608 for a in actors.values()),'Buffer not accepted on every actor'
                    time.sleep(3);assert all(p.poll() is None for p,_,_ in captures)
                    # Only A-star readiness is required, not the twenty unrelated channels.
                    # Current actors publish the native session IDs in their mask-ready receipt.
                    ready={}
                    for u in g.ENDPOINTS:
                        cmd="/root/candidate-mcc-runtime3148-5002-restored-20261015/python/bin/python3.14 -B -c \"import json;from pathlib import Path;print('PUBLIC_JSON='+Path('"+str(ROOT/(job+'-MASK-READY.json'))+"').read_text())\""
                        ready[f'User{u}']=admission.remote_json(u,cmd)
                    a=attempt['initiator']
                    assert all(r.get('sender_ready') and not r.get('error') for r in ready.values()),'Owned sender not admitted before IKE'
                    assert all(ready[a]['native_sids'].get(p) and ready[a]['native_sids'][p]==ready[p]['native_sids'].get(a) for p in ready if p!=a),'Native A-star channels not matched; no IKE start'
                    atom(current_work/'MASK-ADMISSION.json',ready)
                    state['started_ids'].append(job);state.update(stage='running_connection',at_utc=g.now());atom(STATUS,state)
                    start=time.monotonic();up=v.node(source,'up',peer=receiver,job=job);ssh_s=time.monotonic()-start
                    ready=v.node(receiver,'status',peer=source)
                    ping=v.node(source,'ping',peer=receiver) if up['returncode']==0 and up['installed'] and ready['installed'] and up['mask_acceptance_passed'] else {'received':0}
                    time.sleep(1)
                    active_final={str(user):v.node(user,'direct') for user in g.ENDPOINTS}
                    atom(current_work/'ACTIVE-FINAL-COUNTERS.json',active_final)
                    socket_coverage=all(x.get('socket_owner_verified') and x.get('actor_job')==job for x in active_final.values())
                    # Drain residual in-flight datagrams after all senders stopped.
                    time.sleep(8)
                    checks=stop_captures(captures,current_work);captures=[]
                    packet_counts={label:len(v.decode(current_work/f'User{source}.pcap',bpf)) for label,bpf in {
                        'direct_ike':'udp port 500 or (udp port 4500 and udp[8:4] = 0)',
                        'overlay':'udp port 9000','esp':'esp or (udp port 4500 and udp[8:4] != 0)'}.items()}
                    assert packet_counts['direct_ike']==0, 'Protected path leaked direct IKE'
                    success=up['returncode']==0 and up['installed'] and ready['installed'] and up['mask_acceptance_passed'] and socket_coverage and ping.get('received')==3 and packet_counts['esp']>0 and packet_counts['overlay']>0
                    result={'attempt':attempt,'up':up,'ssh_elapsed_s':ssh_s,'receiver':ready,'ping':ping,'packet_counts':packet_counts,
                            'success':success,'captures':checks,'capture_manifest':{'format':'per_tap_ethernet','captures':manifest},
                            'actors':actors,'replayed':False,'protocol_modified':True,'compact_wire_version':2,'queue_changes':0,'max_limit':0}
                    atom(current_work/'RESULT.json',result)
                    # The first job is the live canary. Every later job also has this gate.
                    from mask_audit import ledger_check
                    try:mask_check=ledger_check(active_final,attempt['initiator'])
                    except Exception as error:mask_check={'passed':False,'coverage_unknown':True,'error_type':type(error).__name__}
                    atom(current_work/'MASK-LEDGER-CHECK.json',mask_check)
                    rolling.append({'attempt':attempt,'success':success,'up':up,'ssh_elapsed_s':ssh_s})
                    for user,peer in ((source,receiver),(receiver,source)):v.node(user,'down',peer=peer)
                    active_pair=None;state['completed_ids'].append(job);state['successful']+=int(success);state['failed']+=int(not success)
                    consecutive=0 if success else consecutive+1
                    state.update(stage='between_connections',current_id=None,at_utc=g.now(),progress=summarize(rolling,19));atom(STATUS,state)
                    assert mask_check['passed'] and success,'Canary/transport acceptance failed; stop, never replay'
                    assert consecutive<plan['max_consecutive_failures'] and state['failed']<plan['max_failures'], 'Failure safety threshold; retain all results, no retries'
            finally:
                if captures:
                    try:atom(current_work/'PARTIAL-CAPTURE-CHECK.json',stop_captures(captures,current_work))
                    finally:captures=[]
                state.update(stage='batch_evidence',at_utc=g.now());atom(STATUS,state)
                collection_errors=[]
                try:
                    after=pathcap.routers_snapshot(mapping);atom(batch_dir/'ROUTER-AFTER.json',after)
                    atom(batch_dir/'LOSS-CHECK.json',loss_deltas(before,after))
                except Exception as error:
                    collection_errors.append({'section':'router_counters','type':type(error).__name__})
                    atom(batch_dir/'LOSS-CHECK.json',{'passed':False,'complete':False,'unknown_is_not_zero':True,'error_type':type(error).__name__})
                for name,collector in (('UDP-AFTER.json',udp_snapshot),('HOST-AFTER.json',lambda:pathcap.host_counters(mapping)),('NODE-LOGS.json',logs)):
                    try:atom(batch_dir/name,collector())
                    except Exception as error:
                        collection_errors.append({'section':name,'type':type(error).__name__});atom(batch_dir/(name+'.ERROR.json'),{'type':type(error).__name__})
                atom(batch_dir/'COLLECTION-STATUS.json',{'passed':not collection_errors,'errors':collection_errors})
                receipt=export_tree(batch_dir,f'round-{batch_no:02d}');state['round_exports'].append(receipt);atom(STATUS,state)
                assert not collection_errors, 'Batch evidence exported; counter coverage incomplete; no silent zero and no replay'
        terminal='completed'
    except Exception as error:
        state.update(error_type=type(error).__name__,error=str(error)[:220],at_utc=g.now())
        atom(ROOT/'ERROR.json',{'type':type(error).__name__,'frames':[{'file':Path(f.filename).name,'line':f.lineno,'function':f.name} for f in traceback.extract_tb(error.__traceback__)]})
    finally:
        state.update(stage='cleaning_up',terminal_stage=terminal,at_utc=g.now());atom(STATUS,state)
        if captures:
            try:stop_captures(captures,current_work)
            except Exception:terminal='blocked'
        cleanup={}
        if initialized:
            for user in g.ENDPOINTS:
                try:cleanup[str(user)]=v.node(user,'direct')
                except Exception as error:cleanup[str(user)]={'error_type':type(error).__name__};terminal='blocked'
            if active_pair:
                a,b=active_pair
                for user,peer in ((a,b),(b,a)):
                    try:v.node(user,'down',peer=peer)
                    except Exception:terminal='blocked'
        atom(ROOT/'ACTOR-CLEANUP.json',cleanup)
        if mapping:
            try:
                final=pathcap.routers_snapshot(mapping,static=True);atom(ROOT/'ROUTER-FINAL.json',final)
                atom(ROOT/'QUEUE-FINAL-ACCEPTANCE.json',verify_queues(final,expected))
            except Exception as error:terminal='blocked';atom(ROOT/'QUEUE-FINAL-ERROR.json',{'type':type(error).__name__,'error':str(error)[:160]})
        shutdown={'sync':{},'stopped_node_ids':[]}
        if initialized:
            for user in g.ENDPOINTS:
                try:g.ssh(user,'sync',timeout=20);shutdown['sync'][str(user)]=True
                except Exception:shutdown['sync'][str(user)]=False
        if mapping:
            shutdown['router_guest_shutdown']=router_lifecycle.shutdown_all(mapping,v)
            if not all(x['passed'] for x in shutdown['router_guest_shutdown'].values()):terminal='blocked'
        for nid in reversed(state['started_node_ids']):
            p=subprocess.run(['/opt/unetlab/wrappers/unl_wrapper','-a','stop','-T','0','-F',str(v.LAB),'-D',str(nid)],capture_output=True,timeout=30)
            graceful=shutdown.get('router_guest_shutdown',{}).get(str(nid),{})
            router=next((r for r in mapping['routers'] if r['node_id']==nid),None) if mapping else None
            already_off=bool(graceful.get('passed') and router and not router_lifecycle.alive(router['console_proof']['qemu_pid']))
            if p.returncode==0 or already_off:shutdown['stopped_node_ids'].append(nid)
        subprocess.run(['sync'],check=True,timeout=30)
        shutdown['passed']=all(shutdown['sync'].values()) and set(shutdown['stopped_node_ids'])==set(state['started_node_ids'])
        atom(ROOT/'NODE-SHUTDOWN.json',shutdown)
        if not shutdown['passed']:terminal='blocked'
        state.update(stage=terminal,cleanup_done=False,at_utc=g.now());atom(STATUS,state)
        if (ROOT/'capacity').is_dir():
            receipt=export_tree(ROOT/'capacity','capacity-evidence');state['round_exports'].append(receipt);atom(STATUS,state)
        receipt=export_tree(ROOT,'final-evidence',exclude_children=True);atom(ROOT/'EXPORT-READY.json',receipt)
        state.update(cleanup_done=True,at_utc=g.now());atom(STATUS,state)
if __name__=='__main__':main()
