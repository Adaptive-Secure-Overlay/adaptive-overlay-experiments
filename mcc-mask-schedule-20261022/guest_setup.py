"""Clone-only existing-component deployment, canaries, then serial measurements."""
import ast, base64, hashlib, json, os, re, shutil, signal, subprocess, tarfile, time, traceback
from pathlib import Path
import guest_setup_network as g

ROOT=Path('/root/candidate-mcc-mask-schedule-20261022-r8'); STATUS=ROOT/'LIVE-STATUS.json'
LAB=Path('/opt/unetlab/labs/IPsec-Debian13-StrongSwan/01-core-mikrotik-4debian.unl')
IDS=[1,26,27,28,29,30,31,32,33,13,15,17,19,21,12,14,16,18,20]
NODE_SCRIPT=str(ROOT/'node_pilot_control.py')
def atom(p,v):
    tmp=p.with_suffix(p.suffix+'.tmp'); tmp.write_text(json.dumps(v,indent=2)); tmp.replace(p)
def no_physical(): assert not [p for p in Path('/sys/class/net').iterdir() if (p/'device').exists()]
def node(user,action,peer=None,job=None,mask_source=None,mask_token=None):
    args=['/root/candidate-mcc-runtime3148-5002-restored-20261015/python/bin/python3.14','-B',NODE_SCRIPT,action,f'User{user}']
    if peer: args+=['--peer',str(peer)]
    if job: args+=['--job',job]
    if mask_source:args+=['--mask-source',mask_source,'--mask-token',mask_token]
    out=g.ssh(user,' '.join(args),timeout=110 if action=='up' else 35)
    m=re.search(r'NODE_PILOT_JSON=(\{[^\r\n]+\})',out); assert m,'Missing owned-node result'
    return json.loads(m.group(1))
def decode(p,bpf):
    r=subprocess.run(['tcpdump','-r',str(p),'-tt','-nn','-q',bpf],capture_output=True,text=True,timeout=15)
    assert r.returncode==0
    return r.stdout.splitlines()
def setup(state,contract):
    import xml.etree.ElementTree as ET
    no_physical()
    lab=ET.parse(LAB).getroot(); assert lab.get('id')=='542bfe9b-f14f-44ca-973b-7477f3850705'
    nodes={int(n.get('id')):n for n in lab.findall('.//nodes/node')}
    expected={1:'ISP1-R1',26:'ISP1-R2',27:'ISP1-R3',28:'ISP2-R1',29:'ISP2-R2',30:'ISP2-R3',31:'ISP3-R1',32:'ISP3-R2',33:'ISP3-R3'}
    assert all(nodes[n].get('name')==label for n,label in expected.items() if n in IDS)
    ram=sum(int(nodes[n].get('ram')) for n in IDS); assert ram<=24576,'Nested guest memory cap exceeded'
    assert ram==20736,'Memory admission estimate applies only to the verified20736MiB node set'
    atom(ROOT/'CORE-ADMISSION.json',{'node_ids':IDS,'provider_core_nodes':expected,'configured_ram_mib':ram,'config_not_changed':True})
    assert not any(p.name.isdigit() and (p/'comm').exists() and (p/'comm').read_text().strip().startswith('qemu') for p in Path('/proc').iterdir()),'Nested VM already active'
    assert not Path('/sys/class/net/pnet0').exists()
    subprocess.run(['ip','link','add','name','pnet0','type','bridge'],check=True,capture_output=True)
    subprocess.run(['ip','link','set','dev','pnet0','up'],check=True,capture_output=True)
    assert not list(Path('/sys/class/net/pnet0/brif').iterdir())
    for nid in IDS:
        state.update(stage='starting_owned_nodes',current_node=nid); atom(STATUS,state)
        r=subprocess.run(['/opt/unetlab/wrappers/unl_wrapper','-a','start','-T','0','-F',str(LAB),'-D',str(nid)],capture_output=True,text=True,timeout=90)
        (ROOT/f'node-start-{nid}.log').write_text(r.stdout+r.stderr)
        assert r.returncode==0,f'Owned node start failed: {nid}'
        state['started_node_ids'].append(nid); atom(STATUS,state)
    arping=['arping'] if shutil.which('arping') else ['busybox','arping']
    for user,(_,bridge,address) in g.ENDPOINTS.items():
        assert (Path('/sys/class/net')/bridge/'bridge').exists()
        r=subprocess.run([*arping,'-D','-c','2','-w','3','-I',bridge,address],capture_output=True,timeout=5)
        assert r.returncode==0,'DAD failed for clone-only management address'
        subprocess.run(['ip','addr','add',address+'/24','dev',bridge],check=True,capture_output=True)
    # Bounded readiness on the five clone-only addresses, no credentials or mutation.
    import socket
    readiness={}; deadline=time.monotonic()+150
    while time.monotonic()<deadline:
        for user,(ip,_,_) in g.ENDPOINTS.items():
            if readiness.get(str(user),{}).get('ready'): continue
            try:
                with socket.create_connection((ip,22),timeout=2) as sock:
                    sock.settimeout(2); banner=sock.recv(256)
                readiness[str(user)]={'ready':banner.startswith(b'SSH-2.0-'),'last_error':None}
            except OSError as error: readiness[str(user)]={'ready':False,'last_error':type(error).__name__}
        atom(ROOT/'SSH-READINESS.json',{'nodes':readiness,'all_ready':all(readiness.get(str(u),{}).get('ready') for u in g.ENDPOINTS)})
        if all(readiness.get(str(u),{}).get('ready') for u in g.ENDPOINTS): break
        time.sleep(3)
    assert all(readiness.get(str(u),{}).get('ready') for u in g.ENDPOINTS),'Clone SSH readiness deadline; no deployment or IKE launch'
    time.sleep(3)
    package=base64.b64encode((ROOT/'candidate.tar.xz').read_bytes()).decode()
    control=base64.b64encode((ROOT/'node_pilot_control.py').read_bytes()).decode()
    observer=base64.b64encode((ROOT/'observed_daemon.py').read_bytes()).decode()
    # No old node directory is overwritten. All state, code, configuration backups are new.
    deployment="""/root/candidate-mcc-runtime3148-5002-restored-20261015/python/bin/python3.14 - <<'PY'
import traceback
from pathlib import Path
try:
 import ast,base64,hashlib,importlib.util,json,subprocess,tarfile
 from pathlib import Path
 for proc in Path('/proc').iterdir():
  if not proc.name.isdigit(): continue
  try:
   argv=[s.decode(errors='replace') for s in (proc/'cmdline').read_bytes().split(bytes([0])) if s]
   assert not any(Path(s).name in ('node_daemon.py','observed_daemon.py') for s in argv),'Existing overlay actor present; no replacement'
  except (FileNotFoundError,ProcessLookupError): pass
 assert ':9000' not in subprocess.check_output(['ss','-lun'],text=True),'Existing overlay listener present'
 r=Path('%s'); assert not r.exists(),'New deployment directory already exists'
 r.mkdir(mode=0o700)
 a=r/'candidate.tar.xz'; a.write_bytes(base64.b64decode('%s'))
 assert hashlib.sha256(a.read_bytes()).hexdigest()=='%s'
 assert importlib.util.find_spec('cryptography'),'Missing existing cryptography; installations prohibited'
 with tarfile.open(a) as tf:
  for m in tf.getmembers():
   p=Path(m.name); assert not p.is_absolute() and '..' not in p.parts and p.parts[0]=='code' and m.isfile()
   assert m.size<2097152
   out=r/p; out.parent.mkdir(parents=True,exist_ok=True); data=tf.extractfile(m).read()
   if p.suffix=='.py': ast.parse(data.decode())
   out.write_bytes(data); out.chmod(m.mode & 0o777)
 files={str(p.relative_to(r/'code')):hashlib.sha256(p.read_bytes()).hexdigest() for p in (r/'code').rglob('*') if p.is_file()}
 assert files==json.loads('%s')
 for name,data in [('node_pilot_control.py','%s'),('observed_daemon.py','%s'),('selection_policy.py','%s')]:
  p=r/name; p.write_bytes(base64.b64decode(data)); ast.parse(p.read_text()); p.chmod(0o700)
 for p in (r/'code/scripts').glob('*.sh'): subprocess.run(['bash','-n',str(p)],check=True,capture_output=True)
 receipt={'passed':True,'candidate_sha256':files['node_daemon.py'],'file_count':len(files),'old_code_untouched':True}
 (r/'RESTORED-CODE.json').write_text(json.dumps(receipt)); print('DEPLOY_JSON='+json.dumps(receipt))
except Exception as error:
 print('REMOTE_ERROR_JSON='+json.dumps({'type':type(error).__name__,'frames':[{'file':Path(f.filename).name,'line':f.lineno,'function':f.name} for f in traceback.extract_tb(error.__traceback__)]})); raise SystemExit(1)
PY""" % (ROOT,package,contract['archive_sha256'],json.dumps(contract['candidate_files']),control,observer,base64.b64encode((ROOT/'selection_policy.py').read_bytes()).decode())
    receipts={}
    for u in g.ENDPOINTS:
        state.update(stage='deploying_candidate_separately',current_user=u); atom(STATUS,state)
        raw=g.ssh(u,deployment,timeout=65); match=re.search(r'DEPLOY_JSON=(\{[^\r\n]+\})',raw); assert match
        receipts[str(u)]=json.loads(match.group(1)); atom(ROOT/'DEPLOYMENT.json',receipts)
        receipts[str(u)]['initialization']=node(u,'init'); atom(ROOT/'DEPLOYMENT.json',receipts)
    atom(ROOT/'DEPLOYMENT.json',receipts)
    state.update(stage='ready_for_canaries',current_user=None,current_node=None); atom(STATUS,state)
def collect_audit(job):
    result={}
    for u in g.ENDPOINTS:
        cmd="/root/candidate-mcc-runtime3148-5002-restored-20261015/python/bin/python3.14 - <<'PY'\nimport json\nfrom pathlib import Path\np=Path('"+str(ROOT/(job+'-audit.jsonl'))+"'); v=[json.loads(s) for s in p.read_text().splitlines()] if p.exists() else []; print('AUDIT_JSON='+json.dumps(v))\nPY"
        raw=g.ssh(u,cmd,timeout=25); m=re.search(r'AUDIT_JSON=(\[[^\r\n]*\])',raw); assert m
        result[str(u)]=json.loads(m.group(1))
    return result
def management_snapshot(job):
    begin=time.monotonic(); values={}
    for u in g.ENDPOINTS:
        p=str(ROOT/(job+'-audit.ready.json'))
        raw=g.ssh(u,"/root/candidate-mcc-runtime3148-5002-restored-20261015/python/bin/python3.14 - <<'PY'\nfrom pathlib import Path\np=Path('"+p+"'); print('READY_JSON='+p.read_text() if p.exists() else 'READY_JSON={}')\nPY",timeout=20)
        m=re.search(r'READY_JSON=(\{[^\r\n]+\})',raw); assert m
        values[f'User{u}']=json.loads(m.group(1)).get('sessions',{})
    matched=[[a,b] for a in values for b in values if a!=b and values[a].get(b) and values[a].get(b)==values[b].get(a)]
    return {'admission_rule':'native_adaptive_canary','diagnostic_only':True,'elapsed_s':time.monotonic()-begin,
        'peer_counts':{a:len(v) for a,v in values.items()},'matching_directed_links':len(matched),
        'all_twenty_links_match':len(matched)==20,'matches':matched,
        'session_cache_is_not_proof_of_live_channel':True}
def collect_logs(job):
    # Collect inside this live session, before owned actors and VM are stopped.
    records={}
    for u in g.ENDPOINTS:
        try:
            command="/root/candidate-mcc-runtime3148-5002-restored-20261015/python/bin/python3.14 - <<'PY'\nimport json\nfrom pathlib import Path\np=Path('"+str(ROOT/'code/logs')+"')/'User"+str(u)+".log'; lines=p.read_text(errors='replace').splitlines()[-180:] if p.exists() else []; print('LOG_JSON='+json.dumps(lines))\nPY"
            raw=g.ssh(u,command,timeout=20); m=re.search(r'LOG_JSON=(\[[^\r\n]*\])',raw); assert m
            # Saved role/protocol log only; never read environment, secrets or config.
            records[str(u)]=json.loads(m.group(1))
        except Exception as error: records[str(u)]={'error_type':type(error).__name__}
    atom(ROOT/(job+'-NODE-LOGS.json'),records)
def main():
    assert not STATUS.exists(),'Existing controller: never replay'
    plan=json.loads((ROOT/'SEALED-CONTRACT.json').read_text())
    state={'stage':'precheck','started_node_ids':[],'started_ids':[],'completed_ids':[], 'planned_attempts':len(plan['attempts']),'at_utc':g.now()}
    atom(STATUS,state); capture=None; initialized=False
    try:
        setup(state,plan); initialized=True
        for attempt in plan['attempts']:
            no_physical(); job=attempt['id']; peer=int(attempt['receiver'][4:]); work=ROOT/job
            assert not work.exists(); work.mkdir(mode=0o700)
            atom(work/'STATE.json',{'stage':'preparing','attempt':attempt})
            node(1,'down',peer=peer); node(peer,'down',peer=1)
            preparation_begin=time.monotonic()
            for u in g.ENDPOINTS: node(u,attempt['mode'],job=job)
            if attempt['mode']=='protected':
                state.update(stage='recording_management_diagnostic',current_id=job,at_utc=g.now()); atom(STATUS,state)
                health=management_snapshot(job); health['actor_preparation_s']=time.monotonic()-preparation_begin
                atom(work/'READINESS.json',health)
            cap=work/'capture.pcap'; log=(work/'capture.log').open('x')
            capture=subprocess.Popen(['tcpdump','-i','vnet0_6','-nn','-s','0','-B','4096','-U','-w',str(cap),'ip and not tcp port 22'],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=log)
            time.sleep(2); assert capture.poll() is None
            state.update(stage='running_connection',current_id=job,at_utc=g.now()); state['started_ids'].append(job); atom(STATUS,state)
            atom(work/'STATE.json',{'stage':'initiating_once','attempt':attempt})
            start=time.monotonic(); up=node(1,'up',peer=peer,job=job); ssh_s=time.monotonic()-start
            ready=node(peer,'status',peer=1)
            if up['returncode']==0:
                end=time.monotonic()+5
                while not ready['installed'] and time.monotonic()<end:
                    time.sleep(.25); ready=node(peer,'status',peer=1)
            ping=node(1,'ping',peer=peer) if up['returncode']==0 and ready['installed'] else {'received':0}
            time.sleep(1); capture.send_signal(signal.SIGINT); capture.wait(timeout=5); capture=None; log.close()
            ip=g.ENDPOINTS[peer][0]
            all_lines=decode(cap,'ip'); ts=[float(s.split()[0]) for s in all_lines]
            stats={'direct_ike_packets':len(decode(cap,f'host {ip} and (udp port 500 or (udp port 4500 and udp[8:4] = 0))')),
                'overlay_packets':len(decode(cap,'udp port 9000')),
                'esp_packets':len(decode(cap,'esp or (udp port 4500 and udp[8:4] != 0)')),
                'timestamp_regressions':sum(b<a for a,b in zip(ts,ts[1:])),
                'pcap_sha256':hashlib.sha256(cap.read_bytes()).hexdigest()}
            drops=re.search(r'(\d+) packets dropped by kernel',(work/'capture.log').read_text()); stats['drops']=int(drops.group(1)) if drops else None
            audit=collect_audit(job) if attempt['mode']=='protected' else {}
            events=sum(audit.values(),[])
            privacy={'accept_sends':sum(e['event']=='forbidden_accept_send' for e in events),
                'final_schema_events':sum(e['event']=='final_reverse_schema' for e in events),
                'initiator_received_events':sum(e['event']=='initiator_received_reverse' and e['node']=='User1' for e in events),
                'initiator_cache_events':sum(e['event']=='initiator_cache' and e['node']=='User1' for e in events),
                'all_schema_cache_checks_passed':all(e.get('passed',True) for e in events)}
            success=up['returncode']==0 and ready['installed'] and ping['received']==3 and stats['esp_packets']>0
            result={'attempt':attempt,'up':up,'ssh_ipsec_up_s':ssh_s,'receiver':ready,'ping':ping,'capture':stats,'privacy':privacy,'success':success,'replayed':False}
            atom(work/'RESULT.json',result); atom(work/'AUDIT.json',audit)
            if attempt['phase']=='canary' or not success: collect_logs(job)
            node(1,'down',peer=peer); node(peer,'down',peer=1)
            for u in g.ENDPOINTS: node(u,'direct')
            state['completed_ids'].append(job); state.update(stage='between_connections',current_id=None,at_utc=g.now()); atom(STATUS,state)
            assert success,f'Functional gate failed: {job}; no replay'
            assert stats['drops']==0 and stats['timestamp_regressions']==0,'Capture-quality gate failed'
            if attempt['mode']=='protected':
                assert stats['direct_ike_packets']==0 and stats['overlay_packets']>0,'Protected IKE-path gate failed'
                assert privacy['accept_sends']==0 and privacy['all_schema_cache_checks_passed'],'Privacy regression gate failed'
                assert privacy['final_schema_events']>0 and privacy['initiator_received_events']>0 and privacy['initiator_cache_events']>0,'Missing live privacy evidence'
            else: assert stats['direct_ike_packets']>0,'Direct IKE control missing'
            if len(state['completed_ids'])==2:
                atom(ROOT/'CANARY-ACCEPTANCE.json',{'passed':True,'ids':state['completed_ids'],'at_utc':g.now()})
        state.update(stage='completed',at_utc=g.now()); atom(STATUS,state)
    except Exception as error:
        state.update(stage='blocked',error_type=type(error).__name__,error=str(error)[:400],at_utc=g.now()); atom(STATUS,state)
        atom(ROOT/'CONTROLLER-ERROR.json',{'type':type(error).__name__,'frames':[{'file':Path(f.filename).name,'line':f.lineno,'function':f.name} for f in traceback.extract_tb(error.__traceback__)]})
        if state.get('current_id'): collect_logs(state['current_id'])
        elif state.get('current_user'): collect_logs('setup-failure')
    finally:
        if capture and capture.poll() is None:
            capture.send_signal(signal.SIGINT)
            try: capture.wait(timeout=5)
            except subprocess.TimeoutExpired: capture.kill(); capture.wait()
        cleanup={}
        if initialized:
            for u in g.ENDPOINTS:
                try: cleanup[str(u)]=node(u,'direct')
                except Exception as e: cleanup[str(u)]={'error_type':type(e).__name__}
            for peer in (2,3):
                for u,p in ((1,peer),(peer,1)):
                    try: node(u,'down',peer=p)
                    except Exception as e: cleanup[f'pair-{u}-{p}']={'error_type':type(e).__name__}
        atom(ROOT/'ACTOR-CLEANUP.json',cleanup)
        # Export exact new evidence only, with member/size limits.
        with tarfile.open(ROOT/'live-evidence.tar.gz','w:gz') as tf:
            for p in ROOT.rglob('*'):
                if p.is_file() and p.suffix in ('.json','.jsonl','.log','.pcap') and p.name!='candidate.tar.xz':
                    assert p.stat().st_size<32*1024**2
                    tf.add(p,arcname=str(p.relative_to(ROOT)),recursive=False)
        atom(ROOT/'EXPORT-READY.json',{'stage':state['stage'],'sha256':hashlib.sha256((ROOT/'live-evidence.tar.gz').read_bytes()).hexdigest(),'at_utc':g.now()})
if __name__=='__main__': main()
