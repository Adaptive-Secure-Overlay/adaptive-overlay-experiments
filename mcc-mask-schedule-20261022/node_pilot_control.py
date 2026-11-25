"""Temporary, owned-node control. No packages, global XFRM flush, or config replacement."""
import argparse,hashlib,json,os,re,signal,subprocess,time,sys,importlib.metadata
from pathlib import Path
ROOT=Path('/root/candidate-mcc-mask-schedule-20261022-r8')
CODE=ROOT/'code'; STATE=ROOT/'OWNED-PROCESS.json'
PROFILE={'OVERLAY_ACTIVE_USERS':'User6,User7,User8,User9,User10','IKE_MCC_ENABLED':'1',
 'IKE_MCC_FANOUT':'2','IKE_MCC_X1_FANOUT':'2','IKE_MCC_X2_FANOUT':'2','IKE_MCC_IKE_FANOUT':'2',
 'IKE_MCC_ROUTE_TIMEOUT_S':'1','IKE_MCC_ACCEPT_WINDOW_S':'0','IKE_ROUTE_CACHE_TTL_S':'120',
 'IKE_MCC_ACCEPT_MODE':'adaptive','IKE_MCC_ACCEPT_MIN_COPIES':'3','IKE_MCC_ACCEPT_QUIET_S':'0.150',
 'OVERLAY_LOG_CONSOLE':'0','PRECONNECT_ENABLED':'1'}
PROFILE.update({
 'MCC_SIGNING_KEY_FILE':str(ROOT/'identity/signing.key'),
 'MCC_ENCRYPTION_KEY_FILE':str(ROOT/'identity/encryption.key'),
 'MCC_REPLAY_STATE_FILE':str(ROOT/'endpoint-replay.sqlite'),
 'IKE_CASCADE_TRUST_ROOT_FILE':str(ROOT/'trust-root.json'),
 'IKE_CASCADE_TRUST_REGISTRY_FILE':str(ROOT/'registry.json'),
 'IKE_CASCADE_TRUST_STATE_FILE':str(ROOT/'registry-state.json'),
 'IKE_CASCADE_TRUST_BACKUP_FILE':str(ROOT/'registry-backup.json'),
})
def run(args,timeout=15):
    r=subprocess.run(args,capture_output=True,text=True,timeout=timeout)
    return r.returncode,r.stdout,r.stderr

def connection_state(status):
    return {'established':'ESTABLISHED' in status,'installed':'INSTALLED' in status}
def atom(path,value):
    tmp=path.with_suffix('.tmp'); tmp.write_text(json.dumps(value,indent=2)); tmp.replace(path)
def owned(argv,name):
    return str(ROOT/'observed_daemon.py') in argv and '--name' in argv and argv[argv.index('--name')+1]==name
def invariant():
    return {'ipsec_conf_sha256':hashlib.sha256(Path('/etc/ipsec.conf').read_bytes()).hexdigest(),
       'routes':json.loads(subprocess.check_output(['ip','-j','route','show'],text=True)),
       'mtu':{v['ifname']:v['mtu'] for v in json.loads(subprocess.check_output(['ip','-j','link','show'],text=True))}}
def stop(name):
    if STATE.exists():
        state=json.loads(STATE.read_text()); pid=state.get('pid')
        if pid and Path(f'/proc/{pid}/cmdline').exists():
            argv=[s.decode(errors='replace') for s in Path(f'/proc/{pid}/cmdline').read_bytes().split(bytes([0])) if s]
            assert owned(argv,name),'Refusing to signal non-owned PID'
            os.kill(pid,signal.SIGTERM)
            deadline=time.monotonic()+4
            while time.monotonic()<deadline and Path(f'/proc/{pid}/cmdline').exists():
                if not Path(f'/proc/{pid}/cmdline').read_bytes(): break
                time.sleep(.1)
            if Path(f'/proc/{pid}/cmdline').exists() and Path(f'/proc/{pid}/cmdline').read_bytes():
                os.kill(pid,signal.SIGKILL)
        atom(STATE,{'pid':None,'name':name,'stopped':True})
    r=run(['bash',str(CODE/'scripts/ike_proxy_nft_clear.sh')]); assert r[0]==0,'Owned proxy-rule clear failed'
    assert run(['nft','list','table','inet','ikeproxy'])[0]!=0,'IKE interception still active'
    if (ROOT/'MASK-GATE-OWNER.json').exists():
        sys.path.insert(0,str(ROOT/'code'))
        import mask_gate
        gate=json.loads((ROOT/'MASK-GATE-OWNER.json').read_text())
        mask_gate.release(ROOT,gate['job'])
def main():
    global CODE
    assert sys.version_info[:3]==(3,14,8) and importlib.metadata.version('cryptography')=='50.0.2','Wrong project runtime'
    parser=argparse.ArgumentParser(); parser.add_argument('action',choices=('init','protected','direct','down','up','ping','status'))
    parser.add_argument('--variant',choices=('old','new'),default='new'); parser.add_argument('--seed',type=int,default=0); parser.add_argument('name'); parser.add_argument('--job'); parser.add_argument('--peer',type=int)
    parser.add_argument('--mask-source');parser.add_argument('--mask-token');args=parser.parse_args()
    CODE=ROOT/'code'/('old' if args.variant=='old' else '')
    assert re.fullmatch(r'User(?:[6-9]|10)',args.name)
    restored=json.loads((ROOT/'RESTORED-CODE.json').read_text()); assert restored['passed']
    value={'action':args.action,'name':args.name}
    if args.action=='init':
        assert not (ROOT/'NODE-BASELINE.json').exists(),'Existing initialization: reconcile'
        assert 'INSTALLED' not in run(['ipsec','status'])[1],'Unrelated installed SA present'
        for file in ('ipsec.conf','ipsec.secrets'):
            source=Path('/etc')/file; destination=ROOT/('before-'+file); destination.write_bytes(source.read_bytes()); destination.chmod(0o600)
        rc,out,_=run(['nft','list','table','inet','ikeproxy'])
        if rc==0:
            p=ROOT/'before-ikeproxy.nft'; p.write_text(out); p.chmod(0o600)
        atom(ROOT/'NODE-BASELINE.json',invariant())
        stop(args.name)
        r=run(['bash',str(CODE/'scripts/xfrm_overlay_bypass.sh')]); assert r[0]==0,'Scoped UDP overlay bypass failed'
        # Inspect effective settings without exposing USERS passwords or complete VPN configuration.
        env=os.environ.copy(); env.update(PROFILE)
        code="import config,json; print(json.dumps({k:getattr(config,k,None) for k in ('ACTIVE_USERS','IKE_MCC_ENABLED','IKE_MCC_X1_FANOUT','IKE_MCC_X2_FANOUT','IKE_MCC_IKE_FANOUT','IKE_MCC_ACCEPT_WINDOW_S','IKE_MCC_ROUTE_TIMEOUT_S')}))"
        r=subprocess.run(['/root/candidate-mcc-runtime3148-5002-restored-20261015/python/bin/python3.14','-B','-c',code],cwd=CODE,env=env,capture_output=True,text=True,check=True)
        value.update(effective=json.loads(r.stdout),invariant=invariant(),native_ssh_daemon=True)
    elif args.action in ('protected','direct'):
        if args.action=='direct' and STATE.exists():
            try:
                state=json.loads(STATE.read_text()); pid=state.get('pid')
                if pid and Path(f'/proc/{pid}/cmdline').exists():
                    argv=[s.decode(errors='replace') for s in Path(f'/proc/{pid}/cmdline').read_bytes().split(bytes([0])) if s]
                    assert owned(argv,args.name),'Cannot collect from non-owned actor'
                    import node_diag
                    counts=node_diag.counters();inodes={str(x['inode']) for x in counts['overlay_sockets']};links=set()
                    for f in Path(f'/proc/{pid}/fd').iterdir():
                        try:links.add(f.readlink().name)
                        except FileNotFoundError:pass
                    assert len(inodes)==1 and all('socket:['+inode+']' in links for inode in inodes),'Overlay socket owner unconfirmed'
                    value.update(active_final_counters=counts,socket_owner_verified=True,actor_job=state['job'])
            except Exception as error:
                value.update(socket_owner_verified=False,counter_error_type=type(error).__name__)
        prior_job=json.loads(STATE.read_text()).get('job') if STATE.exists() else None
        stop(args.name)
        if args.action=='direct' and prior_job:
            receipt=ROOT/(prior_job+'-MASK-FINAL.json')
            value['mask_result']=json.loads(receipt.read_text()) if receipt.exists() else {'missing_final':True}
        assert invariant()==json.loads((ROOT/'NODE-BASELINE.json').read_text()),'Crypto, MTU or routing drift'
        if args.action=='protected':
            assert args.job and re.fullmatch(r'ike_privacy_20261015_\d{4}',args.job)
            assert args.mask_source in ('User6','User7','User8','User9','User10') and re.fullmatch('[0-9a-f]{32}',args.mask_token or '')
            assert 'INSTALLED' not in run(['ipsec','status'])[1], 'Unrelated SA prevents experimental ESP gate'
            sys.path.insert(0,str(CODE));import mask_gate
            mask_gate.install(ROOT,args.job)
            r=run(['bash',str(CODE/'scripts/ike_proxy_nft_apply.sh')]); assert r[0]==0,'Proxy configuration failed'
            env=os.environ.copy(); env.update(PROFILE); env['AB_VARIANT']=args.variant; env['AB_SEED']=str(args.seed); env['OVERLAY_LOG_FILE']=str(ROOT/(args.job+'-overlay.log')); env['PRIVACY_AUDIT_FILE']=str(ROOT/(args.job+'-audit.jsonl'))
            receipt=ROOT/(args.job+'-RCVBUF.json'); assert not receipt.exists(),'Buffer receipt already exists; no replay'
            env['OVERLAY_RCVBUF_RECEIPT']=str(receipt)
            policy_receipt=ROOT/(args.job+'-POLICY.json');assert not policy_receipt.exists(),'Existing policy receipt; no replay'
            env['SELECTION_POLICY_RECEIPT']=str(policy_receipt)
            env.update(MASK_ROOT=str(ROOT),MASK_JOB=args.job,MASK_SOURCE=args.mask_source,MASK_TOKEN=args.mask_token)
            child=subprocess.Popen(['/root/candidate-mcc-runtime3148-5002-restored-20261015/python/bin/python3.14','-B',str(ROOT/'observed_daemon.py'),'--name',args.name,'--ike-proxy'],
                cwd=CODE,env=env,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,start_new_session=True)
            atom(STATE,{'pid':child.pid,'name':args.name,'job':args.job})
            time.sleep(1)
            assert child.poll() is None,'Restored daemon exited at startup'
            buffer=json.loads(receipt.read_text()); assert buffer['pid']==child.pid and buffer['effective_bytes']>=8388608 and buffer['effective_bytes']>buffer['before_bytes'],'Buffer readback failed'
            value['udp_receive_buffer']=buffer
            from selection_policy import EXPECTED,validate
            actual_policy=json.loads(policy_receipt.read_text());assert actual_policy['pid']==child.pid and actual_policy['name']==args.name
            validate(actual_policy['policy']);value['selection_policy']=actual_policy['policy']
            assert ':9000' in subprocess.check_output(['ss','-lun'],text=True),'Overlay socket not listening'
            import ast
            transport=ast.parse((CODE/'link_transport.py').read_text())
            wire={n.targets[0].id:ast.literal_eval(n.value) for n in transport.body if isinstance(n,ast.Assign) and len(n.targets)==1 and isinstance(n.targets[0],ast.Name) and n.targets[0].id in ('LINK_CIPHER_VERSION','LINK_FRAG_MAX_WIRE','LINK_FRAG_CHUNK_BYTES')}
            assert wire=={'LINK_CIPHER_VERSION':2,'LINK_FRAG_MAX_WIRE':1060,'LINK_FRAG_CHUNK_BYTES':714}
            value.update(pid=child.pid,ike_proxy=True,variant=args.variant,seed=args.seed,code_sha256=hashlib.sha256((CODE/'node_daemon.py').read_bytes()).hexdigest(),transport_sha256=hashlib.sha256((CODE/'link_transport.py').read_bytes()).hexdigest(),compact_wire=wire,invariant=invariant())
        else: value.update(pid=None,ike_proxy=False)
    else:
        assert args.peer in range(6,11) and args.peer!=int(args.name[4:])
        connection='to-node'+str(args.peer)
        if args.action=='down':
            rc,out,_=run(['timeout','12','ipsec','down',connection],timeout=15)
            assert rc!=124,'Pair cleanup timeout'
            status=run(['ipsec','status',connection])[1]
            assert 'ESTABLISHED' not in status and 'INSTALLED' not in status,'Pair SA remains active'
            value.update(returncode=rc,installed=False)
        elif args.action=='up':
            assert args.job and re.fullmatch(r'ike_privacy_20261015_\d{4}',args.job)
            marker=ROOT/(args.job+'-UP-STARTED.json'); assert not marker.exists(),'Never repeat an initiated job'
            atom(marker,{'connection':connection,'initiated_at_epoch':time.time()})
            t=time.monotonic(); rc,out,_=run(['timeout','90','ipsec','up',connection],timeout=95)
            elapsed=time.monotonic()-t
            status_rc,status,_=run(['ipsec','status',connection])
            assert status_rc==0,'Cannot confirm local SA state'
            value.update(returncode=rc,elapsed_seconds=elapsed,timeout=rc==124,
                state_observed_by='ipsec status',**connection_state(status))
            atom(ROOT/(args.job+'-UP-OBSERVED.json'),value)
            # Native SA-up time and usable-after-cover time are NOT the same metric.
            barrier_deadline=time.monotonic()+5
            while time.monotonic()<barrier_deadline:
                ready=json.loads((ROOT/(args.job+'-MASK-READY.json')).read_text())
                if ready['done'] or ready['error']:break
                time.sleep(.05)
            value.update(mask_acceptance_passed=bool(ready['done'] and not ready['error']),
                         usable_elapsed_seconds=time.monotonic()-t if ready['done'] and not ready['error'] else None,
                         mask_gate=ready['gate'],mask_status=ready)
            # Only protocol metadata; no keys, secret configuration or raw XFRM state.
            value['protocol_lines']=[line.strip() for line in out.splitlines() if any(word in line for word in ('ESTABLISHED','INSTALLED','selected proposal','established successfully','failed','ERROR'))][-12:]
        elif args.action=='ping':
            rc,out,_=run(['ping','-n','-c','3','-s','56','-i','1','-W','2',f'192.168.{100+args.peer}.10'],timeout=12)
            m=re.search(r'(\d+) packets transmitted, (\d+) received',out)
            value.update(returncode=rc,transmitted=int(m.group(1)) if m else None,received=int(m.group(2)) if m else None)
        elif args.action=='status':
            status=run(['ipsec','status',connection])[1]
            value.update(installed='INSTALLED' in status,established='ESTABLISHED' in status)
    print('NODE_PILOT_JSON='+json.dumps(value))
if __name__=='__main__':
    try: main()
    except Exception as error:
        import traceback
        diagnostic={'type':type(error).__name__,'frames':[{'file':Path(f.filename).name,'line':f.lineno,'function':f.name} for f in traceback.extract_tb(error.__traceback__)]}
        print('REMOTE_ERROR_JSON='+json.dumps(diagnostic)); raise SystemExit(1)
