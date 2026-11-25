"""Existing singleton clone, finite native controller, incremental bounded export."""
import ast,ctypes,hashlib,json,os,sys,tarfile,time,traceback
from pathlib import Path
ROOT=Path(__file__).resolve().parent;sys.dont_write_bytecode=True
sys.path.insert(0,str(ROOT.parent/'ike_real_ab_pilot_20261014'))
import boot_stage as b
sys.path.insert(0,str(ROOT))
import memory_policy
GUEST='/root/candidate-mcc-mask-schedule-20261022-r8';STATUS=ROOT/'HOST-STATUS.json'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def atom(p,v):b.c.atom(p,v)
def source_state():
    return {'configuration_hashes':{str(p):sha(p) for p in b.c.SOURCE.iterdir() if p.is_file() and p.suffix in ('.vmx','.vmsd','.vmxf','.nvram')},
            'disk_metadata':[b.c.metadata(p) for p in b.c.SOURCE.glob('*.vmdk')]}
def receive(receipt,destination):
    name=receipt['name'];assert name in ('final-evidence','capacity-evidence') or name in {f'round-{i:02d}' for i in range(1,6)}
    archive=ROOT/(name+'.tar.gz');assert not archive.exists() and not destination.exists(), 'Existing export: reconcile, do not overwrite'
    b.vmrun(['copyFileFromGuestToHost',b.c.VMX,GUEST+'/'+archive.name,archive],guest=True)
    assert sha(archive)==receipt['sha256'];destination.mkdir(parents=True)
    with tarfile.open(archive) as tf:
        members=tf.getmembers();assert len(members)<=300 and sum(m.size for m in members)<=192*1024**2
        for member in members:
            p=Path(member.name);assert member.isfile() and not p.is_absolute() and '..' not in p.parts and member.size<=32*1024**2
            target=destination/p;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(tf.extractfile(member).read())
    assert len(members)==receipt['files'] and sum(m.size for m in members)==receipt['bytes']
    atom(ROOT/(name+'-RECEIVED.json'),receipt)
def credentials():
    tree=ast.parse((ROOT.parents[1]/'Testing-EVE-NG/LegacyWorkspace/tools/traffic_ml_pilot_eve.py').read_text(encoding='utf-8-sig'))
    node=next(ast.literal_eval(n.value) for n in tree.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='PASSWORD' for t in n.targets))
    tree=ast.parse((ROOT.parents[1]/'Testing-EVE-NG/LegacyWorkspace/configure_eve_mikrotik_clients.py').read_text(encoding='utf-8-sig'))
    router=next(ast.literal_eval(n.value) for n in tree.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='ADMIN_PASSWORD' for t in n.targets)).decode()
    return node,router
def main():
    assert not STATUS.exists(), 'Existing controller: reconcile, never replay'
    plan=json.loads((ROOT/'SEALED-CONTRACT.json').read_text())
    k=ctypes.WinDLL('kernel32',use_last_error=True);k.CreateMutexW.argtypes=[ctypes.c_void_p,ctypes.c_bool,ctypes.c_wchar_p];k.CreateMutexW.restype=ctypes.c_void_p
    handle=k.CreateMutexW(None,True,'Local\\CandidateIkeABPilot20261014');assert handle and ctypes.get_last_error()!=183,'Clone already owned'
    state={'stage':'precheck','controller_pid':os.getpid(),'planned_attempts':19,'received_batches':[],'at_utc':b.c.now()};started=False;before=source_state();last={};monitor=memory_policy.Monitor(ROOT);memory_wait=None;memory_granted=False
    try:
        assert Path(r'C:\Program Files\Wireshark\tshark.exe').is_file(), 'Existing offline decoder executable unavailable; no installs'
        assert all(sha(ROOT/n)==v for n,v in {**plan['helpers'],**plan['host_and_report_hashes']}.items())
        assert sha(ROOT/'candidate.tar.xz')==plan['archive_sha256'] and sha(ROOT/'EXPECTED-QUEUES.json')==plan['expected_queues_sha256']
        baseline=json.loads((ROOT.parent/'mcc_adaptive_series100_20261017/ACCEPTANCE.json').read_text())
        assert baseline['measurement_complete'] and baseline['summary']['completed']==100 and baseline['copy_stopped']
        assert plan['execute_ids']==['ike_privacy_20261015_'+str(i) for i in range(6600,6619)]
        assert plan['compact_candidate_authorized'] and plan['compact_wire_version']==2 and plan['cover_scheduler_enabled']
        adaptive=json.loads((ROOT.parent/'mcc_adaptive_wait_20261017/ACCEPTANCE.json').read_text());assert adaptive['passed'] and adaptive['results']==12
        tests=json.loads((ROOT/'LOCAL-TESTS.json').read_text());assert tests['passed'] and tests['contract_sha256']==sha(ROOT/'SEALED-CONTRACT.json')
        assert tests['gil_regression_sha256']==sha(ROOT/'GIL-REGRESSION.json')
        previous=json.loads((ROOT.parent/'mcc_buffer512_validation_20261015/FINAL-ACCEPTANCE-SUMMARY.json').read_text())
        assert previous['stage']=='verified' and previous['all_vms_stopped_final_readback'] and previous['added_buffers']==20
        sys.path.insert(0,str(ROOT));import readiness
        readiness.validate(json.loads((ROOT.parent/'chr7245_unlimited_migration_20261016/NETWORK-SPEED-ACCEPTANCE.json').read_text()))
        assert 'Total running VMs: 0' in b.vmrun(['list'])
        assert all(sha(Path(n))==v for n,v in plan['old_artifact_hashes'].items())
        state.update(isolation=b.c.vmx_contract(),memory=memory_policy.admit(),source_before=before);atom(STATUS,state)
        assert state['isolation']['ram_gib']==32 and state['isolation']['vcpus']==4
        monitor.start()
        b.vmrun(['start',b.c.VMX,'nogui'],timeout=120);started=True;state.update(stage='booting_copy');atom(STATUS,state)
        time.sleep(25);monitor.check();b.memory_gate(16);b.c.vmx_contract();assert str(b.c.SOURCE_VMX) not in b.vmrun(['list'])
        b.vmrun(['listProcessesInGuest',b.c.VMX],guest=True,timeout=30)
        b.vmrun(['runProgramInGuest',b.c.VMX,'/usr/bin/test','!','-e',GUEST],guest=True)
        b.vmrun(['runProgramInGuest',b.c.VMX,'/bin/mkdir','-m','700',GUEST],guest=True)
        for name in (*plan['helpers'],'candidate.tar.xz','SEALED-CONTRACT.json','EXPECTED-QUEUES.json'):
            b.vmrun(['copyFileFromHostToGuest',b.c.VMX,ROOT/name,GUEST+'/'+name],guest=True)
        node,router=credentials()
        b.vmrun(['runProgramInGuest',b.c.VMX,'-noWait','/usr/bin/env','PILOT_NODE_CREDENTIAL='+node,'ROUTER_ADMIN_CREDENTIAL='+router,
                 '/root/candidate-mcc-runtime3148-5002-restored-20261015/python/bin/python3.14','-B',GUEST+'/guest_live.py'],guest=True)
        node=None;router=None;state.update(stage='guest_controller_submitted');atom(STATUS,state)
        deadline=time.monotonic()+plan['max_wall_s']
        while time.monotonic()<deadline:
            time.sleep(10);monitor.check();b.memory_gate(16);b.c.vmx_contract();assert str(b.c.SOURCE_VMX) not in b.vmrun(['list'])
            try:b.vmrun(['copyFileFromGuestToHost',b.c.VMX,GUEST+'/LIVE-STATUS.json',ROOT/'LIVE-STATUS.json'],guest=True)
            except RuntimeError:continue
            last=json.loads((ROOT/'LIVE-STATUS.json').read_text());state.update(stage='running',guest=last,at_utc=b.c.now());atom(STATUS,state)
            if last.get('stage')=='awaiting_full_load_memory_admission' and not memory_granted:
                assert not last['started_ids'],'Memory grant must precede every IKE attempt'
                if memory_wait is None:memory_wait=time.monotonic()
                grant=monitor.stable(memory_wait)
                if grant:
                    grant.update(contract_sha256=sha(ROOT/'SEALED-CONTRACT.json'),at_utc=b.c.now())
                    target=ROOT/'MEMORY-RUN-ADMISSION.json';assert not target.exists();atom(target,grant)
                    b.vmrun(['copyFileFromHostToGuest',b.c.VMX,target,GUEST+'/'+target.name+'.tmp'],guest=True)
                    b.vmrun(['runProgramInGuest',b.c.VMX,'/bin/mv','-n',GUEST+'/'+target.name+'.tmp',GUEST+'/'+target.name],guest=True)
                    memory_granted=True;state['full_load_memory_admitted']=True;atom(STATUS,state)
            for receipt in last.get('round_exports',[]):
                if receipt['name'] not in state['received_batches']:
                    receive(receipt,ROOT/'evidence'/receipt['name']);state['received_batches'].append(receipt['name']);atom(STATUS,state)
            if last.get('stage') in ('completed','blocked') and last.get('cleanup_done'):break
        else:raise TimeoutError('Finite series deadline; preserve all started ids; do not replay')
        b.vmrun(['copyFileFromGuestToHost',b.c.VMX,GUEST+'/EXPORT-READY.json',ROOT/'EXPORT-READY.json'],guest=True)
        receive(json.loads((ROOT/'EXPORT-READY.json').read_text()),ROOT/'evidence/final')
        state.update(stage=last['stage'],guest=last,at_utc=b.c.now())
    except Exception as error:
        state.update(stage='blocked',error_type=type(error).__name__,error=str(error)[:250],at_utc=b.c.now())
        atom(ROOT/'HOST-ERROR.json',{'type':type(error).__name__,'frames':[{'file':Path(f.filename).name,'line':f.lineno,'function':f.name} for f in traceback.extract_tb(error.__traceback__)]})
    finally:
        if started:
            try:
                if str(b.c.VMX) in b.vmrun(['list']):b.vmrun(['stop',b.c.VMX,'soft'],timeout=90)
                state['owned_clone_stopped']=str(b.c.VMX) not in b.vmrun(['list'])
            except Exception:state['owned_clone_stop_unconfirmed']=True
        state['memory_profile']=monitor.close()
        try:
            assert source_state()==before and all(sha(Path(n))==v for n,v in plan['old_artifact_hashes'].items())
            source=ROOT.parents[1]/'Development-WireGuard/mcc-e2e-20261015/candidate'
            assert all(sha(source/n)==v for n,v in plan['source_candidate_files'].items())
            safe={'passed':True,'source_not_started':str(b.c.SOURCE_VMX) not in b.vmrun(['list']),
                  'original_config_and_disk_metadata_unchanged':True,'old_results_unchanged':True,'protocol_source_preserved':True,
                  'copy_stopped':state.get('owned_clone_stopped',False),'documents_changed':False,'keenetic_touched':False,'new_packages_installed':False}
            atom(ROOT/'FINAL-SAFETY-CHECK.json',safe)
        except Exception as error:state['safety_error_type']=type(error).__name__
        state['at_utc']=b.c.now();atom(STATUS,state)
        k.CloseHandle.argtypes=[ctypes.c_void_p];k.CloseHandle(handle)
    # Reporting is part of this finite controller, after the copy has stopped.
    try:
        sys.path.insert(0,str(ROOT));import report_mask as analyse_series
        state['analysis']=analyse_series.main();atom(STATUS,state)
    except Exception as error:
        state['analysis_error_type']=type(error).__name__;state['analysis_error']=str(error)[:200];atom(STATUS,state)
        atom(ROOT/'ANALYSIS-ERROR.json',{'type':type(error).__name__,'frames':[{'file':Path(f.filename).name,'line':f.lineno,'function':f.name} for f in traceback.extract_tb(error.__traceback__)]})
    return 0 if state['stage']=='completed' and state.get('analysis',{}).get('passed') else 1
if __name__=='__main__':raise SystemExit(main())
