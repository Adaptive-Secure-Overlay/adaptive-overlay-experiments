"""New immutable experiment contract, no VM or network action."""
import ast,hashlib,json,secrets,tarfile
from pathlib import Path
ROOT=Path(__file__).resolve().parent
BASE=ROOT.parent/'mcc_compact_series20_20261019'
def read(p):return json.loads(p.read_text(encoding='utf-8-sig'))
def sha(p):
    h=hashlib.sha256()
    with p.open('rb') as f:
        for b in iter(lambda:f.read(1024**2),b''):h.update(b)
    return h.hexdigest()
def main():
    assert not any((ROOT/n).exists() for n in ('SEALED-CONTRACT.json','HOST-STATUS.json','LAUNCH-RECEIPT.json','candidate.tar.xz'))
    old=read(BASE/'SEALED-CONTRACT.json');accepted=read(BASE/'ACCEPTANCE.json')
    assert accepted['passed'] and accepted['measurement_complete'] and read(BASE/'FINAL-SAFETY-CHECK.json')['copy_stopped']
    code=ROOT/'candidate-copy/code'
    files={p.relative_to(code).as_posix():sha(p) for p in code.rglob('*') if p.is_file() and '__pycache__' not in p.parts}
    assert all(files[n]==h for n,h in old['candidate_files'].items()),'Compact code or buffers modified'
    assert set(files)-set(old['candidate_files'])=={'mask_transport.py','mask_node.py','mask_gate.py','mask_sender.py'}
    assert sha(ROOT/'EXPECTED-QUEUES.json')==old['expected_queues_sha256']
    for p in [*ROOT.glob('*.py'),*code.rglob('*.py')]:ast.parse(p.read_text(encoding='utf-8-sig'),filename=str(p))
    previous=ROOT.parent/'mcc_mask_schedule_20261022_r4'
    assert read(previous/'FINAL-SAFETY-CHECK.json')['copy_stopped'] and read(previous/'HOST-STATUS.json').get('analysis')
    prior_plan=read(previous/'SEALED-CONTRACT.json')
    assert {n for n,h in prior_plan['candidate_files'].items() if files[n]!=h}=={'mask_node.py'},'Only sender integration may differ'
    assert set(files)-set(prior_plan['candidate_files'])=={'mask_sender.py'}
    prior_status=read(previous/'LIVE-STATUS.json');assert prior_status['completed_ids']==['ike_privacy_20261015_6200'] and prior_status['started_ids']==prior_status['completed_ids']
    diagnostic=ROOT.parent/'mcc_mask_schedule_20261019_r2'
    assert read(diagnostic/'FINAL-SAFETY-CHECK.json')['copy_stopped'],'Diagnostic still owns copy'
    assert read(diagnostic/'HOST-STATUS.json').get('analysis') and (diagnostic/'ACCEPTANCE.json').exists(),'Diagnostic report still active'
    prototype=ROOT.parent/'mcc_mask_schedule_20261022_r5'
    assert not (prototype/'LAUNCH-RECEIPT.json').exists() and not (prototype/'HOST-STATUS.json').exists(),'Uncertain prototype execution; stop'
    source_revision=ROOT.parent/'mcc_mask_schedule_20261022_r6'
    assert not (source_revision/'LAUNCH-RECEIPT.json').exists() and not (source_revision/'HOST-STATUS.json').exists(),'Uncertain prior19 submission; stop'
    assert files==read(source_revision/'SEALED-CONTRACT.json')['candidate_files'],'Memory revision must preserve entire tested sender/protocol package'
    prior_memory=ROOT.parent/'mcc_mask_schedule_20261022_r7'
    assert not (prior_memory/'LAUNCH-RECEIPT.json').exists() and not (prior_memory/'HOST-STATUS.json').exists(),'Uncertain previous memory revision; stop'
    assert files==read(prior_memory/'SEALED-CONTRACT.json')['candidate_files']
    ids=['ike_privacy_20261015_'+str(i) for i in range(6600,6619)]
    for p in ROOT.parent.glob('*/SEALED-CONTRACT.json'):
        assert set(ids).isdisjoint(read(p).get('execute_ids',[])),('Prior ID collision',str(p))
    attempts=[{**a,'id':ids[i],'continuation_of_id':a['id'],'phase':'mask_schedule_remaining19',
               'batch':1 if i==0 else 2+(i-1)//5,'mask_token':secrets.token_hex(16)} for i,a in enumerate(prior_plan['attempts'][1:])]
    assert len(attempts)==19 and len({a['mask_token'] for a in attempts})==19 and len({(a['initiator'],a['receiver']) for a in attempts})==19
    assert all((a['initiator'],a['receiver'])!=('User6','User9') for a in attempts),'Never repeat the failed prior pair'
    with tarfile.open(ROOT/'candidate.tar.xz','w:xz') as tf:
        for name in sorted(files):tf.add(code/name,arcname='code/'+name,recursive=False)
    preserved=dict(prior_plan['old_artifact_hashes'])
    for p in BASE.rglob('*'):
        if p.is_file() and '__pycache__' not in p.parts:preserved[str(p)]=sha(p)
    for directory in (ROOT.parent/'mcc_mask_schedule_20261019',ROOT.parent/'mcc_mask_schedule_20261019_recovery2',diagnostic,previous,prototype,source_revision,prior_memory):
        for p in directory.rglob('*'):
            if p.is_file() and '__pycache__' not in p.parts:preserved[str(p)]=sha(p)
    assert all(sha(Path(n))==h for n,h in preserved.items())
    helpers=[*old['helpers'],'mask_audit.py','capacity_gate.py','capacity_probe.py']
    hosts=set(old['host_and_report_hashes'])|{p.name for p in ROOT.glob('*.py')}
    plan={**old,'attempts':attempts,'execute_ids':ids,'candidate_files':files,
          'helpers':{n:sha(ROOT/n) for n in helpers},'host_and_report_hashes':{n:sha(ROOT/n) for n in sorted(hosts)},
          'archive_sha256':sha(ROOT/'candidate.tar.xz'),'old_artifact_hashes':preserved,
          'cover_scheduler_enabled':True,'queue_changes_authorized':False,
          'mask_contract':{'records_per_peer_direction':1000,'udp_bytes':1124,'ip_bytes':1152,'slot_interval_s':.002,
                           'window_s':2.,'guard_s':.1,'max_lateness_s':.02,'at_A_ip_bytes':9216000,
                           'actual_receiver_is_not_scheduler_input':True,'native_A_star_required':True,
                           'initial_canary':ids[0],'ESP_gate':'temporary owned nft table; ANY early ESP/NAT-T drop FAILS acceptance',
                           'no_application_traffic_until_after_common_cover_end':True,
                           'selection_timer_unchanged':True,'native_time_and_usable_time_reported_separately':True},
          'only_functional_change':'Copy-only encrypted fixed-size A-star cover scheduler and experimental ESP barrier. Original compact code/buffers unmodified.',
          'comparability_limits':'Only remaining19 directed pairs, first then18; prior failed6200 not repeated or pooled as success. Sender version differs from prior failed canary. Fixed2s plus100ms,18 metadata rules, not all ML attacks. Historical matched compact baseline. Separate native/usable/SSH times. Any early ESP/drop/missing ledger fails.',
          'decision':'Reuse finite singleton executor and stdlib spawn sender. Protocol/security/UDP buffers and original Schedule/Codec unchanged. Isolated interpreter and bounded IPC prevent protocol GIL/locks blocking timed sender. No real-time guarantee on VM: unchanged20ms fail-closed gate, additionally checked after actual send. Same fresh capacity admission.',
          'continuation':{'prior_root':str(previous),'prior_completed_failed_ids':prior_status['completed_ids'],'remaining_count':19,'prior20_success_claimed':False},
          'decision_evidence_sha256':sha(ROOT/'DECISION-RU.txt'),
          'memory_admission':{'startup_physical_gib':48,'startup_commit_gib':36,'runtime_physical_and_commit_gib':16,
              'full_node_ram_mib':20736,'full_node_stability_s':30,'sample_interval_s':1,
              'startup_permission_is_preparation_only':True,'actual_full_load_grant_required_before_IKE':True,
              'assurance':'Conditional staged admission, not a lower runtime reserve or absolute guarantee against unrelated host allocations',
              'report_sha256':sha(ROOT/'MEMORY-ADMISSION-RU.txt')},
          'capacity_contract':{'source_rate_ip_bps':26000000,'duration_s':2.,'minimum_measured_ip_bps':22000000,'required_mask_rate_per_direction_ip_bps':18432000,'peers':['User6','User7'],'physical_egress':['ether1','ether2'],'full_delivery_required':True,'allowed_repair':'at most one User6 guest OS reboot','image_or_license_or_buffer_changes':False,'failed_admission_starts_IKE':False},
          'initial_state':'Sealed offline, local and fresh live gates still required'}
    with (ROOT/'SEALED-CONTRACT.json').open('x',encoding='utf-8') as f:json.dump(plan,f,ensure_ascii=False,indent=2)
    print(json.dumps({'sealed':True,'connections':19,'canary':ids[0],'buffers_and_compact_code_unchanged':True,'vm_started':False}))
if __name__=='__main__':main()
