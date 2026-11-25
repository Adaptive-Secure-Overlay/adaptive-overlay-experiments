"""Seal a new20-job copy; reuse existing finite runner, queues and buffer adapter."""
import ast,hashlib,json,tarfile
from pathlib import Path
ROOT=Path(__file__).resolve().parent
BASE=ROOT.parent/'mcc_adaptive_series100_20261017'
COMPACT=ROOT.parent/'mcc_compact_wire_candidate_20261019'
def sha(p):
    h=hashlib.sha256()
    with Path(p).open('rb') as f:
        for part in iter(lambda:f.read(1024**2),b''):h.update(part)
    return h.hexdigest()
def read(p):return json.loads(Path(p).read_text(encoding='utf-8-sig'))
def main():
    assert not any((ROOT/n).exists() for n in ('SEALED-CONTRACT.json','HOST-STATUS.json','LAUNCH-RECEIPT.json','candidate.tar.xz'))
    old=read(BASE/'SEALED-CONTRACT.json');accepted=read(BASE/'ACCEPTANCE.json')
    assert accepted['measurement_complete'] and accepted['summary']['completed']==100 and accepted['copy_stopped']
    assert read(BASE/'FINAL-SAFETY-CHECK.json')['passed'] and read(ROOT/'PRECHECK.json')['passed']
    pure=COMPACT/'package/candidate';code=ROOT/'candidate-copy/code'
    buffer_lines="        from udp_receive_buffer import configure_udp_receive\n        self.udp_receive_buffer = configure_udp_receive(self.sock, os.environ.get('OVERLAY_RCVBUF_RECEIPT'))\n"
    deployed=(code/'node_daemon.py').read_text(encoding='utf-8-sig')
    assert deployed.count(buffer_lines)==1
    assert deployed.replace(buffer_lines,'')==(pure/'node_daemon.py').read_text(encoding='utf-8-sig')
    assert sha(code/'link_transport.py')==sha(pure/'link_transport.py')
    files={p.relative_to(code).as_posix():sha(p) for p in code.rglob('*') if p.is_file() and '__pycache__' not in p.parts}
    assert set(files)==set(old['candidate_files'])
    assert {n for n,h in old['candidate_files'].items() if files[n]!=h}=={'node_daemon.py','link_transport.py'}
    assert sha(code/'udp_receive_buffer.py')==old['candidate_files']['udp_receive_buffer.py']
    assert sha(ROOT/'EXPECTED-QUEUES.json')==old['expected_queues_sha256']
    helpers=list(old['helpers']);hosts=list(old['host_and_report_hashes'])
    for p in [*ROOT.glob('*.py'),*code.rglob('*.py')]:ast.parse(p.read_text(encoding='utf-8-sig'),filename=str(p))
    ids=['ike_privacy_20261015_'+str(i) for i in range(5800,5820)]
    for p in ROOT.parent.glob('*/SEALED-CONTRACT.json'):
        assert set(ids).isdisjoint(read(p).get('execute_ids',[])),('Prior job ID collision',p)
    attempts=[{**a,'id':ids[i],'baseline_id':a['id'],'phase':'compact_wire_series20'} for i,a in enumerate(old['attempts'][:20])]
    assert len({(a['initiator'],a['receiver']) for a in attempts})==20 and {a['batch'] for a in attempts}=={1}
    with tarfile.open(ROOT/'candidate.tar.xz','w:xz') as tf:
        for name in sorted(files):tf.add(code/name,arcname='code/'+name,recursive=False)
    preserved=dict(old['old_artifact_hashes'])
    for directory in (BASE,COMPACT):
        for p in directory.rglob('*'):
            if p.is_file() and '__pycache__' not in p.parts:preserved[str(p)]=sha(p)
    assert all(sha(p)==h for p,h in preserved.items())
    plan={**old,'attempts':attempts,'execute_ids':ids,'candidate_files':files,
      'helpers':{n:sha(ROOT/n) for n in helpers},'host_and_report_hashes':{n:sha(ROOT/n) for n in hosts},
      'archive_sha256':sha(ROOT/'candidate.tar.xz'),'old_artifact_hashes':preserved,
      'baseline_acceptance_sha256':sha(BASE/'ACCEPTANCE.json'),
      'only_functional_change':'Neighbor ciphertext explicit authenticated lv2/base64; fragment714, UDPcap1060. Original buffer shim preserved verbatim.',
      'compact_candidate_authorized':True,'compact_wire_version':2,'cover_scheduler_enabled':False,
      'compact_local_acceptance_sha256':sha(COMPACT/'FINAL-CHECK.json'),
      'max_wall_s':5400,'max_failures':3,'max_consecutive_failures':2,
      'comparability_limits':'20 pairs once, same adaptive1s profile/fanout/seed and first-block order as old100; separate boot/test keys and changed wire encoding. Historical comparison, not randomized paired A/B. No cover scheduling or privacy claim.',
      'preservation':'No original stand, old package/results, documents, queues, buffers, OS/EVE/strongSwan or external infrastructure changed.',
      'decision':'Reuse existing hidden finite clone executor;20 new unique IDs; no retries of started jobs; check all5 compact transports before IKE.',
      'initial_state':'Sealed offline, pending local harness/core tests and fresh live launch gates'}
    with (ROOT/'SEALED-CONTRACT.json').open('x',encoding='utf-8') as f:json.dump(plan,f,ensure_ascii=False,indent=2)
    print(json.dumps({'sealed':True,'connections':20,'pairs':20,'old_hashes':len(preserved),'buffer_unchanged':True,'queue_unchanged':True,'vm_started':False}))
if __name__=='__main__':main()
