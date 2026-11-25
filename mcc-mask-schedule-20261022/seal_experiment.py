"""Bounded reuse of accepted clone runners; no new runtime or protected-code edits."""
import ast,hashlib,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parent
BASE=ROOT.parent/'mcc_chr7245_series100_20261016'
ADAPTIVE=ROOT.parent/'mcc_adaptive_wait_20261017'
def sha(path):
    h=hashlib.sha256()
    with path.open('rb') as f:
        for block in iter(lambda:f.read(1024**2),b''):h.update(block)
    return h.hexdigest()
def read(p):return json.loads(p.read_text(encoding='utf-8'))
def main():
    assert not (ROOT/'SEALED-CONTRACT.json').exists() and not (ROOT/'HOST-STATUS.json').exists(),'Existing or uncertain series; no overwrite/replay'
    old=read(BASE/'SEALED-CONTRACT.json');prior=read(ADAPTIVE/'SEALED-CONTRACT.json')
    baseline=read(BASE/'ACCEPTANCE.json');assert baseline['measurement_complete'] and baseline['summary']['completed']==100 and baseline['copy_stopped']
    accepted=read(ADAPTIVE/'ACCEPTANCE.json');assert accepted['passed'] and accepted['results']==12
    assert read(ADAPTIVE/'HOST-STATUS.json')['stage']=='completed'
    for directory in (BASE,ADAPTIVE):
        safety=read(directory/'FINAL-SAFETY-CHECK.json');assert safety['passed'] and safety['copy_stopped'] and safety['source_not_started']
    assert sha(ROOT/'candidate.tar.xz')==old['archive_sha256']==prior['archive_sha256']
    assert sha(ROOT/'EXPECTED-QUEUES.json')==old['expected_queues_sha256']==prior['expected_queues_sha256']
    source=ROOT.parents[1]/'Development-WireGuard/mcc-e2e-20261015/candidate'
    assert all(sha(source/n)==v for n,v in prior['source_candidate_files'].items()),'Protected source drift'
    code=ROOT/'candidate-copy/code'
    assert {str(p.relative_to(code)).replace('\\','/'):sha(p) for p in code.rglob('*') if p.is_file()}==old['candidate_files']
    helpers=[*old['helpers'],'router_lifecycle.py','selection_policy.py']
    for name in [*helpers,*old['host_and_report_hashes'],'submit_hidden.py','seal_experiment.py','run_tests.py','test_selection_policy.py','test_udp.py','test_readiness.py','test_router_lifecycle.py']:
        ast.parse((ROOT/name).read_text(encoding='utf-8-sig'),filename=name)
    preserved=dict(prior['old_artifact_hashes'])
    for directory in (BASE,ADAPTIVE):
        for p in directory.rglob('*'):
            if p.is_file():
                h=sha(p);assert str(p) not in preserved or preserved[str(p)]==h,'Old evidence drift'
                preserved[str(p)]=h
    assert all(sha(Path(p))==v for p,v in preserved.items()),'Previously sealed result changed'
    attempts=[{**a,'id':'ike_privacy_20261015_'+str(5000+i),'baseline_id':a['id'],
               'phase':'adaptive1s_series100','selection_mode':'adaptive','deadline_s':1} for i,a in enumerate(old['attempts'])]
    assert len(attempts)==100 and len({a['id'] for a in attempts})==100
    plan={**old,'attempts':attempts,'execute_ids':[a['id'] for a in attempts],
          'helpers':{n:sha(ROOT/n) for n in helpers},
          'host_and_report_hashes':{n:sha(ROOT/n) for n in (*old['host_and_report_hashes'],'selection_policy.py')},
          'old_artifact_hashes':preserved,'baseline_acceptance_sha256':sha(BASE/'ACCEPTANCE.json'),
          'adaptive_security_acceptance_sha256':sha(ADAPTIVE/'ACCEPTANCE.json'),
          'only_functional_change':'selection profile: adaptive, route-timeout 1s, min_copies 3, quiet 150ms; protocol archive unchanged',
          'unchanged_settings':['application archive','fanout 2x2x2','five active users','seed 0','pairs and order','SO_RCVBUF 4MiB','PFIFO512','max-limit 0','strongSwan/IPsec proposal','CHR 7.24.5'],
          'selection_policy':{'mode':'adaptive','window_ms':0,'deadline_ms':1000,'min_copies':3,'quiet_ms':150},
          'initial_state':'offline prepared; local tests and fresh isolation/readiness gates required before launch',
          'decision':'reuse previous 100-job finite harness and latest clone lifecycle; passive startup-only policy receipt',
          'max_wall_s':14400,'max_failures':5,'max_consecutive_failures':3,
          'comparability_limits':'Same CHR/pairs/order, separate boots and test keys. Historical previous series used first-valid mode, not adaptive10s. No attack or recipient-hiding claim from this 100-job series.',
          'deadline_coupling':'Existing ROUTE_TIMEOUT_S also forms outer expires_at; whole-setting test, not isolated timer patch.',
          'test_traffic_only':True,'router_config_commands_authorized':False,'license_commands_authorized':False,
          'packages_installed':False,'graceful_router_shutdown_required':True,
          'no_completed_or_started_job_retries':True,'p95_method':'statistics.quantiles(n=100, method=inclusive), index94; success-only and all-attempt durations reported separately',
          'all_original_tz_requirements_closed':False}
    with (ROOT/'SEALED-CONTRACT.json').open('x',encoding='utf-8') as f:json.dump(plan,f,ensure_ascii=False,indent=2)
    print(json.dumps({'sealed':True,'planned':100,'pairs':20,'per_pair':5,'archive_unchanged':True,'old_files_hash_bound':len(preserved),'vm_started':False}))
if __name__=='__main__':main()
