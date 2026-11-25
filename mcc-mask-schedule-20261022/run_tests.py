import hashlib,json,sys,unittest
from pathlib import Path
if __name__=='__mp_main__' and sys.platform=='win32':
    import os
    sys.stderr=(Path(__file__).resolve().parent/('spawn-bootstrap-'+str(os.getpid())+'.log')).open('x',encoding='utf-8')
R=Path(__file__).resolve().parent;sys.path.insert(0,str(R));sys.dont_write_bytecode=True
import test_udp,test_readiness,test_router_lifecycle,test_selection_policy,test_mask,test_mask_integration,test_capacity,test_sender,test_memory
def main():
    core=json.loads((R/'CORE-LOCAL-TESTS.json').read_text())
    plan=json.loads((R/'SEALED-CONTRACT.json').read_text())
    assert core['passed'] and core['tests_run']==88 and core['skipped']==1
    assert core['node_daemon_sha256']==plan['candidate_files']['node_daemon.py']
    suite=unittest.TestSuite([unittest.defaultTestLoader.loadTestsFromModule(m) for m in (test_udp,test_readiness,test_router_lifecycle,test_selection_policy,test_mask,test_mask_integration,test_capacity,test_sender,test_memory)])
    result=unittest.TextTestRunner(verbosity=1).run(suite)
    with (R/'LOCAL-TESTS.json').open('x',encoding='utf-8') as stream:
        json.dump({'passed':result.wasSuccessful(),'tests_run':result.testsRun,'core_tests_passed':True,'core_tests_run':88,'core_tests_skipped':1,'gil_regression_sha256':hashlib.sha256((R/'GIL-REGRESSION.json').read_bytes()).hexdigest() if (R/'GIL-REGRESSION.json').exists() else None,'contract_sha256':hashlib.sha256((R/'SEALED-CONTRACT.json').read_bytes()).hexdigest(),'scope':'offline only; actual policy, isolation, queues, IKE/ESP and captures require live run'},stream,indent=2)
    raise SystemExit(not result.wasSuccessful())
if __name__=='__main__':main()
