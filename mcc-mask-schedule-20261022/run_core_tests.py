"""Exercise the88-test suite against the actual buffer-preserving live package."""
import hashlib,json,os,sys,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parent
TESTS=ROOT.parent/'mcc_compact_wire_candidate_20261019/package/tests'
scratch=ROOT/'local/core';scratch.mkdir(parents=True,exist_ok=False)
os.environ.update(MCC_TEST_TMP_DIR=str(scratch),TEMP=str(scratch),TMP=str(scratch))
sys.path.insert(0,str(TESTS))
import harness_mcc_auth as h
h.SOURCE=ROOT/'candidate-copy/code'
h.M,h.AUTH,h.CORE,h.TRUST,h.ADAPTER=h.load_code()
assert 'from udp_receive_buffer import configure_udp_receive' in (h.SOURCE/'node_daemon.py').read_text()
suite=unittest.defaultTestLoader.discover(str(TESTS),'test_*.py')
result=unittest.TextTestRunner(verbosity=1).run(suite)
output={'passed':result.wasSuccessful(),'tests_run':result.testsRun,'skipped':len(result.skipped),
        'source':str(h.SOURCE),'node_daemon_sha256':hashlib.sha256((h.SOURCE/'node_daemon.py').read_bytes()).hexdigest(),
        'network_used':False,'live_ike_esp_verified':False}
with (ROOT/'CORE-LOCAL-TESTS.json').open('x',encoding='utf-8') as f:json.dump(output,f,indent=2)
print(json.dumps(output))
raise SystemExit(not result.wasSuccessful())
