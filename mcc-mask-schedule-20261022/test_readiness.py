import copy,hashlib,json,sys,unittest
from pathlib import Path
R=Path(__file__).resolve().parent;sys.path.insert(0,str(R))
import readiness
class Tests(unittest.TestCase):
 def fixture(self):return {'passed':True,'queue_configuration_preserved':True,'external_nics_absent':True,'candidate_code_archive_sha256':readiness.ARCHIVE,'routers':{str(i):{'reported_license_level':'p-unlimited','version':'7.24.5 (stable)','measured_tx_bps':5_000_000,'measurement_duration_s':6,'egress_interface_verified':True,'measured_egress_byte_delta':3_750_000} for i in readiness.IDS}}
 def test_all_fourteen_gate(self):self.assertEqual(readiness.validate(self.fixture())['routers'],14)
 def test_free_rate_does_not_pass(self):
  v=self.fixture();v['routers']['1']['measured_tx_bps']=1_000_000
  with self.assertRaises(AssertionError):readiness.validate(v)
 def test_missing_router_does_not_pass(self):
  v=self.fixture();del v['routers']['1']
  with self.assertRaises(AssertionError):readiness.validate(v)
 def test_license_text_without_speed_insufficient(self):
  v=self.fixture();v['routers']['1']['measured_tx_bps']=0
  with self.assertRaises(AssertionError):readiness.validate(v)
 def test_archive_identical_to_previous(self):
  base=R.parent/'mcc_udp4m_series100_20261016'
  p=json.loads((R/'SEALED-CONTRACT.json').read_text())
  self.assertEqual(hashlib.sha256((R/'candidate.tar.xz').read_bytes()).hexdigest(),p['archive_sha256'])
  self.assertEqual(hashlib.sha256((base/'candidate.tar.xz').read_bytes()).hexdigest(),readiness.ARCHIVE)
  self.assertTrue(p['compact_candidate_authorized']);self.assertEqual(p['compact_wire_version'],2)
 def test_both_entrypoints_block_before_launch(self):
  for name in ('submit_hidden.py','host_live.py'):
   text=(R/name).read_text(encoding='utf-8');self.assertIn('readiness.validate',text)
 def test_gate_unknown_is_not_pass(self):
  with self.assertRaises((AssertionError,KeyError)):readiness.validate({})
if __name__=='__main__':unittest.main()
