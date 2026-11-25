import copy,json,tempfile,unittest
from pathlib import Path
import memory_policy as m
R=Path(__file__).resolve().parent
def row(physical=50,commit=45,process=45):
    return dict(available_physical=int(physical*m.GIB),system_available_commit=int(commit*m.GIB),process_available_commit=int(process*m.GIB))
class MemoryTests(unittest.TestCase):
    def test_staged_start_accepts_36_commit(self):self.assertTrue(m.evaluate(row(commit=36,process=36),48,36))
    def test_physical48_preserved(self):self.assertFalse(m.evaluate(row(47.99),48,36))
    def test_commit36_strict(self):self.assertFalse(m.evaluate(row(commit=35.99),48,36))
    def test_process_limit_still_blocks(self):self.assertFalse(m.evaluate(row(commit=50,process=35.99),48,36))
    def test_both_exact_limits(self):self.assertTrue(m.evaluate(row(48,36,36),48,36))
    def test_authorized_start_constants(self):
        self.assertEqual((m.START_PHYSICAL_GIB,m.START_COMMIT_GIB,m.RUNTIME_GIB),(48,36,16))
    def test_admit_uses_new_limits(self):
        from unittest.mock import patch
        with patch.object(m,'snapshot',return_value=row(48,36,36)):
            proof=m.admit();self.assertTrue(proof['passed']);self.assertEqual(proof['commit_floor_gib'],36)
        with patch.object(m,'snapshot',return_value=row(48,35.99,36)),self.assertRaises(AssertionError):m.admit()
    def test_grant_still_requires_30_seconds(self):self.assertEqual(m.STABLE_SECONDS,30)
    def test_runtime16_unchanged(self):
        self.assertEqual(m.RUNTIME_GIB,16);self.assertFalse(m.evaluate(row(15.99,50,50),16,16))
        self.assertFalse(m.evaluate(row(50,15.99,50),16,16))
    def test_unknowns_never_zero(self):
        for value in (None,True,-1,float('nan'),'48'):
            value_row=row();value_row['available_physical']=value
            with self.assertRaises(AssertionError):m.evaluate(value_row,48,36)
    def monitor(self,reader=lambda:row()):
        self.clock=0
        return m.Monitor(R,reader=reader,clock=lambda:self.clock)
    def test_never_grants_without_samples(self):
        monitor=self.monitor();self.clock=40;self.assertIsNone(monitor.stable(0))
    def test_29_seconds_not_enough(self):
        monitor=self.monitor()
        for i in range(30):self.clock=i;monitor.sample()
        self.assertIsNone(monitor.stable(0))
    def test_stable_full_load_grant(self):
        monitor=self.monitor()
        for i in range(31):self.clock=i;monitor.sample()
        proof=monitor.stable(0);self.assertTrue(proof['passed']);self.assertEqual(proof['samples'],31)
    def test_stale_samples_not_granted(self):
        monitor=self.monitor()
        for i in range(31):self.clock=i;monitor.sample()
        self.clock=34
        with self.assertRaises(AssertionError):monitor.stable(0)
    def test_single_dip_latches_stop(self):
        monitor=self.monitor(lambda:row(commit=15));monitor.sample();monitor.reader=lambda:row();monitor.sample()
        with self.assertRaises(AssertionError):monitor.check()
    def test_failed_metric_stops(self):
        def unavailable():raise OSError('fixture')
        monitor=self.monitor(unavailable);monitor.sample()
        with self.assertRaises(AssertionError):monitor.check()
    def test_bounded_telemetry(self):
        monitor=self.monitor();monitor.rows=[row()]*6000;monitor.sample()
        with self.assertRaises(AssertionError):monitor.check()
    def test_full_node_cap_exact(self):self.assertIn("assert ram==20736",(R/'guest_setup.py').read_text())
    def test_no_IKE_before_memory_grant(self):
        text=(R/'guest_live.py').read_text()
        self.assertLess(text.index('awaiting_full_load_memory_admission'),text.index('for batch_no in range'))
        self.assertIn("grant['runtime_floor_gib']==16",text)
    def test_original_runtime_guard_retained(self):
        text=(R/'host_live.py').read_text();self.assertEqual(text.count('b.memory_gate(16)'),2)
        self.assertIn('monitor.check()',text);self.assertIn('monitor.stable(memory_wait)',text)
    def test_configured_policy(self):
        plan=json.loads((R/'SEALED-CONTRACT.json').read_text());p=plan['memory_admission']
        self.assertEqual((p['startup_physical_gib'],p['startup_commit_gib'],p['runtime_physical_and_commit_gib']),(48,36,16))
    def test_whole_candidate_package_unchanged(self):
        import hashlib
        plan=json.loads((R/'SEALED-CONTRACT.json').read_text());old=json.loads((R.parent/'mcc_mask_schedule_20261022_r6/SEALED-CONTRACT.json').read_text())
        self.assertEqual(plan['candidate_files'],old['candidate_files'])
        for name,digest in plan['candidate_files'].items():self.assertEqual(hashlib.sha256((R/'candidate-copy/code'/name).read_bytes()).hexdigest(),digest)
if __name__=='__main__':unittest.main()
