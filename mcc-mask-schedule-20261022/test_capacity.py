"""Deterministic offline capacity, fail-closed and preservation regression checks."""
import copy,hashlib,json,unittest
from pathlib import Path
import capacity_gate as c
import capacity_probe as p
R=Path(__file__).resolve().parent

class CapacityTests(unittest.TestCase):
    def fixture(self):
        node={'sent':5642,'received':5642,'expected_count':5642,'duplicates':0,'invalid':0,'sender_errors':[],
              'tx_ip_bps':26000000.,'rx_ip_bps':26000000.,'tx_span_s':2.,'socket_drops':0,'buffer_options_changed':False}
        return {'6':copy.deepcopy(node),'7':copy.deepcopy(node)},{n:{'ip_bps':26000000.,'span_s':2.} for n in ('ether1','ether2')}
    def test_good_duplex(self):
        n,e=self.fixture();self.assertTrue(c.check_rows(n,e)['passed'])
    def test_missing_packet_blocks(self):
        n,e=self.fixture();n['7']['received']-=1;self.assertFalse(c.check_rows(n,e)['passed'])
    def test_low_egress_classification(self):
        n,e=self.fixture()
        for row in e.values():row.update(ip_bps=1000000.,span_s=8.)
        d=c.check_rows(n,e);self.assertFalse(d['passed']);self.assertTrue(d['low_egress_pattern']);self.assertTrue(c.needs_reboot(d,'p-unlimited'))
    def test_slow_sender_no_speculative_reboot(self):
        n,e=self.fixture();n['6']['tx_ip_bps']=1000000.;d=c.check_rows(n,e)
        self.assertFalse(d['source_qualified']);self.assertFalse(c.needs_reboot(d,'free'))
    def test_socket_loss_no_speculative_reboot(self):
        n,e=self.fixture();n['7']['socket_drops']=1;d=c.check_rows(n,e)
        self.assertFalse(d['passed']);self.assertFalse(c.needs_reboot(d,'p-unlimited'))
    def test_unknown_numeric_fails_closed(self):
        for value in (None,float('nan'),float('inf'),True,'26000000'):
            n,e=self.fixture();n['6']['tx_ip_bps']=value;self.assertFalse(c.check_rows(n,e)['passed'])
            n,e=self.fixture();e['ether1']['ip_bps']=value;self.assertFalse(c.check_rows(n,e)['passed'])
    def test_both_ends_required(self):
        n,e=self.fixture();del n['7'];self.assertFalse(c.check_rows(n,e)['passed'])
    def test_both_interfaces_required(self):
        n,e=self.fixture();del e['ether2'];self.assertFalse(c.check_rows(n,e)['passed'])
    def test_full_span_not_a_burst(self):
        n,e=self.fixture();e['ether1']['span_s']=.01;self.assertFalse(c.check_rows(n,e)['passed'])
    def test_decode_ip_bytes_not_ethernet(self):
        d=c.pure_rate('100.000000 IP A.9000 > B.9000: UDP, length 1124\n102.000000 IP A.9000 > B.9000: UDP, length 1124\n')
        self.assertEqual(d['ip_bytes'],2304);self.assertEqual(d['ip_bps'],9216.)
        self.assertIsNone(c.pure_rate('truncated unknown')['ip_bps'])
    def test_uptime_strict(self):
        self.assertEqual(c.uptime_seconds('UPTIME|1d2h3m4s'),93784)
        for value in ('UPTIME|','UPTIME|unknown','UPTIME|1:03:04','UPTIME|2s\nUPTIME|3s'):
            with self.assertRaises(AssertionError):c.uptime_seconds(value)
    def test_capacity_margin_and_fixed_size(self):
        self.assertEqual((p.RATE,p.DURATION,p.PAYLOAD,p.IP_BYTES),(26000000,2.,1124,1152))
        self.assertGreater(c.MIN_BPS,18432000)
        self.assertNotIn('setsockopt',(R/'capacity_probe.py').read_text())
    def test_original_mask_and_buffers_byte_identical(self):
        old=json.loads((R.parent/'mcc_mask_schedule_20261019_r3/SEALED-CONTRACT.json').read_text())
        for name,digest in old['candidate_files'].items():
            if name=='mask_node.py':continue
            self.assertEqual(hashlib.sha256((R/'candidate-copy/code'/name).read_bytes()).hexdigest(),digest)
    def test_capacity_before_connections_no_cold_restart(self):
        source=(R/'guest_live.py').read_text()
        self.assertLess(source.index('capacity_gate.run('),source.index('for batch_no in range'))
        self.assertNotIn('recover_initial(',source)
        self.assertIn("'capacity-evidence'",source)
    def test_no_configuration_writes(self):
        text=(R/'capacity_gate.py').read_text()
        for token in ('/queue set','/queue add','/system license renew','/system license generate','-a reset'):
            self.assertNotIn(token,text)
        self.assertEqual(text.count("tn.write(b'/system reboot"),1)

if __name__=='__main__':unittest.main()
