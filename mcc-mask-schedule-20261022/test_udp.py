import ast,copy,hashlib,importlib.util,json,socket,sys,unittest
from pathlib import Path
from unittest.mock import Mock,patch
ROOT=Path(__file__).resolve().parent;sys.path.insert(0,str(ROOT))
spec=importlib.util.spec_from_file_location('buffer_policy',ROOT/'candidate-copy/code/udp_receive_buffer.py')
policy=importlib.util.module_from_spec(spec);spec.loader.exec_module(policy)
import report_udp as report
import router_read as rr
from analyse_series import udp_delta
from series_common import describe
class Tests(unittest.TestCase):
    def fake(self,values):
        sock=Mock();sock.getsockopt.side_effect=values;return sock
    def test_normal_buffer(self):
        sock=self.fake([212992,8388608,8388608])
        with patch.object(policy.sys,'platform','linux'):r=policy.configure_udp_receive(sock)
        self.assertEqual(r['method'],'SO_RCVBUF');self.assertEqual(sock.setsockopt.call_count,1)
        self.assertEqual(r['effective_bytes'],8388608);self.assertFalse(r['global_settings_changed'])
    def test_clamped_force_only_this_socket(self):
        sock=self.fake([212992,425984,8388608])
        with patch.object(policy.sys,'platform','linux'):r=policy.configure_udp_receive(sock)
        self.assertEqual(r['method'],'SO_RCVBUFFORCE');self.assertEqual(sock.setsockopt.call_count,2)
        self.assertEqual(sock.setsockopt.call_args.args,(socket.SOL_SOCKET,getattr(socket,'SO_RCVBUFFORCE',33),4194304))
    def test_force_denied_no_silent_fallback(self):
        sock=self.fake([212992,425984]);sock.setsockopt.side_effect=[None,PermissionError('fixture')]
        with patch.object(policy.sys,'platform','linux'),self.assertRaises(PermissionError):policy.configure_udp_receive(sock)
    def test_readback_too_small_blocks(self):
        sock=self.fake([212992,425984,425984])
        with patch.object(policy.sys,'platform','linux'),self.assertRaises(RuntimeError):policy.configure_udp_receive(sock)
    def test_not_increased_blocks(self):
        sock=self.fake([8388608,8388608,8388608])
        with patch.object(policy.sys,'platform','linux'),self.assertRaises(RuntimeError):policy.configure_udp_receive(sock)
    def test_linux_only(self):
        sock=self.fake([])
        with patch.object(policy.sys,'platform','win32'),self.assertRaises(RuntimeError):policy.configure_udp_receive(sock)
        sock.setsockopt.assert_not_called()
    def fixtures(self):
        r={'attempt':{'id':'ike_privacy_20261015_3000'},'actors':{}};end={}
        for user in ('6','7','8','9','10'):
            r['actors'][user]={'pid':123,'udp_receive_buffer':{'pid':123,'effective_bytes':8388608,'before_bytes':212992,'global_settings_changed':False,'method':'SO_RCVBUF'}}
            end[user]={'socket_owner_verified':True,'actor_job':r['attempt']['id'],'active_final_counters':{'overlay_sockets':[{'drops':0,'inode':'12345'}]}}
        return r,end
    def test_zero_socket_drops(self):
        r,end=self.fixtures();self.assertTrue(report.socket_check(r,end)['passed'])
    def test_one_drop_fails(self):
        r,end=self.fixtures();end['10']['active_final_counters']['overlay_sockets'][0]['drops']=1
        self.assertFalse(report.socket_check(r,end)['passed'])
    def test_missing_socket_unknown(self):
        r,end=self.fixtures();end['10']['active_final_counters']['overlay_sockets']=[]
        with self.assertRaises(AssertionError):report.socket_check(r,end)
    def test_wrong_owner_blocks(self):
        r,end=self.fixtures();end['10']['socket_owner_verified']=False
        with self.assertRaises(AssertionError):report.socket_check(r,end)
    def test_wrong_job_blocks(self):
        r,end=self.fixtures();end['10']['actor_job']='other'
        with self.assertRaises(AssertionError):report.socket_check(r,end)
    def test_global_setting_claim_blocks(self):
        r,end=self.fixtures();r['actors']['10']['udp_receive_buffer']['global_settings_changed']=True
        with self.assertRaises(AssertionError):report.socket_check(r,end)
    def test_udp_delta_counts_one_event(self):
        b={'10':{'udp':dict(InErrors=0,RcvbufErrors=0,SndbufErrors=0,InCsumErrors=0)}};a=copy.deepcopy(b)
        a['10']['udp'].update(InErrors=1,RcvbufErrors=1)
        d=udp_delta(b,a);self.assertFalse(d['passed']);self.assertEqual(d['nodes']['10']['RcvbufErrors'],1)
    def test_counter_reset_unknown(self):
        b={'10':{'udp':dict(InErrors=1,RcvbufErrors=1,SndbufErrors=0,InCsumErrors=0)}};a=copy.deepcopy(b);a['10']['udp']['InErrors']=0
        with self.assertRaises(AssertionError):udp_delta(b,a)
    def test_schedule_and_hashes(self):
        p=json.loads((ROOT/'SEALED-CONTRACT.json').read_text());old=json.loads((ROOT.parent/'mcc_chr7245_series100_20261016/SEALED-CONTRACT.json').read_text())
        self.assertEqual(p['execute_ids'],['ike_privacy_20261015_'+str(i) for i in range(6600,6619)])
        for a,b in zip(p['attempts'],old['attempts'][1:20]):
            for k in ('initiator','receiver','mode'):self.assertEqual(a[k],b[k])
        self.assertTrue(set(p['execute_ids']).isdisjoint(x['id'] for x in old['attempts']))
        for n,h in {**p['helpers'],**p['host_and_report_hashes']}.items():self.assertEqual(hashlib.sha256((ROOT/n).read_bytes()).hexdigest(),h)
        self.assertFalse(p['queue_changes_authorized'])
    def test_only_socket_change(self):
        p=json.loads((ROOT/'SEALED-CONTRACT.json').read_text());self.assertEqual(set(p['candidate_files'])-set(p['source_candidate_files']),{'udp_receive_buffer.py','mask_transport.py','mask_node.py','mask_gate.py','mask_sender.py'})
        self.assertEqual({n for n,h in p['source_candidate_files'].items() if p['candidate_files'][n]!=h},{'node_daemon.py','link_transport.py'})
    def test_profile_preserved(self):
        def profile(path):return next(ast.literal_eval(n.value) for n in ast.parse(path.read_text()).body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='PROFILE' for t in n.targets))
        old=profile(ROOT.parent/'mcc_chr7245_series100_20261016/node_pilot_control.py')
        expected={**old,'IKE_MCC_ROUTE_TIMEOUT_S':'1','IKE_MCC_ACCEPT_MODE':'adaptive','IKE_MCC_ACCEPT_MIN_COPIES':'3','IKE_MCC_ACCEPT_QUIET_S':'0.150'}
        self.assertEqual(profile(ROOT/'node_pilot_control.py'),expected)
    def test_no_extra_pre_up_round_trip(self):
        text=(ROOT/'guest_live.py').read_text();start=text.index("actors={str(u)");end=text.index("start=time.monotonic();up=")
        segment=text[start:end];self.assertEqual(segment.count('v.node('),1);self.assertIn('time.sleep(3)',segment)
        self.assertIn("ready[a]['native_sids'][p]==ready[p]['native_sids'].get(a)",segment)
        self.assertIn("attempt['id'] not in state['started_ids']",text)
    def test_stale_prompt_rejected(self):
        self.assertFalse(rr.current_prompt(b'[admin@MikroTik] > old\nPassword: '));self.assertTrue(rr.current_prompt(b'new\n[admin@MikroTik] > '))
    def test_marker_entropy_preserved(self):
        self.assertIn('token_hex(12)',(ROOT/'router_read.py').read_text())
    def test_all_syntax(self):
        for p in [*ROOT.glob('*.py'),*(ROOT/'candidate-copy/code').glob('*.py')]:ast.parse(p.read_text(),filename=str(p))
    def test_p95(self):self.assertAlmostEqual(describe(list(range(1,101)))['p95_s'],95.05)
    def test_compare(self):
        b={'summary':{'native_successful':{'median_s':2,'p95_s':4},'ssh_successful':{'median_s':3,'p95_s':5}}}
        s={'native_successful':{'median_s':1,'p95_s':3},'ssh_successful':{'median_s':2,'p95_s':4}}
        self.assertEqual(report.comparison(b,s)['native_successful']['median_s']['delta_percent'],-50)
if __name__=='__main__':unittest.main(verbosity=2)
