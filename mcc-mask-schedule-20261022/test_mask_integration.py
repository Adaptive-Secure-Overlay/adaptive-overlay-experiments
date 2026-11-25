import copy,importlib.util,json,os,sys,tempfile,threading,unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock,patch
ROOT=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT))
sys.path.insert(0,str(ROOT/'candidate-copy/code'))
import mask_transport as m
import mask_node
import mask_gate
from mask_audit import ledger_check,is_mask_udp


class FakeBase:
    def __init__(self,name):
        self.name=name;self.lock=threading.RLock();self.sessions={p:SimpleNamespace(key=bytes(32),sid='pair') for p in ('User6','User7','User8','User9','User10') if p!=name}
        self.sent=[];self.incoming=None
    def send_peer(self,peer,payload):self._send_peer_raw(peer,payload)
    def _send_peer_raw(self,peer,payload):self.sent.append((peer,payload))
    def recv_one(self):return self.incoming
    def peer_from_src(self,src):return src[0]
    def stop(self):pass
    def serve_forever(self):raise LookupError('synthetic_packet_failure')


class Integration(unittest.TestCase):
    def setUp(self):
        (ROOT/'local').mkdir(exist_ok=True)
        self.tmp=tempfile.TemporaryDirectory(dir=ROOT/'local');self.addCleanup(self.tmp.cleanup)
        self.env=patch.dict(os.environ,MASK_ROOT=self.tmp.name,MASK_JOB='job',MASK_SOURCE='User6',MASK_TOKEN='00'*16);self.env.start();self.addCleanup(self.env.stop)
    def node(self,name):
        with patch.object(mask_node.signal,'signal'),patch.object(mask_node.threading.Thread,'start'):
            return mask_node.wrap(FakeBase)(name)
    def test_preparation_not_masked(self):
        n=self.node('User6');n.send_peer('User7',b'{"t":"MGMT_INIT"}')
        self.assertFalse(n.mask.started);self.assertEqual(n.sent,[('User7',b'{"t":"MGMT_INIT"}')])
    def test_first_mcc_activates_all_four(self):
        n=self.node('User6')
        with patch.object(n.mask,'start',side_effect=lambda:setattr(n.mask,'started',True)),patch.object(n.mask,'enqueue') as enqueue:
            n.send_peer('User7',b'{"t":"MCC_START"}')
            enqueue.assert_called_once_with('User7',b'{"t":"MCC_START"}')
        self.assertEqual(set(n.mask_peers),{'User7','User8','User9','User10'})
        self.assertFalse(n.sent)
    def test_non_A_pair_unmodified(self):
        n=self.node('User7');n.mask.started=True;n.send_peer('User8',b'x')
        self.assertEqual(n.sent,[('User8',b'x')])
    def test_unwrapped_A_star_dropped(self):
        n=self.node('User7');n.mask.started=True;n.incoming=(b'{"t":"MCC_START"}',('User6',9000))
        self.assertIsNone(n.recv_one());self.assertEqual(n.mask_plain_after_activation,1)
    def test_cover_recovers_native_datagram_before_dispatch(self):
        n=self.node('User7');tx=m.Codec(bytes(32),'pair','User6','User7',bytes(16))
        n.incoming=(tx.encode(0,b'{"t":"LINK_FRAG"}'),('User6',9000))
        with patch.object(n.mask,'start',side_effect=lambda *_:setattr(n.mask,'started',True)):
            self.assertEqual(n.recv_one(),(b'{"t":"LINK_FRAG"}',('User6',9000)))
    def test_dummy_not_dispatched(self):
        n=self.node('User7');n.mask.started=True;tx=m.Codec(bytes(32),'pair','User6','User7',bytes(16));n.incoming=(tx.encode(0),('User6',9000))
        self.assertIsNone(n.recv_one());self.assertEqual(n.mask_rx['User6'],[[0,None]])
    def test_session_rotation_fail_closed(self):
        n=self.node('User7');n.mask_pair('User6');n.sessions['User6'].sid='rotated'
        with self.assertRaises(m.MaskError):n.mask_pair('User6')
    def test_nonce_reuse_rejected(self):
        c=m.Codec(bytes(32),'pair','User6','User7',bytes(16));c.encode(0)
        with self.assertRaises(ValueError):c.encode(0,b'x')
    def test_gate_nonzero_invalidates(self):
        n=self.node('User7')
        with patch.object(mask_gate,'release',return_value={'released':True,'packets':1}),self.assertRaises(m.MaskError):n.mask_finish()
    def test_gate_existing_table_rejected(self):
        with patch.object(mask_gate,'run',return_value=SimpleNamespace(returncode=0)) as run,self.assertRaises(AssertionError):mask_gate.install(Path(self.tmp.name),'job')
        self.assertEqual(run.call_count,1)
    def test_gate_unknown_counter_not_deleted(self):
        p=Path(self.tmp.name);(p/'MASK-GATE-OWNER.json').write_text(json.dumps({'job':'job','owned_table':mask_gate.TABLE}))
        with patch.object(mask_gate,'run',return_value=SimpleNamespace(stdout='{"nftables":[]}')) as run,self.assertRaises(AssertionError):mask_gate.release(p,'job')
        self.assertEqual(run.call_count,1)
    def test_native_failure_never_uses_plain_fallback(self):
        n=self.node('User6');n.mask.started=True;n.mask.error='late'
        with self.assertRaises(m.MaskError):n._send_peer_raw('User7',b'x')
        self.assertFalse(n.sent)
    def test_controller_requires_canary_and_admission(self):
        text=(ROOT/'guest_live.py').read_text()
        self.assertIn("assert mask_check['passed'] and success",text)
        self.assertIn("'Native A-star channels not matched; no IKE start'",text)
        self.assertIn('range(1,6)',text)
    def test_no_buffer_or_security_core_changes(self):
        import hashlib
        base=ROOT.parent/'mcc_compact_series20_20261019/candidate-copy/code'
        for p in base.rglob('*'):
            if p.is_file() and '__pycache__' not in p.parts:
                self.assertEqual(hashlib.sha256(p.read_bytes()).digest(),hashlib.sha256((ROOT/'candidate-copy/code'/p.relative_to(base)).read_bytes()).digest(),str(p))
    def test_fatal_handler_keeps_sanitized_diagnostics(self):
        n=self.node('User9')
        with patch.object(n.mask,'close'),patch.object(n.mask_monitor,'join'),self.assertRaises(LookupError):n.serve_forever()
        proof=json.loads((Path(self.tmp.name)/'job-MASK-FINAL.json').read_text())
        self.assertEqual(proof['fatal']['type'],'LookupError')
        self.assertNotIn('synthetic_packet_failure',json.dumps(proof))
    def test_security_window_not_extended(self):
        self.assertEqual((m.RECORDS,m.INTERVAL,m.WINDOW,m.GUARD),(1000,.002,2.,.1))
    def test_timed_sender_does_not_acquire_protocol_lock(self):
        n=self.node('User9');n.mask_pair('User6')
        # Reproduce native handler owning its NON-reentrant lock. With the old
        # mask_encode this sender is blocked; it cannot make its2ms slots.
        n.lock=threading.Lock();completed=threading.Event();errors=[]
        def send():
            try:n.mask_encode('User6',0,b'x')
            except Exception as exc:errors.append(type(exc).__name__)
            finally:completed.set()
        with n.lock:
            thread=threading.Thread(target=send);thread.start();unblocked=completed.wait(.05)
        thread.join(timeout=1)
        self.assertTrue(unblocked,'Timed sender waited for native handler lock')
        self.assertFalse(errors)
    def test_missing_cached_key_never_builds_it_on_timed_path(self):
        n=self.node('User9')
        with patch.object(n,'mask_pair') as prepare,self.assertRaises(m.MaskError):n.mask_encode('User6',0,b'x')
        prepare.assert_not_called()
    def test_ICMP_quotation_never_counts_as_mask_datagram(self):
        p={'proto':'17','sport':9000,'dport':9000,'payload':b'MSK1'+bytes(1120)}
        self.assertTrue(is_mask_udp(p))
        self.assertFalse(is_mask_udp({**p,'proto':'1','payload':b'MSK1'+bytes(544)}))
        self.assertFalse(is_mask_udp({**p,'dport':53,'sport':53}))
    def test_scheduler_failure_not_overwritten_by_late_retransmission(self):
        n=self.node('User9');n.mask.error='slot_lateness_exceeded'
        with self.assertRaises(m.MaskError):n.mask.enqueue('User6',b'x')
        self.assertEqual(n.mask.error,'slot_lateness_exceeded')
    def test_UDP4500_IKE_allowed_but_ESP_blocked(self):
        # Captured IKE_AUTH is276bytes; the old broad rule dropped304IPbytes.
        self.assertFalse(mask_gate.udp_is_esp(bytes(4)+bytes([1])*272))
        self.assertFalse(mask_gate.udp_is_esp(b'\xff'))
        self.assertTrue(mask_gate.udp_is_esp(bytes.fromhex('11223344')+bytes(4)))
        self.assertIn('udp length >= 16 @th,64,32 != 0',mask_gate.rules_script())
        self.assertNotIn('udp dport 4500 counter drop',mask_gate.rules_script())

if __name__=='__main__':unittest.main(verbosity=2)
