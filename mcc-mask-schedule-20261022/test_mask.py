import hashlib
import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('mask_transport', ROOT/'candidate-copy/code/mask_transport.py')
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)


class CodecTests(unittest.TestCase):
    def codec(self, **kw):
        return m.Codec(**(dict(key=bytes(32), sid='sid', source='User6', destination='User7', token=bytes(16)) | kw))

    def test_same_size_dummy_and_full(self):
        for payload in (b'', b'x', bytes(1060)):
            with self.subTest(n=len(payload)):
                wire = self.codec().encode(0, payload)
                self.assertEqual(len(wire), 1124)
                self.assertEqual(self.codec().decode(wire), (0, payload))

    def test_no_plain_type_or_length(self):
        wire = self.codec().encode(0, b'{"t":"LINK_FRAG"}')
        self.assertNotIn(b'LINK_FRAG', wire)
        self.assertNotIn(b'{"t"', wire)

    def test_key_separation(self):
        wire = self.codec().encode(0, b'x')
        for change in ({'sid':'new'}, {'source':'User8'}, {'destination':'User9'}, {'token':bytes([1])*16}, {'key':bytes([1])*32}):
            with self.subTest(change=list(change)), self.assertRaises(Exception):
                self.codec(**change).decode(wire)

    def test_bad_tag_does_not_consume_sequence(self):
        wire = self.codec().encode(5, b'x'); decoder = self.codec()
        damaged = bytearray(wire); damaged[-1] ^= 1
        with self.assertRaises(Exception): decoder.decode(bytes(damaged))
        self.assertEqual(decoder.decode(wire), (5, b'x'))

    def test_replay_rejected(self):
        wire = self.codec().encode(5, b'x'); decoder = self.codec(); decoder.decode(wire)
        with self.assertRaises(ValueError): decoder.decode(wire)

    def test_reordering_allowed(self):
        tx = self.codec(); rx = self.codec()
        self.assertEqual([rx.decode(tx.encode(n, b'x'))[0] for n in (3, 0, 2, 1)], [3, 0, 2, 1])

    def test_boundaries(self):
        for seq, data in ((-1,b''),(1000,b''),(True,b''),(0,bytes(1061))):
            with self.subTest(seq=seq,n=len(data)), self.assertRaises(ValueError): self.codec().encode(seq,data)

    def test_size_rejected(self):
        wire = self.codec().encode(0,b'x')
        for data in (wire[:-1], wire+b'x', b''):
            with self.assertRaises(ValueError): self.codec().decode(data)

    def test_header_authenticated(self):
        wire = bytearray(self.codec().encode(0,b'x')); wire[m.HEADER.size-1] ^= 1
        with self.assertRaises(Exception): self.codec().decode(bytes(wire))


class ScheduleTests(unittest.TestCase):
    def schedule(self, peers=('User7',)):
        self.now=10.; self.sent=[]; self.finished=[]
        s=m.Schedule(peers,lambda p,n,b:(n,b),lambda p,b:self.sent.append((p,b)),lambda:self.finished.append(True),clock=lambda:self.now)
        s.anchor=10.
        return s

    def test_public_quota(self):
        plan=m.slots(('User10','User8','User7','User9'))
        self.assertEqual(len(plan),4000)
        for peer in ('User7','User8','User9','User10'):
            self.assertEqual([n for _,p,n in plan if p==peer],list(range(1000)))
        self.assertLess(plan[-1][0],2.)

    def test_group_input_order_irrelevant(self):
        self.assertEqual(m.slots(['User7','User10']),m.slots(['User10','User7']))

    def test_dummy_uses_same_slot(self):
        s=self.schedule(); s.step(.001,'User7',0); s.enqueue('User7',b'x'); s.step(.003,'User7',1)
        self.assertEqual(self.sent,[('User7',(0,b'')),('User7',(1,b'x'))])
        self.assertEqual(s.tx['User7'][1][1],hashlib.sha256(b'x').hexdigest())

    def test_overflow_has_no_fallback(self):
        s=self.schedule()
        for _ in range(m.MAX_QUEUE):s.enqueue('User7',b'x')
        with self.assertRaises(m.MaskError):s.enqueue('User7',b'y')
        self.assertEqual(self.sent,[])

    def test_late_slot_fails_closed(self):
        s=self.schedule(); self.now=10.1
        with self.assertRaises(m.MaskError):s.step(.001,'User7',0)
        self.assertFalse(self.sent)

    def test_after_window_no_plain_fallback(self):
        s=self.schedule(); s.done=True
        with self.assertRaises(m.MaskError):s.enqueue('User7',b'x')
        self.assertFalse(self.sent)

    def test_unknown_peer_rejected(self):
        s=self.schedule()
        with self.assertRaises(m.MaskError):s.enqueue('User8',b'x')

    def test_adaptive_timer_not_changed(self):
        import ast
        tree=ast.parse((ROOT/'node_pilot_control.py').read_text())
        profile=next(ast.literal_eval(n.value) for n in tree.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='PROFILE' for t in n.targets))
        self.assertEqual(profile['IKE_MCC_ROUTE_TIMEOUT_S'],'1')
        self.assertEqual(profile['IKE_MCC_ACCEPT_MIN_COPIES'],'3')
        self.assertEqual(profile['IKE_MCC_ACCEPT_QUIET_S'],'0.150')


if __name__=='__main__':unittest.main(verbosity=2)
