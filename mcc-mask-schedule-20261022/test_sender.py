"""Local loopback-only ownership, GIL isolation, bounds and unchanged deadlines."""
import ctypes,hashlib,importlib.util,json,os,socket,sys,threading,time,unittest
from pathlib import Path
if __name__=='__mp_main__' and sys.platform=='win32':
    sys.stderr=(Path(__file__).resolve().parent/('spawn-bootstrap-'+str(os.getpid())+'.log')).open('x',encoding='utf-8')
from unittest.mock import Mock
R=Path(__file__).resolve().parent
sys.path.insert(0,str(R/'candidate-copy/code'))
from mask_sender import IsolatedSchedule
import mask_sender as sender
from mask_transport import Codec,Schedule,MaskError,MAX_LATENESS,MAX_QUEUE,WINDOW,GUARD

def busy(seconds):
    until=time.monotonic()+seconds
    while time.monotonic()<until:pass

class SenderTests(unittest.TestCase):
    def facade(self):
        s=IsolatedSchedule(['User7'],lambda:None);s.ready={'pid':123};s.started=True;s.anchor=time.monotonic()
        s.capacity=[threading.BoundedSemaphore(MAX_QUEUE)];s.submitted=[0];s.sent_real=[0];s.inbox=Mock()
        return s
    def test_bounded_same_peer_budget(self):
        s=self.facade()
        for _ in range(MAX_QUEUE):s.enqueue('User7',b'x')
        with self.assertRaises(MaskError):s.enqueue('User7',b'x')
        self.assertEqual(s.error,'queue_overflow');self.assertEqual(s.inbox.put_nowait.call_count,MAX_QUEUE)
    def test_no_send_after_window_even_during_guard(self):
        s=self.facade();s.anchor=time.monotonic()-WINDOW-.01
        with self.assertRaises(MaskError):s.enqueue('User7',b'x')
        s.inbox.put_nowait.assert_not_called()
    def test_no_fallback_after_worker_error(self):
        s=self.facade();s.error='emit_deadline_exceeded'
        with self.assertRaises(MaskError):s.enqueue('User7',b'x')
        s.inbox.put_nowait.assert_not_called()
    def test_IPC_full_fails_without_expanding_budget(self):
        s=self.facade();s.inbox.put_nowait.side_effect=RuntimeError('fixture')
        with self.assertRaises(MaskError):s.enqueue('User7',b'x')
        self.assertEqual(s.error,'sender_IPC_full');self.assertEqual(s.submitted,[0])
        self.assertTrue(s.capacity[0].acquire(False))
    def test_start_requires_prepared_sender(self):
        s=IsolatedSchedule(['User7'],lambda:None)
        with self.assertRaises(MaskError):s.start()
    def test_invalid_payload_or_peer(self):
        for peer,payload in [('User8',b'x'),('User7',b''),('User7',bytes(1061)),('User7','x')]:
            with self.assertRaises(MaskError):self.facade().enqueue(peer,payload)
    def test_constants_and_post_emit_deadline(self):
        self.assertEqual((WINDOW,GUARD,MAX_LATENESS,MAX_QUEUE),(2.,.1,.02,1000))
        text=(R/'candidate-copy/code/mask_sender.py').read_text()
        self.assertIn("record['emitted_lateness_s']>MAX_LATENESS",text)
        self.assertIn("get_context('spawn')",text)
        self.assertNotIn('setsockopt',text)
        self.assertNotIn('sched_setscheduler',text)
    def test_only_nineteen_remaining_directions(self):
        p=json.loads((R/'SEALED-CONTRACT.json').read_text())
        self.assertEqual(len(p['attempts']),19)
        self.assertNotIn(('User6','User9'),[(a['initiator'],a['receiver']) for a in p['attempts']])
        self.assertEqual([a['continuation_of_id'] for a in p['attempts']],['ike_privacy_20261015_'+str(i) for i in range(6201,6220)])
    def test_real_sender_independent_of_parent_GIL_and_lock(self):
        hashes={name:hashlib.sha256((R/'candidate-copy/code'/name).read_bytes()).hexdigest() for name in ('mask_sender.py','mask_transport.py')}
        proof_path=R/'GIL-REGRESSION.json'
        if proof_path.exists():
            verified=json.loads(proof_path.read_text())
            self.assertEqual(verified['tested_source_hashes'],hashes)
            self.assertTrue(verified['owned_child_exited']);self.assertEqual(verified['visible_owned_windows'],0)
            self.assertEqual(verified['old_thread_error'],'slot_lateness_exceeded');self.assertGreaterEqual(verified['isolated_packets_received'],5)
            return
        s=IsolatedSchedule(['User7'],lambda:None)
        tx=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);tx.bind(('127.0.0.1',0))
        rx=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);rx.bind(('127.0.0.1',0));rx.settimeout(.05)
        before=(tx.getsockopt(socket.SOL_SOCKET,socket.SO_RCVBUF),tx.getsockopt(socket.SOL_SOCKET,socket.SO_SNDBUF))
        context=dict(key=bytes(32),sid='local-test',source='User6',destination='User7',token=bytes(16))
        old_sent=[];old=Schedule(['User7'],lambda p,n,b:b'',lambda p,b:old_sent.append(True),lambda:None)
        old_switch=sys.getswitchinterval();received=[];native_lock=threading.Lock()
        try:
            s.prepare(tx,{'User7':context},{'User7':rx.getsockname()})
            self.assertNotEqual(s.ready['pid'],os.getpid());self.assertEqual(tuple(s.ready['buffer_values']),before)
            visible=[]
            if sys.platform=='win32':
                user=ctypes.WinDLL('user32');callback=ctypes.WINFUNCTYPE(ctypes.c_bool,ctypes.c_void_p,ctypes.c_void_p)
                user.GetWindowThreadProcessId.argtypes=[ctypes.c_void_p,ctypes.POINTER(ctypes.c_uint)];user.IsWindowVisible.argtypes=[ctypes.c_void_p]
                def visit(hwnd,unused):
                    pid=ctypes.c_uint();user.GetWindowThreadProcessId(hwnd,ctypes.byref(pid))
                    if pid.value==s.ready['pid'] and user.IsWindowVisible(hwnd):visible.append(pid.value)
                    return True
                self.assertTrue(user.EnumWindows(callback(visit),None));self.assertFalse(visible)
            # Both start20ms in the future; hold the parent's GIL/native lock80ms.
            # No deadline/buffer is changed in either implementation.
            anchor=time.monotonic()+.02;old.start(anchor);s.start(anchor)
            sys.setswitchinterval(.2)
            with native_lock:busy(.08)
            sys.setswitchinterval(old_switch)
            for _ in range(100):
                try:wire,remote=rx.recvfrom(2048)
                except socket.timeout:break
                received.append(wire)
                if len(received)>=10:break
            decoder=Codec(**context)
            for wire in received:decoder.decode(wire)
            old.thread.join(timeout=.2)
            proof={'old_thread_error':old.error,'old_thread_packets':len(old_sent),
                   'tested_source_hashes':hashes,
                   'isolated_packets_received':len(received),'isolated_pid':s.ready['pid'],'parent_pid':os.getpid(),
                   'visible_owned_windows':len(visible),
                   'window_s':WINDOW,'guard_s':GUARD,'max_lateness_s':MAX_LATENESS,
                   'scope':'local controlled GIL contention; not proof of exact historical pause or live VM acceptance'}
            self.assertEqual(old.error,'slot_lateness_exceeded');self.assertFalse(old_sent)
            self.assertGreaterEqual(len(received),5)
            s.close();self.assertFalse(s.process.is_alive());proof['owned_child_exited']=True
            self.assertEqual(before,(tx.getsockopt(socket.SOL_SOCKET,socket.SO_RCVBUF),tx.getsockopt(socket.SOL_SOCKET,socket.SO_SNDBUF)))
            with (R/'GIL-REGRESSION.json').open('x',encoding='utf-8') as f:json.dump(proof,f,indent=2)
        finally:
            sys.setswitchinterval(old_switch);s.close();old.close();tx.close();rx.close()

if __name__=='__main__':unittest.main(verbosity=2)
