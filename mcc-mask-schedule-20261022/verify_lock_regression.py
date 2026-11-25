"""Deterministic before/after reproduction, no sockets/VM/connection."""
import ast,hashlib,json,sys,threading,types
from pathlib import Path
R=Path(__file__).resolve().parent;sys.path.insert(0,str(R))
import test_mask_integration as tests
old=R.parent/'mcc_mask_schedule_20261019/candidate-copy/code/mask_node.py'
tree=ast.parse(old.read_text());method=next(n for n in ast.walk(tree) if isinstance(n,ast.FunctionDef) and n.name=='mask_encode')
module=ast.Module(body=[method],type_ignores=[]);namespace={};exec(compile(module,str(old),'exec'),namespace)
case=tests.Integration();case.setUp()
try:
    node=case.node('User9');node.mask_pair('User6');node.lock=threading.Lock()
    current=node.mask_encode;legacy=types.MethodType(namespace['mask_encode'],node)
    observations={}
    for label,fn,seq in [('old',legacy,0),('fixed',current,1)]:
        done=threading.Event();errors=[]
        def send():
            try:fn('User6',seq,b'local-regression')
            except Exception as exc:errors.append(type(exc).__name__)
            finally:done.set()
        with node.lock:
            thread=threading.Thread(target=send);thread.start()
            blocked=not done.wait(.05)
        thread.join(timeout=1)
        assert done.is_set() and not errors
        observations[label]={'blocked_by_native_handler_lock':blocked}
    assert observations['old']['blocked_by_native_handler_lock'] and not observations['fixed']['blocked_by_native_handler_lock']
    output={'passed':True,'observations':observations,'held_native_lock_s':.05,'slot_interval_s':.002,
            'maximum_slot_lateness_s':.02,'window_s':2.,'guard_s':.1,'network_used':False,
            'original_User9_exact_exception_recovered':False,
            'scope':'Proves scheduler/native-lock coupling defect; live diagnostic is required to attribute original failure.',
            'old_source_sha256':hashlib.sha256(old.read_bytes()).hexdigest()}
    with (R/'LOCK-REGRESSION.json').open('x') as stream:json.dump(output,stream,indent=2)
    print(json.dumps(output))
finally:case.doCleanups()
