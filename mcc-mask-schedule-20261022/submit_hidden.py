"""Single guarded submission through the existing no-console finite launcher."""
import ctypes, json, os, subprocess, sys
from pathlib import Path
ROOT=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT))
import host_live as h
import memory_policy
def main():
    assert not (ROOT/'HOST-STATUS.json').exists() and not (ROOT/'LAUNCH-RECEIPT.json').exists(), 'Existing or uncertain submission; never repeat'
    plan=json.loads((ROOT/'SEALED-CONTRACT.json').read_text())
    tests=json.loads((ROOT/'LOCAL-TESTS.json').read_text());assert tests['passed'] and tests['contract_sha256']==h.sha(ROOT/'SEALED-CONTRACT.json')
    assert tests['gil_regression_sha256']==h.sha(ROOT/'GIL-REGRESSION.json')
    regression=json.loads((ROOT/'GIL-REGRESSION.json').read_text());assert regression['owned_child_exited'] and regression['isolated_packets_received']>=5 and regression['old_thread_error']=='slot_lateness_exceeded'
    import readiness
    readiness.validate(json.loads((ROOT.parent/'chr7245_unlimited_migration_20261016/NETWORK-SPEED-ACCEPTANCE.json').read_text()))
    assert all(h.sha(ROOT/n)==v for n,v in {**plan['helpers'],**plan['host_and_report_hashes']}.items())
    assert all(h.sha(Path(n))==v for n,v in plan['old_artifact_hashes'].items())
    assert 'Total running VMs: 0' in h.b.vmrun(['list'])
    isolation=h.b.c.vmx_contract();memory=memory_policy.admit()
    assert isolation['ram_gib']==32 and isolation['vcpus']==4
    k=ctypes.WinDLL('kernel32',use_last_error=True)
    k.CreateMutexW.argtypes=[ctypes.c_void_p,ctypes.c_bool,ctypes.c_wchar_p];k.CreateMutexW.restype=ctypes.c_void_p
    k.CloseHandle.argtypes=[ctypes.c_void_p]
    handle=k.CreateMutexW(None,True,'Local\\CandidateIkeABPilot20261014')
    assert handle and ctypes.get_last_error()!=183, 'Existing clone owner; no parallel launch'
    k.CloseHandle(handle)
    pythonw=Path(r'C:\Codex\System\runtimes\toolhub-python-3.14.7\pythonw.exe')
    runner=Path(r'C:\Codex\System\Scripts\hidden_process_runner.py')
    runtime=ROOT.parent/'mcc_runtime_3148_5002_20261015/windows/python/python.exe'
    assert all(p.is_file() for p in (pythonw,runner,runtime))
    receipt={'stage':'submission_started','at_utc':h.b.c.now(),'contract_sha256':h.sha(ROOT/'SEALED-CONTRACT.json'),
             'hidden_runner_sha256':h.sha(runner),'isolation':isolation,'memory':memory,'prelaunch_vms_stopped':True}
    with (ROOT/'LAUNCH-RECEIPT.json').open('x') as f:json.dump(receipt,f,indent=2)
    child=subprocess.Popen([str(pythonw),str(runner),str(runtime),'-I','-B','-X','utf8',str(ROOT/'host_live.py')],cwd=ROOT,
                           stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,
                           shell=False,creationflags=subprocess.CREATE_NO_WINDOW)
    receipt.update(stage='submitted_to_existing_hidden_runner',runner_pid=child.pid)
    h.atom(ROOT/'LAUNCH-RECEIPT.json',receipt)
    print(json.dumps({'submitted':True,'runner_pid':child.pid,'planned_connections':len(plan['attempts']),'actual_connections_started':False}))
if __name__=='__main__':main()
