"""One bounded read-only check of owned controller, visibility and isolated VM."""
import ctypes,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT.parent/'ike_real_ab_pilot_20261014'))
import boot_stage as b
def main():
    h=json.loads((ROOT/'HOST-STATUS.json').read_text());r=json.loads((ROOT/'LAUNCH-RECEIPT.json').read_text())
    guest=h.get('guest') or {}
    kernel=ctypes.WinDLL('kernel32',use_last_error=True)
    kernel.OpenProcess.argtypes=[ctypes.c_uint,ctypes.c_bool,ctypes.c_uint];kernel.OpenProcess.restype=ctypes.c_void_p
    kernel.GetExitCodeProcess.argtypes=[ctypes.c_void_p,ctypes.POINTER(ctypes.c_uint)]
    kernel.CloseHandle.argtypes=[ctypes.c_void_p]
    actors={}
    for label,pid in (('runner',r['runner_pid']),('controller',h['controller_pid'])):
        handle=kernel.OpenProcess(0x1000,False,pid);assert handle,'Cannot verify owned process'
        code=ctypes.c_uint();assert kernel.GetExitCodeProcess(handle,ctypes.byref(code));kernel.CloseHandle(handle)
        actors[label]={'pid':pid,'running':code.value==259,'exit_code':None if code.value==259 else code.value}
    user=ctypes.WinDLL('user32',use_last_error=True);owned={p['pid'] for p in actors.values()};visible=[]
    callback=ctypes.WINFUNCTYPE(ctypes.c_bool,ctypes.c_void_p,ctypes.c_void_p)
    user.GetWindowThreadProcessId.argtypes=[ctypes.c_void_p,ctypes.POINTER(ctypes.c_uint)]
    user.IsWindowVisible.argtypes=[ctypes.c_void_p]
    def visit(hwnd,unused):
        pid=ctypes.c_uint();user.GetWindowThreadProcessId(hwnd,ctypes.byref(pid))
        if pid.value in owned and user.IsWindowVisible(hwnd):visible.append(pid.value)
        return True
    assert user.EnumWindows(callback(visit),None)
    running=b.vmrun(['list']);assert str(b.c.SOURCE_VMX) not in running
    assert 'Total running VMs: 1' in running and str(b.c.VMX) in running
    isolation=b.c.vmx_contract();memory=b.memory_gate(16)
    assert all(p['running'] for p in actors.values()) and not visible
    assert h['stage'] not in ('blocked','completed')
    output={'passed':True,'controller_stage':h['stage'],'guest_stage':guest.get('stage'),
      'started_connections':len(guest.get('started_ids',[])),'completed_connections':len(guest.get('completed_ids',[])),
      'started_nodes':len(guest.get('started_node_ids',[])),'owned_processes':actors,
      'visible_owned_windows':len(visible),'only_authorized_clone_running':True,'source_not_started':True,
      'isolation':isolation,'memory':memory,'new_launches_by_this_check':0}
    with (ROOT/'LAUNCH-VERIFICATION.json').open('x') as f:json.dump(output,f,indent=2)
    print(json.dumps(output))
if __name__=='__main__':main()
