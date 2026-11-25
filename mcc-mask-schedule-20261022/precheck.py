"""Read-only clone/mutex/memory/code precheck; never boots or sends traffic."""
import ctypes,datetime,hashlib,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT.parent/'ike_real_ab_pilot_20261014'))
import boot_stage as b
sys.path.insert(0,str(ROOT))
import memory_policy
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def main():
    assert not (ROOT/'PRECHECK.json').exists(),'Do not overwrite an earlier precheck'
    candidate=ROOT.parent/'mcc_compact_wire_candidate_20261019'
    accepted=json.loads((candidate/'FINAL-CHECK.json').read_text(encoding='utf-8'))
    assert accepted['candidate_local_tests']=={'run':88,'passed':87,'skipped':1,'reason':'Linux ownership/modes unavailable on Windows'}
    tested=json.loads((candidate/'validation-candidate/RESULT.json').read_text(encoding='utf-8'))
    assert all(sha(candidate/'package'/name)==h for name,h in tested['candidate_hashes'].items())
    kernels=ctypes.WinDLL('kernel32',use_last_error=True)
    kernels.OpenMutexW.argtypes=[ctypes.c_uint,ctypes.c_bool,ctypes.c_wchar_p];kernels.OpenMutexW.restype=ctypes.c_void_p
    kernels.CloseHandle.argtypes=[ctypes.c_void_p]
    owner=kernels.OpenMutexW(0x00100000,False,'Local\\CandidateIkeABPilot20261014')
    err=ctypes.get_last_error()
    if owner:kernels.CloseHandle(owner)
    assert not owner and err==2,'Shared clone owner exists or cannot be verified; no parallel launch'
    running=b.vmrun(['list']);assert 'Total running VMs: 0' in running
    isolation=b.c.vmx_contract();memory=memory_policy.admit()
    assert isolation['ram_gib']==32 and isolation['vcpus']==4
    state={'at_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'passed':True,
      'all_vms_stopped':True,'mutex_absent_verified':True,'isolation':isolation,'memory':memory,
      'clone':str(b.c.VMX),'source_not_started':str(b.c.SOURCE_VMX) not in running,
      'candidate_tested_hashes_match':True,'vm_started':False,'new_connections':0}
    with (ROOT/'PRECHECK.json').open('x',encoding='utf-8') as f:json.dump(state,f,indent=2)
    print(json.dumps(state))
if __name__=='__main__':main()
