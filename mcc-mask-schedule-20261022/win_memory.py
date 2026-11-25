"""Read-only Win32 metric-scope audit. No VM/process/config changes."""
import ctypes,datetime,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT.parent/'ike_real_ab_pilot_20261014'))
import boot_stage as b

class Performance(ctypes.Structure):
    _fields_=[('cb',ctypes.c_ulong)]+[(name,ctypes.c_size_t) for name in
        ('CommitTotal','CommitLimit','CommitPeak','PhysicalTotal','PhysicalAvailable','SystemCache',
         'KernelTotal','KernelPaged','KernelNonpaged','PageSize')]+[(name,ctypes.c_ulong) for name in ('HandleCount','ProcessCount','ThreadCount')]
class BasicLimit(ctypes.Structure):
    _fields_=[('PerProcessUserTimeLimit',ctypes.c_longlong),('PerJobUserTimeLimit',ctypes.c_longlong),
        ('LimitFlags',ctypes.c_ulong),('MinimumWorkingSetSize',ctypes.c_size_t),('MaximumWorkingSetSize',ctypes.c_size_t),
        ('ActiveProcessLimit',ctypes.c_ulong),('Affinity',ctypes.c_size_t),('PriorityClass',ctypes.c_ulong),('SchedulingClass',ctypes.c_ulong)]
class IO(ctypes.Structure):
    _fields_=[(n,ctypes.c_ulonglong) for n in ('ReadOperationCount','WriteOperationCount','OtherOperationCount','ReadTransferCount','WriteTransferCount','OtherTransferCount')]
class ExtendedLimit(ctypes.Structure):
    _fields_=[('BasicLimitInformation',BasicLimit),('IoInfo',IO)]+[(n,ctypes.c_size_t) for n in
        ('ProcessMemoryLimit','JobMemoryLimit','PeakProcessMemoryUsed','PeakJobMemoryUsed')]

def snapshot():
    k=ctypes.WinDLL('kernel32',use_last_error=True);ps=ctypes.WinDLL('psapi',use_last_error=True)
    m=b.MemoryStatus();m.length=ctypes.sizeof(m);assert k.GlobalMemoryStatusEx(ctypes.byref(m))
    p=Performance();p.cb=ctypes.sizeof(p)
    ps.GetPerformanceInfo.argtypes=[ctypes.POINTER(Performance),ctypes.c_ulong];ps.GetPerformanceInfo.restype=ctypes.c_bool
    assert ps.GetPerformanceInfo(ctypes.byref(p),ctypes.sizeof(p))
    assert p.PageSize in (4096,65536) and p.CommitLimit>=p.CommitTotal and p.PhysicalTotal>0
    k.GetCurrentProcess.restype=ctypes.c_void_p;k.IsProcessInJob.argtypes=[ctypes.c_void_p,ctypes.c_void_p,ctypes.POINTER(ctypes.c_int)]
    inside=ctypes.c_int();assert k.IsProcessInJob(k.GetCurrentProcess(),None,ctypes.byref(inside))
    job={'inside_job':bool(inside.value)}
    if inside.value:
        limits=ExtendedLimit();k.QueryInformationJobObject.argtypes=[ctypes.c_void_p,ctypes.c_int,ctypes.c_void_p,ctypes.c_ulong,ctypes.c_void_p]
        assert k.QueryInformationJobObject(None,9,ctypes.byref(limits),ctypes.sizeof(limits),None)
        flags=limits.BasicLimitInformation.LimitFlags
        job.update(limit_flags=flags,process_memory_limited=bool(flags&0x100),job_memory_limited=bool(flags&0x200),
                   process_memory_limit=limits.ProcessMemoryLimit,job_memory_limit=limits.JobMemoryLimit,
                   peak_job_memory_used=limits.PeakJobMemoryUsed)
    return {'at_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'available_physical':m.available_physical,'process_available_commit':m.available_page,
        'system_available_commit':(p.CommitLimit-p.CommitTotal)*p.PageSize,
        'system_commit_total':p.CommitTotal*p.PageSize,'system_commit_limit':p.CommitLimit*p.PageSize,
        'system_commit_peak':p.CommitPeak*p.PageSize,'system_physical_total':p.PhysicalTotal*p.PageSize,
        'performance_physical_available':p.PhysicalAvailable*p.PageSize,'job':job,
        'new_VM_launches':0,'new_connections':0}
if __name__=='__main__':print(json.dumps(snapshot()))
