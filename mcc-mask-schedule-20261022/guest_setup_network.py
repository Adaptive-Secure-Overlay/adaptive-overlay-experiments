"""Add clone-only management addresses, then inspect existing endpoint configuration."""
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import time
import pexpect
ROOT=Path('/root/candidate-mcc-mask-schedule-20261022-r8')
STATUS=ROOT/'NETWORK-SETUP-STATUS.json'
ENDPOINTS={6:('192.168.106.10','vnet0_13','192.168.106.254'),7:('192.168.107.10','vnet0_15','192.168.107.254'),8:('192.168.108.10','vnet0_17','192.168.108.254'),9:('192.168.109.10','vnet0_19','192.168.109.254'),10:('192.168.110.10','vnet0_21','192.168.110.254')}
def now(): return datetime.datetime.now(datetime.timezone.utc).isoformat()
def save(value):
    path=STATUS.with_suffix('.tmp'); path.write_text(json.dumps(value,indent=2)); path.replace(STATUS)
def ssh(user,command,timeout=25):
    ip=ENDPOINTS[user][0]
    args=['-F','/dev/null','-o','StrictHostKeyChecking=accept-new','-o','UserKnownHostsFile='+str(ROOT/'node-known-hosts'),
        '-o','ConnectTimeout=8','-o','ConnectionAttempts=1','-o','NumberOfPasswordPrompts=1','root@'+ip,command]
    child=pexpect.spawn('/usr/bin/ssh',args,encoding='utf-8',timeout=timeout)
    try:
        code=child.expect([r'(?i)password:',pexpect.EOF])
        if code==0:
            credential=os.environ.get('PILOT_NODE_CREDENTIAL')
            assert credential,'Existing node credential unavailable; no guessing'
            child.sendline(credential); child.expect(pexpect.EOF)
        output=child.before; child.close()
    except (pexpect.TIMEOUT,pexpect.EOF):
        child.close(force=True)
        raise RuntimeError(f'Owned User{user} SSH transport ended without command completion; raw buffers omitted') from None
    if child.exitstatus!=0:
        frames=re.findall(r'File "([^"\r\n]+)", line (\d+), in ([^\r\n]+)',output)
        marker=re.search(r'REMOTE_ERROR_JSON=(\{[^\r\n]+\})',output)
        text=output.lower()
        reasons=[('connection_refused','connection refused'),('no_route','no route to host'),('connect_timeout','connection timed out'),('auth_denied','permission denied'),('host_key_changed','remote host identification has changed'),('connection_closed','connection closed'),('connection_reset','connection reset'),('argument_too_long','argument list too long'),('kex_failed','kex_exchange_identification')]
        classes=[label for label,pattern in reasons if pattern in text]
        diagnostic={'user':user,'exit_code':child.exitstatus,'transport_failure_classes':classes or ['unclassified'],
            'frames':[{'file':Path(f).name,'line':int(n),'function':fn} for f,n,fn in frames],
            'exception_types':re.findall(r'^([A-Za-z]+Error|AssertionError|SystemExit)(?::|$)',output,re.M)}
        if marker: diagnostic['remote']=json.loads(marker.group(1))
        target=ROOT/f'SSH-ERROR-User{user}-{time.time_ns()}.json'
        target.write_text(json.dumps(diagnostic,indent=2))
        raise RuntimeError(f'Owned User{user} SSH command failed: rc={child.exitstatus}; saved {target.name}')
    return output
NODE_INSPECT=r'''/root/candidate-mcc-runtime3148-5002-restored-20261015/python/bin/python3.14 - <<'PY'
import hashlib,json,os,re,shutil,subprocess
from pathlib import Path
fields=('OVERLAY_ACTIVE_USERS','IKE_MCC_ENABLED','IKE_MCC_FANOUT','IKE_MCC_X1_FANOUT','IKE_MCC_X2_FANOUT','IKE_MCC_IKE_FANOUT','IKE_MCC_ACCEPT_MODE','IKE_MCC_ACCEPT_WINDOW_S','IKE_MCC_ACCEPT_MIN_COPIES','IKE_MCC_ACCEPT_QUIET_S','IKE_ROUTE_CACHE_TTL_S','IKE_MCC_ROUTE_TIMEOUT_S','OVERLAY_IPSEC_DATA_MARK')
agents=[]
for p in Path('/proc').iterdir():
 if not p.name.isdigit(): continue
 try:
  argv=[v.decode(errors='replace') for v in (p/'cmdline').read_bytes().split(bytes([0])) if v]
  if '/root/hybrid-overlay/node_daemon.py' not in argv: continue
  cmd=' '.join(argv)
  env=dict(v.split('=',1) for v in (p/'environ').read_bytes().decode(errors='replace').split(chr(0)) if '=' in v)
  m=re.search(r'--name[=\s]+(User\d+)',cmd)
  os.environ.update(env)
  import sys
  sys.path.insert(0,'/root/hybrid-overlay')
  import config
  effective={k:getattr(config,k,None) for k in ('ACTIVE_USERS','IKE_MCC_ENABLED','IKE_MCC_FANOUT','IKE_MCC_X1_FANOUT','IKE_MCC_X2_FANOUT','IKE_MCC_IKE_FANOUT','IKE_MCC_ACCEPT_MODE','IKE_MCC_ACCEPT_WINDOW_S','IKE_MCC_ROUTE_TIMEOUT_S','IKE_ROUTE_CACHE_TTL_S','IKE_MCC_ADAPTIVE_ACCEPT')}
  agents.append({'pid':int(p.name),'name':m.group(1) if m else None,'ike_proxy':'--ike-proxy' in cmd,'environment':{k:env[k] for k in fields if k in env},'effective_configuration':effective})
 except (FileNotFoundError,PermissionError,ProcessLookupError): pass
conf=Path('/etc/ipsec.conf'); text=conf.read_text() if conf.exists() else ''
approved=('ike','esp','keyexchange','authby','type','auto','left','right','leftsubnet','rightsubnet','mark','mark_in','mark_out','leftfirewall')
settings=[]; current=None
for line in text.splitlines():
 line=line.split('#',1)[0].strip()
 if line.startswith('conn '): current=line[5:].strip()
 if '=' in line:
  key,value=map(str.strip,line.split('=',1))
  if key in approved: settings.append({'connection':current,'key':key,'value':value})
links=subprocess.run(['ip','-j','address','show'],capture_output=True,text=True,check=True).stdout
state=subprocess.run(['ipsec','status'],capture_output=True,text=True).stdout
value={'hostname':subprocess.check_output(['hostname'],text=True).strip(),'links':json.loads(links),'agents':agents,
 'ipsec_conf_sha256':hashlib.sha256(text.encode()).hexdigest(),'ipsec_settings':settings,
 'installed_sas':state.count('INSTALLED'),'established_ike':state.count('ESTABLISHED'),
 'binaries':{k:shutil.which(k) is not None for k in ('ipsec','nft','tcpdump','/root/candidate-mcc-runtime3148-5002-restored-20261015/python/bin/python3.14')},
 'existing_overlay_files':{n:(Path('/root/hybrid-overlay')/n).exists() for n in ('node_daemon.py','scripts/ike_proxy_nft_apply.sh','scripts/ike_proxy_nft_clear.sh','scripts/xfrm_overlay_bypass.sh')},
 'node_daemon_sha256':hashlib.sha256(Path('/root/hybrid-overlay/node_daemon.py').read_bytes()).hexdigest() if Path('/root/hybrid-overlay/node_daemon.py').exists() else None}
print('PILOT_NODE_JSON='+json.dumps(value))
PY'''
def main():
    assert not STATUS.exists(),'Existing setup attempt: no replay'
    state={'stage':'precheck','at_utc':now(),'addresses_added':[],'pilot_connections_started':0}
    try:
        assert not [p for p in Path('/sys/class/net').iterdir() if (p/'device').exists()]
        start=json.loads((ROOT/'LAB-START-AUTHORIZED-RESUME.json').read_text())
        assert start['stage']=='selected_nodes_started_waiting_readiness' and len(start['started_ids'])==15
        if shutil.which('arping'): arping=['arping']
        elif shutil.which('busybox') and 'arping' in subprocess.check_output(['busybox','--list'],text=True).splitlines(): arping=['busybox','arping']
        else: raise RuntimeError('No installed ARP duplicate-address checker; no installations permitted')
        state.update(stage='adding_clone_only_internal_management'); save(state)
        for user,(ip,bridge,address) in ENDPOINTS.items():
            assert (Path('/sys/class/net')/bridge/'bridge').exists(),'Expected internal Linux bridge absent'
            r=subprocess.run([*arping,'-D','-c','2','-w','3','-I',bridge,address],capture_output=True,text=True,timeout=5)
            if r.returncode: raise RuntimeError(f'Management address conflict or DAD failure on owned bridge {bridge}')
            subprocess.run(['ip','address','add',address+'/24','dev',bridge],check=True,capture_output=True)
            state['addresses_added'].append({'bridge':bridge,'address':address}); state['at_utc']=now(); save(state)
        # Give already-started nested guests a fixed boot interval, not extra IKE connections.
        time.sleep(20)
        results={}
        for user in ENDPOINTS:
            state.update(stage='reading_existing_endpoint',current_user=user,at_utc=now()); save(state)
            output=ssh(user,NODE_INSPECT,timeout=40)
            match=re.search(r'PILOT_NODE_JSON=(\{[^\r\n]+\})',output)
            assert match,'Sanitized node evidence absent'
            results[str(user)]=json.loads(match.group(1))
            assert any(a.get('local')==ENDPOINTS[user][0] for link in results[str(user)]['links'] for a in link.get('addr_info',[]))
            assert all(results[str(user)]['binaries'].values())
        with (ROOT/'ENDPOINT-INVENTORY.json').open('x') as f: json.dump(results,f,indent=2)
        state.update(stage='clone_management_and_endpoints_verified',current_user=None,at_utc=now()); save(state)
    except Exception as error:
        state.update(stage='blocked',error_type=type(error).__name__,error=str(error)[:1000],at_utc=now()); save(state)
        raise
if __name__=='__main__': main()
