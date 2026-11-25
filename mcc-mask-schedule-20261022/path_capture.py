"""Passive clone-host capture, exact runtime tap mapping and read-only host counters."""
import hashlib,json,os,re,signal,subprocess,time,xml.etree.ElementTree as ET
from pathlib import Path
import router_probe
ROOT=Path(__file__).resolve().parent
def atom(p,v):
    t=p.with_suffix('.tmp'); t.write_text(json.dumps(v,indent=2)); t.replace(p)
def fields(value): return dict(x.split('=',1) for x in value.split(',')[1:] if '=' in x)

def process_inventory():
    out={}
    for proc in Path('/proc').iterdir():
        if not proc.name.isdigit(): continue
        try:
            argv=[v.decode(errors='replace') for v in (proc/'cmdline').read_bytes().split(b'\0') if v]
            exe=os.readlink(proc/'exe'); cwd=os.readlink(proc/'cwd'); root=os.readlink(proc/'root')
            parent=int(re.search(r'(?m)^PPid:\s*(\d+)',(proc/'status').read_text())[1])
            out[int(proc.name)]={'argv':argv,'exe':exe,'cwd':cwd,'root':root,'parent':parent}
        except (FileNotFoundError,ProcessLookupError,PermissionError): pass
    return out

def owned_process(p,node_root):
    return p['cwd'].rstrip('/')==str(node_root) or p['root'].rstrip('/')==str(node_root) or any(str(node_root)+'/' in arg for arg in p['argv'])

def listener_ports(pid):
    inodes=set()
    for fd in (Path('/proc')/str(pid)/'fd').iterdir():
        try:
            m=re.fullmatch(r'socket:\[(\d+)\]',os.readlink(fd))
            if m: inodes.add(m[1])
        except (FileNotFoundError,PermissionError): pass
    ports=[]
    for table in ('tcp','tcp6'):
        for line in (Path('/proc/net')/table).read_text().splitlines()[1:]:
            f=line.split()
            if f[3]=='0A' and f[9] in inodes:
                address,port=f[1].split(':')
                if address in ('00000000','0100007F','00000000000000000000000000000000','00000000000000000000000001000000'): ports.append(int(port,16))
    return sorted(set(ports))
def discover(lab_path,node_ids):
    lab=ET.parse(lab_path).getroot(); nodes={int(n.get('id')):n for n in lab.findall('.//nodes/node')}; runtime=Path('/opt/unetlab/tmp/0')/lab.get('id')
    taps=[]; routers=[]; inventory=process_inventory(); disconnected=[]
    for node_id in node_ids:
        node=nodes[node_id]; expected={int(i.get('id')):int(i.get('network_id')) for i in node.findall('interface')}
        procs=[]
        for pid,p in inventory.items():
            if Path(p['exe']).name.startswith('qemu-system-') and owned_process(p,runtime/str(node_id)):
                procs.append((pid,p['argv']))
        assert len(procs)==1,f'Owned QEMU mapping unavailable for node {node_id}'
        pid,argv=procs[0]; netdevs={}; macs={}; serial=[]
        for k,arg in enumerate(argv[:-1]):
            if arg=='-netdev':
                f=fields(argv[k+1]);
                if f.get('ifname'): netdevs[f.get('id')]=f['ifname']
            elif arg=='-device':
                f=fields(argv[k+1]);
                if f.get('netdev') and f.get('mac'): macs[f['netdev']]=f['mac'].lower()
            elif arg=='-serial': serial.append(argv[k+1])
        matched=set()
        for netdev,name in netdevs.items():
            m=re.fullmatch(r'vunl0_(\d+)_(\d+)',name); assert m and int(m[1])==node_id
            iface=int(m[2]); base=Path('/sys/class/net')/name; assert base.exists()
            if iface not in expected:
                assert not (base/'master').exists(),'Unexpected connected interface outside XML topology'
                disconnected.append({'node_id':node_id,'tap':name,'qemu_pid':pid}); continue
            master=(base/'master').resolve().name; expected_master='pnet0' if expected[iface]==1 else 'vnet0_'+str(expected[iface])
            assert master==expected_master,(node_id,iface,master,expected_master)
            taps.append({'node_id':node_id,'node_name':node.get('name'),'interface_id':iface,'xml_name':next(i.get('name') for i in node.findall('interface') if int(i.get('id'))==iface),
              'tap':name,'ifindex':int((base/'ifindex').read_text()),'bridge':master,'network_id':expected[iface],'qemu_pid':pid,'guest_mac':macs.get(netdev)})
            matched.add(iface)
        assert matched==set(expected),f'Not every interface was mapped for owned node {node_id}'
        if 'MikroTik' in node.get('name','') or node.get('name','').startswith('ISP'):
            candidates=[]
            for s in serial:
                m=re.fullmatch(r'telnet:(?:0\.0\.0\.0|127\.0\.0\.1|localhost):(\d+),.*',s)
                if m: candidates.append(int(m[1]))
            proof={'method':'qemu_serial_argv','qemu_pid':pid}
            if not candidates:
                wrappers=[(wid,wp) for wid,wp in inventory.items() if Path(wp['exe']).name=='qemu_wrapper' and owned_process(wp,runtime/str(node_id))]
                if wrappers:
                    candidates=sorted({port for wid,wp in wrappers for port in listener_ports(wid)})
                    proof={'method':'owned_node_qemu_wrapper_listener_inode','qemu_pid':pid,'wrapper_pids':[wid for wid,wp in wrappers]}
            routers.append({'node_id':node_id,'name':node.get('name'),'host':'127.0.0.1',
                'console_port':candidates[0] if len(candidates)==1 else None,
                'console_verified_from_owned_qemu':len(candidates)==1,'console_proof':proof})
    links={}
    for p in Path('/sys/class/net').iterdir():
        if p.name.startswith(('vnet0_','vunl0_')) or p.name=='pnet0': links[p.name]=int((p/'ifindex').read_text())
    return {'taps':taps,'routers':routers,'ifindices':links,'disconnected_taps':disconnected,'sll2_packet_direction':'On a TAP, PACKET_OUTGOING (4) is host→QEMU, router ingress. Other packet types are QEMU→host, router egress. Validate using endpoints, bridges and hop TTL.', 'configuration_changed':False}
def host_counters(mapping):
    names=set(mapping['ifindices']); paths={}
    for name in names:
        p=Path('/sys/class/net')/name/'statistics'
        paths[name]={k:int((p/k).read_text()) for k in ('rx_packets','tx_packets','rx_dropped','tx_dropped','rx_errors','tx_errors')}
    result={'epoch':time.time(),'interfaces':paths,'softnet_stat':Path('/proc/net/softnet_stat').read_text()}
    for key,args in [('qdisc',['tc','-s','-d','-j','qdisc','show']),('links',['ip','-s','-j','link','show'])]:
        try:
            p=subprocess.run(args,capture_output=True,text=True,timeout=15); result[key]=json.loads(p.stdout) if p.returncode==0 else {'available':False,'exit_code':p.returncode}
        except (OSError,ValueError,subprocess.TimeoutExpired) as e: result[key]={'available':False,'error_type':type(e).__name__}
    return result
def routers_snapshot(mapping,static=False): return {str(r['node_id']):router_probe.snapshot(r,static) for r in mapping['routers']}
def start(work):
    mapping=json.loads((ROOT/'PATH-MAPPING.json').read_text()); processes=[]; manifest=[]
    try:
        for tap in mapping['taps']:
            assert tap['guest_mac'] and (Path('/sys/class/net')/tap['tap']).exists()
            pcap=work/(tap['tap']+'.pcap'); log=(work/(tap['tap']+'.log')).open('x')
            p=subprocess.Popen(['tcpdump','-i',tap['tap'],'-nn','-s','0','-B','1024','-U','-w',str(pcap),'ip and (udp or esp or icmp)'],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=log)
            processes.append((p,log)); manifest.append({'pcap':pcap.name,**tap,'pid':p.pid})
        time.sleep(.5); assert all(p.poll() is None for p,log in processes),'Per-TAP passive capture failed'
        atom(work/'path-capture.json',{'format':'per_tap_ethernet','captures':manifest})
        return processes,None
    except Exception:
        for p,log in processes:
            if p.poll() is None: p.send_signal(signal.SIGINT); p.wait(timeout=8)
            log.close()
        raise
def stop(processes,unused,work):
    for p,log in processes:
        if p.poll() is None: p.send_signal(signal.SIGINT)
    for p,log in processes: p.wait(timeout=8); log.close()
    manifest=work/'path-capture.json'; metadata=json.loads(manifest.read_text()); checks=[]
    for cap in metadata['captures']:
        p=work/cap['pcap']; assert p.stat().st_size<=8*1024**2
        m=re.search(r'(\d+) packets dropped by kernel',p.with_suffix('.log').read_text())
        checks.append({'pcap':p.name,'bytes':p.stat().st_size,'sha256':hashlib.sha256(p.read_bytes()).hexdigest(),'kernel_drops':int(m[1]) if m else None})
    assert sum(c['bytes'] for c in checks)<=64*1024**2,'Total passive capture cap exceeded'
    atom(work/'PATH-CAPTURE-CHECK.json',{'stopped':True,'capture_kernel_dropped':sum(c['kernel_drops'] for c in checks) if all(c['kernel_drops'] is not None for c in checks) else None,'sha256':hashlib.sha256(manifest.read_bytes()).hexdigest(),'captures':checks})
