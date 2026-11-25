"""Owned tcpdump capture and sanitized counter collection on copied Linux endpoints."""
import argparse,base64,hashlib,json,os,re,signal,subprocess,tarfile,time
from pathlib import Path
ROOT=Path('/root/candidate-mcc-chr7245-series100-20261016')
def udp_counts(text):
    lines=text.splitlines()
    for i,line in enumerate(lines[:-1]):
        if line.startswith('Udp:') and lines[i+1].startswith('Udp:'):
            return dict(zip(line.split()[1:],map(int,lines[i+1].split()[1:])))
    return {}
def overlay_sockets():
    values=[]
    for row in Path('/proc/net/udp').read_text().splitlines()[1:]:
        f=row.split()
        if len(f)>=13 and int(f[1].split(':')[1],16)==9000:
            values.append({'rx_queue_bytes':int(f[4].split(':')[1],16),'drops':int(f[-1]),'inode':f[9]})
    return values
def counters():
    return {'monotonic_s':time.monotonic(),'udp':udp_counts(Path('/proc/net/snmp').read_text()),'overlay_sockets':overlay_sockets(),
        'rmem_sysctls':{k:int((Path('/proc/sys/net/core')/k).read_text()) for k in ('rmem_default','rmem_max')},
        'interface':{k:int((Path('/sys/class/net/ens3/statistics')/k).read_text()) for k in ('rx_packets','rx_dropped','rx_errors','tx_packets','tx_dropped','tx_errors')}}
def atom(p,v):
    tmp=p.with_suffix('.tmp'); tmp.write_text(json.dumps(v,indent=2)); tmp.replace(p)
def main():
    parser=argparse.ArgumentParser(); parser.add_argument('action',choices=('start','stop','export')); parser.add_argument('job'); args=parser.parse_args()
    assert re.fullmatch(r'ike_privacy_20261015_91[0-2]',args.job)
    work=ROOT/args.job; statefile=work/'CAPTURE-PROCESS.json'
    if args.action=='start':
        assert not work.exists(),'Owned node capture directory exists; no replay'
        work.mkdir(mode=0o700)
        atom(work/'COUNTERS-BEFORE.json',counters())
        log=(work/'capture-node.log').open('x')
        child=subprocess.Popen(['tcpdump','-i','any','-nn','-s','0','-B','4096','-U','-w',str(work/'capture-node.pcap'),'ip and not tcp port 22'],
            stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=log,start_new_session=True)
        atom(statefile,{'pid':child.pid,'pcap':str(work/'capture-node.pcap'),'owned':True}); log.close()
        time.sleep(.5); assert child.poll() is None,'Node capture exited before diagnostic'
        result={'capture_started':True,'pid':child.pid}
    elif args.action=='stop':
        st=json.loads(statefile.read_text()); pid=st['pid']; p=Path(f'/proc/{pid}/cmdline')
        if p.exists() and p.read_bytes():
            argv=[v.decode(errors='replace') for v in p.read_bytes().split(bytes([0])) if v]
            assert Path(argv[0]).name=='tcpdump' and st['pcap'] in argv,'Refusing to stop non-owned capture'
            os.kill(pid,signal.SIGINT); end=time.monotonic()+5
            while time.monotonic()<end and p.exists() and p.read_bytes(): time.sleep(.1)
            if p.exists() and p.read_bytes(): raise RuntimeError('Owned tcpdump stop unconfirmed')
        atom(work/'COUNTERS-AFTER.json',counters()); text=(work/'capture-node.log').read_text()
        match=re.search(r'(\d+) packets dropped by kernel',text)
        atom(work/'CAPTURE-CHECK.json',{'stopped':True,'capture_kernel_dropped':int(match.group(1)) if match else None,
            'pcap_sha256':hashlib.sha256((work/'capture-node.pcap').read_bytes()).hexdigest()})
        result={'capture_stopped':True,'capture_kernel_dropped':int(match.group(1)) if match else None}
    else:
        assert json.loads((work/'CAPTURE-CHECK.json').read_text())['stopped']
        archive=work/'node-evidence.tar.gz'; assert not archive.exists(),'Existing export; reconcile'
        files=[work/n for n in ('COUNTERS-BEFORE.json','COUNTERS-AFTER.json','CAPTURE-CHECK.json','capture-node.pcap','capture-node.log')]
        with tarfile.open(archive,'w:gz') as tf:
            for p in files:
                assert p.is_file() and p.stat().st_size<=8388608
                tf.add(p,arcname=p.name,recursive=False)
        assert archive.stat().st_size<=8388608
        result={'archive_sha256':hashlib.sha256(archive.read_bytes()).hexdigest(),'archive_b64':base64.b64encode(archive.read_bytes()).decode()}
    print('DIAG_JSON='+json.dumps(result))
if __name__=='__main__':
    try: main()
    except Exception as error:
        import traceback
        print('REMOTE_ERROR_JSON='+json.dumps({'type':type(error).__name__,'frames':[{'file':Path(f.filename).name,'line':f.lineno,'function':f.name} for f in traceback.extract_tb(error.__traceback__)]})); raise SystemExit(1)
