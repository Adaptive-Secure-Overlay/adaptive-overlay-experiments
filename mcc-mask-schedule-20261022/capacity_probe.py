"""Finite synthetic UDP9000 test, only isolated User6/User7, no buffer changes."""
import argparse,hashlib,json,os,re,socket,subprocess,sys,threading,time,traceback
from pathlib import Path
ROOT=Path(__file__).resolve().parent
PORT=9000;PAYLOAD=1124;IP_BYTES=1152;RATE=26_000_000;DURATION=2.;LIFETIME=9.
ALLOWED={'192.168.106.10','192.168.107.10'}

def atom(p,v):
    tmp=p.with_suffix('.tmp');tmp.write_text(json.dumps(v));tmp.replace(p)

def socket_drops(sock):
    inode=re.fullmatch(r'socket:\[(\d+)\]',os.readlink('/proc/self/fd/'+str(sock.fileno()))).group(1)
    rows=[v.split() for v in Path('/proc/net/udp').read_text().splitlines()[1:]]
    rows=[r for r in rows if len(r)>=13 and r[9]==inode]
    assert len(rows)==1,'Probe socket ownership unknown'
    return int(rows[0][-1])

def worker(job,peer,token):
    result={'job':job,'peer':peer,'token':token,'buffer_options_changed':False,'sent':0,'received':0,'duplicates':0,'invalid':0}
    sock=None
    try:
        prefix=b'CAP4'+bytes.fromhex(token);assert len(prefix)==20
        sock=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);sock.bind(('0.0.0.0',PORT));sock.settimeout(.1)
        result['receive_buffer_effective']=sock.getsockopt(socket.SOL_SOCKET,socket.SO_RCVBUF)
        seen=set();tx_times=[];rx_times=[];thread_error=[];started=time.monotonic();count=int(RATE*DURATION/(IP_BYTES*8))
        result['expected_count']=count
        def send():
            try:
                origin=started+2.;interval=IP_BYTES*8/RATE
                for seq in range(count):
                    remaining=origin+seq*interval-time.monotonic()
                    if remaining>0:time.sleep(remaining)
                    if time.monotonic()>origin+DURATION+.1:raise TimeoutError('Probe sender deadline')
                    wire=prefix+seq.to_bytes(4,'big')+bytes(PAYLOAD-24)
                    assert sock.sendto(wire,(peer,PORT))==PAYLOAD
                    tx_times.append(time.monotonic())
            except Exception as error:thread_error.append(type(error).__name__)
        sender=threading.Thread(target=send,name='owned-capacity-sender',daemon=True);sender.start()
        while time.monotonic()-started<LIFETIME:
            try:data,remote=sock.recvfrom(65535)
            except socket.timeout:continue
            if remote!=(peer,PORT) or len(data)!=PAYLOAD or not data.startswith(prefix):result['invalid']+=1;continue
            seq=int.from_bytes(data[20:24],'big')
            if not 0<=seq<count:result['invalid']+=1;continue
            if seq in seen:result['duplicates']+=1;continue
            seen.add(seq);rx_times.append(time.monotonic())
        sender.join(timeout=1);assert not sender.is_alive()
        result.update(sent=len(tx_times),received=len(seen),missing=count-len(seen),missing_first16=sorted(set(range(count))-seen)[:16],
            sender_errors=thread_error,socket_drops=socket_drops(sock),
            tx_span_s=tx_times[-1]-tx_times[0] if len(tx_times)>1 else None,
            rx_span_s=rx_times[-1]-rx_times[0] if len(rx_times)>1 else None)
        result['tx_ip_bps']=len(tx_times)*IP_BYTES*8/result['tx_span_s'] if result['tx_span_s'] else None
        result['rx_ip_bps']=len(rx_times)*IP_BYTES*8/result['rx_span_s'] if result['rx_span_s'] else None
    except Exception as error:
        result.update(error_type=type(error).__name__,frames=[{'file':Path(f.filename).name,'line':f.lineno} for f in traceback.extract_tb(error.__traceback__)])
    finally:
        if sock:sock.close()
        atom(ROOT/(job+'-CAPACITY.json'),result)

def main():
    p=argparse.ArgumentParser();p.add_argument('action',choices=('start','run','collect'));p.add_argument('job');p.add_argument('--peer');p.add_argument('--token');a=p.parse_args()
    assert re.fullmatch(r'cap4_(?:before|after)_\d{2}',a.job)
    assert a.peer in ALLOWED and re.fullmatch('[0-9a-f]{32}',a.token or '')
    marker=ROOT/(a.job+'-CAPACITY-START.json');output=ROOT/(a.job+'-CAPACITY.json')
    if a.action=='start':
        assert not marker.exists() and not output.exists(),'Existing/uncertain capacity attempt; never replay'
        assert ':9000' not in subprocess.check_output(['ss','-lun'],text=True),'Overlay listener already owned'
        with marker.open('x') as stream:json.dump({'job':a.job,'peer':a.peer,'token':a.token,'started_at':time.time()},stream)
        child=subprocess.Popen([sys.executable,'-B',str(Path(__file__).resolve()),'run',a.job,'--peer',a.peer,'--token',a.token],
             cwd=ROOT,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,start_new_session=True)
        value={'started':True,'pid':child.pid,'job':a.job}
    elif a.action=='run':worker(a.job,a.peer,a.token);return
    else:
        deadline=time.monotonic()+12
        while not output.exists() and time.monotonic()<deadline:time.sleep(.1)
        value=json.loads(output.read_text());assert value['job']==a.job and value['peer']==a.peer and value['token']==a.token
    print('PUBLIC_JSON='+json.dumps(value))
if __name__=='__main__':main()
