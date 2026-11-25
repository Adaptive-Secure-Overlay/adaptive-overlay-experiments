"""No network actions. Inner ledgers are diagnostics, NEVER classifier inputs."""
import collections
import hashlib
import json
import struct
import subprocess
from pathlib import Path

HEADER=struct.Struct('!4s16sI')
TSHARK=Path(r'C:\Program Files\Wireshark\tshark.exe')

def is_mask_udp(p):
    return p['proto']=='17' and 9000 in (p['sport'],p['dport']) and p['payload'].startswith(b'MSK1')


def ledger_check(final,source):
    rows={f'User{u}':r['mask_result'] for u,r in final.items()}
    assert set(rows)=={'User6','User7','User8','User9','User10'}
    good=True;edges=[]
    for name,row in rows.items():
        expected=set(rows)-{name} if name==source else {source}
        good &= bool(row['started'] and row['done'] and not row['error'] and row['source']==source and
                     row['invalid_records']==0 and row['plaintext_after_activation']==0 and
                     row['gate'] and row['gate']['released'] and row['gate']['packets']==0 and
                     set(row['tx'])==expected and set(row['rx'])==expected and not any(row['queued'].values()))
        good &= bool(row.get('sender_ready') and row.get('sender_exited') and row.get('sender',{}).get('separate_interpreter') and
                     row.get('sender',{}).get('buffer_options_changed') is False and row.get('max_lateness_s',float('inf'))<=.020)
        for peer,tx in row['tx'].items():
            rx=rows[peer]['rx'][name]
            match=len(tx)==len(rx)==1000 and sorted(tx)==sorted(rx) and sorted(n for n,h in tx)==list(range(1000))
            good &= match
            edges.append({'from':name,'to':peer,'sent':len(tx),'received':len(rx),'real_records':sum(h is not None for n,h in tx),'matched':match})
    return {'passed':bool(good),'edges':edges,'real_records':sum(r['real_records'] for r in edges),
            'diagnostic_hashes_excluded_from_observer_features':True}


def packets(path):
    assert path.stat().st_size<=32*1024**2
    fields=['frame.time_epoch','ip.src','ip.dst','ip.proto','udp.srcport','udp.dstport','ip.len','udp.payload']
    args=[str(TSHARK),'-n','-o','ip.defragment:false','-r',str(path),'-Y','ip','-T','fields','-E','occurrence=f']
    for f in fields:args+=['-e',f]
    r=subprocess.run(args,capture_output=True,text=True,timeout=45,creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
    assert r.returncode==0 and len(r.stdout)<64*1024**2
    out=[]
    for line in r.stdout.splitlines():
        v=line.split('\t');assert len(v)==8
        out.append({'time':float(v[0]),'src':v[1],'dst':v[2],'proto':v[3],
                    'sport':int(v[4]) if v[4] else None,'dport':int(v[5]) if v[5] else None,
                    'size':int(v[6]),'payload':bytes.fromhex(v[7].replace(':',''))})
    return out


def capture_check(work,result,final):
    rows={f'User{u}':r['mask_result'] for u,r in final.items()}
    source=result['attempt']['initiator']; token=bytes.fromhex(result['attempt']['mask_token'])
    data={};bad=[]
    for name in rows:
        user=name[4:];path=work/f'{name}.pcap';proof=result['captures'][user]
        assert hashlib.sha256(path.read_bytes()).hexdigest()==proof['sha256'] and proof['kernel_drops']==0
        values=packets(path);data[name]=values
        observed=collections.Counter()
        for p in values:
            raw=p['payload']
            # ICMP may quote UDP payload. A quotation is NOT a cover datagram.
            if not is_mask_udp(p):continue
            if len(raw)!=1124 or p['size']!=1152 or p['proto']!='17':bad.append('wrong_size');continue
            magic,context,seq=HEADER.unpack(raw[:HEADER.size])
            if context!=token or seq>=1000:bad.append('wrong_context');continue
            observed[p['src'],p['dst'],seq]+=1
        expected=collections.Counter()
        ip=lambda n:'192.168.'+str(100+int(n[4:]))+'.10'
        for peer in rows[name]['tx']:
            for seq in range(1000):expected[ip(name),ip(peer),seq]+=1
        for peer in rows[name]['rx']:
            for seq in range(1000):expected[ip(peer),ip(name),seq]+=1
        if observed!=expected:bad.append('capture_sequence_coverage_'+name)
    # ESP only cuts off the observation. It is never a feature or a source of B.
    a=data[source]
    first=min(p['time'] for p in a if is_mask_udp(p) and p['src']=='192.168.'+str(100+int(source[4:]))+'.10')
    def esp(p):return p['proto']=='50' or (p['proto']=='17' and 4500 in (p['sport'],p['dport']) and p['payload'][:4]!=bytes(4))
    ends=[p['time'] for p in a if esp(p) and p['time']>=first]
    assert ends,'No ESP boundary observed'
    end=min(ends);visible=[p for p in a if first<=p['time']<end]
    cover=[p for p in visible if is_mask_udp(p)]
    if len(cover)!=8000:bad.append('fixed_cover_not_complete_before_ESP')
    noncover=[p for p in visible if not p['payload'].startswith(b'MSK1') and p['proto']=='17' and 9000 in (p['sport'],p['dport'])]
    if noncover:bad.append('unwrapped_overlay_inside_mask_window')
    direct=[p for p in visible if p['proto']=='17' and ({p['sport'],p['dport']}&{500,4500})]
    if direct:bad.append('direct_IKE_or_keepalive_visible_before_ESP')
    return {'passed':not bad,'errors':bad,'pcaps':5,'packets_at_A':len(cover),
            'ip_bytes_at_A':sum(p['size'] for p in cover),'window_to_ESP_s':end-first,
            'observer_rows':[{k:p[k] for k in ('time','src','dst','sport','dport','size')} for p in visible],
            'observer_prefix_rows':[{k:p[k] for k in ('time','src','dst','sport','dport','size')} for p in a if p['time']<end]}
