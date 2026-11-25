"""Independent saved-capture verification; never connects to a running lab.

Exclude ICMP quotations from real UDP observations. Preserve all received
ICMP in the original capture and count it separately, rather than calling
quoted inner headers invalid interface metadata.
"""
import base64, collections, hashlib, json, subprocess, sys
from pathlib import Path
ROOT=Path(__file__).resolve().parent
sys.dont_write_bytecode=True
sys.path.insert(0,str(ROOT))
import legacy_analysis as a

def ether_lines(path,cap):
    fields=['frame.number','frame.time_epoch','eth.src','eth.dst','ip.src','ip.dst','ip.ttl','ip.id','ip.proto','icmp.type','udp.payload']
    cmd=[str(a.TSHARK),'-n','-o','ip.defragment:false','-r',str(path),'-Y','udp.port == 9000','-T','fields']
    for f in fields: cmd+=['-e',f]
    p=subprocess.run(cmd,capture_output=True,text=True,timeout=90,creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0)); assert p.returncode==0
    for line in p.stdout.splitlines():
        v=line.split('\t'); assert len(v)==11
        src,dst=v[2].lower(),v[3].lower(); mac=cap['guest_mac'].lower()
        kind=0 if src==mac else 4 if dst==mac or dst=='ff:ff:ff:ff:ff:ff' else -1
        yield '\t'.join(v[:2]+[str(cap['ifindex']),str(kind)]+v[4:])

def decode(path):
    fields=['frame.number','frame.time_epoch','sll.ifindex','sll.pkttype',
            'ip.src','ip.dst','ip.ttl','ip.id','ip.proto','icmp.type','udp.payload']
    cmd=[str(a.TSHARK),'-n','-o','ip.defragment:false','-r',str(path),
         '-Y','udp.port == 9000','-T','fields']
    for f in fields: cmd+=['-e',f]
    if path.suffix=='.json':
        manifest=a.read(path); assert manifest['format']=='per_tap_ethernet'
        lines=(line for cap in manifest['captures'] for line in ether_lines(path.parent/cap['pcap'],cap))
    else:
        p=subprocess.run(cmd,capture_output=True,text=True,timeout=120,
                         creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
        assert p.returncode==0
        lines=p.stdout.splitlines()
    groups={}; quotes=[]; invalid=[]; nonfrag=0
    for line in lines:
        v=line.split('\t')
        if len(v)!=len(fields): invalid.append({'frame':v[0],'reason':'column_count'}); continue
        if v[9]:
            quotes.append({'frame':int(v[0]),'icmp_type':v[9],
                           'ip_src_chain':v[4],'ip_dst_chain':v[5]})
            continue
        try:
            frame=int(v[0]); epoch=float(v[1]); idx=int(v[2]); kind=int(v[3]); ttl=int(v[6])
            assert v[8]=='17' and kind in (0,1,2,3,4)
            payload=bytes.fromhex(v[10].replace(':',''))
            if payload.startswith(b'MSK1'):
                assert len(payload)==1124
                nonfrag+=1;continue
            msg=json.loads(payload)
            if msg.get('t')!='LINK_FRAG': nonfrag+=1; continue
            seq=int(msg['seq']); total=int(msg['total']); data=base64.b64decode(msg['data'],validate=True)
            assert 0<=seq<total<=94
            key=(msg['from'],msg['to'],msg['frag_id'])
            g=groups.setdefault(key,{'sender':key[0],'receiver':key[1],'frag_id':key[2],
                       'total':total,'parts':{},'points':{},'type':None})
            assert g['total']==total and (seq not in g['parts'] or g['parts'][seq]==data)
            g['parts'][seq]=data
            point=g['points'].setdefault((idx,kind),{'seq':set(),'first':epoch,'last':epoch,'ttl':set(),'frames':[],'ip_src':set(),'ip_dst':set()})
            point['seq'].add(seq); point['last']=epoch; point['ttl'].add(ttl)
            point['frames'].append(frame); point['ip_src'].add(v[4]); point['ip_dst'].add(v[5])
        except Exception as error: invalid.append({'frame':v[0],'reason':type(error).__name__})
    for g in groups.values():
        if len(g['parts'])==g['total']:
            g['type']=json.loads(b''.join(g['parts'][i] for i in range(g['total']))).get('t')
        g.pop('parts')
    return groups,{'invalid_real_udp':invalid,'icmp_quotations':quotes,'nonfragment_udp':nonfrag}

def main():
    assert not (ROOT/'INDEPENDENT-LOCALIZATION.json').exists(),'Preserve verification'
    safety=a.read(ROOT/'FINAL-SAFETY-CHECK.json'); assert safety['passed'] and safety['clone_stopped'] and safety['source_not_started']
    mapping=a.read(ROOT/'evidence/PATH-MAPPING.json')
    bynode=collections.defaultdict(list)
    for tap in mapping['taps']: bynode[tap['node_id']].append(tap)
    routers={r['node_id']:r for r in mapping['routers']}
    jobs=[]
    for spec in a.read(ROOT/'SEALED-CONTRACT.json')['attempts']:
        w=ROOT/'evidence'/spec['id']
        if not (w/'RESULT.json').exists(): continue
        result=a.read(w/'RESULT.json'); assert result['attempt']==spec
        check=a.read(w/'PATH-CAPTURE-CHECK.json'); assert a.sha(w/'path-capture.json')==check['sha256']
        for cap in check['captures']: assert a.sha(w/cap['pcap'])==cap['sha256']
        groups,quality=decode(w/'path-capture.json'); loss_messages=[]
        for g in groups.values():
            balances=[]
            for nid,taps in bynode.items():
                b=a.router_balance(g,taps)
                if b['ingress_count'] or b['egress_count']:
                    balances.append({'node_id':nid,'name':taps[0]['node_name'],'is_router':nid in routers,**b})
            losses=[b for b in balances if b['is_router'] and b['missing_seq']]
            if not losses: continue
            balances.sort(key=lambda b:b['first_ingress_epoch'] or float('inf'))
            observations=[]
            for (idx,kind),point in g['points'].items():
                tap=next((t for t in mapping['taps'] if t['ifindex']==idx),None)
                observations.append({'ifindex':idx,'interface':tap['tap'] if tap else next((n for n,i in mapping['ifindices'].items() if i==idx),'unknown'),
                    'node':tap['node_name'] if tap else None,'packet_type':kind,
                    **{k:sorted(v) if isinstance(v,set) else v for k,v in point.items()}})
            observations.sort(key=lambda v:v['first'])
            loss_messages.append({k:g[k] for k in ('sender','receiver','frag_id','total','type')}|
                                 {'balances':balances,'all_observations':observations})
        jobs.append({'id':spec['id'],'success':result['connection_success'],'native_s':result['up']['elapsed_seconds'],
                     'capture_kernel_dropped':check['capture_kernel_dropped'],'decode_quality':quality,
                     'loss_messages':loss_messages,
                     'router_queue_deltas':a.queue_deltas(a.read(w/'ROUTER-BEFORE.json'),a.read(w/'ROUTER-AFTER.json'))})
    (ROOT/'INDEPENDENT-LOCALIZATION.json').write_text(json.dumps({'jobs':jobs,'safety':safety,
        'direction_acceptance':'Must inspect sender TAP pkttype=0 at TTL64, next router TAP pkttype=4 at same TTL, router egress pkttype=0 with TTL63 and adjacent ingress TTL63.',
        'queue_acceptance':'Compare MAC-matched interface tx_queue_drop with missing fragment ids; host tc and softnet counters separately. Unknown is not zero.'},indent=2),encoding='utf-8')
    print(json.dumps({'verified_jobs':len(jobs),'loss_messages':sum(len(j['loss_messages']) for j in jobs),
                      'invalid_real_udp':sum(len(j['decode_quality']['invalid_real_udp']) for j in jobs)}))

if __name__=='__main__': main()
