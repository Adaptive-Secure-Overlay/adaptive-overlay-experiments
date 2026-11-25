"""Offline identify identical fragments at router ingress/egress and queue deltas."""
import base64,collections,hashlib,json,re,subprocess,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parent; TSHARK=Path(r'C:\Program Files\Wireshark\tshark.exe')
def read(p): return json.loads(p.read_text(encoding='utf-8'))
def sha(p): return hashlib.sha256(p.read_bytes()).hexdigest()
def decode_path(p):
    if p.suffix=='.json':
        import verify_localization
        groups,q=verify_localization.decode(p)
        return groups,{'malformed_overlay':len(q['invalid_real_udp']),'invalid_ifindex':0,'icmp_quotations_excluded':len(q['icmp_quotations'])}
    assert p.stat().st_size<=64*1024**2
    argv=[str(TSHARK),'-n','-o','ip.defragment:false','-r',str(p),'-Y','udp.port == 9000','-T','fields',
      '-e','frame.time_epoch','-e','sll.ifindex','-e','sll.pkttype','-e','ip.ttl','-e','udp.payload']
    r=subprocess.run(argv,capture_output=True,text=True,timeout=90,shell=False,creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0)); assert r.returncode==0,'Existing SLL2 decoder unavailable'
    groups={}; malformed=0; invalid_ifindex=0
    for line in r.stdout.splitlines():
        f=line.split('\t')
        if len(f)!=5 or not f[4]: continue
        try: epoch=float(f[0]); idx=int(f[1]); direction=int(f[2]); ttl=int(f[3]); payload=bytes.fromhex(f[4].replace(':',''))
        except ValueError: invalid_ifindex+=1; continue
        try: msg=json.loads(payload)
        except (ValueError,UnicodeDecodeError): malformed+=1; continue
        if msg.get('t')!='LINK_FRAG': continue
        key=(msg.get('from'),msg.get('to'),msg.get('frag_id')); g=groups.setdefault(key,{'sender':key[0],'receiver':key[1],'frag_id':key[2],'total':msg['total'],'parts':{},'points':{},'type':None})
        assert g['total']==msg['total']; seq=msg['seq']; data=base64.b64decode(msg['data'],validate=True)
        assert seq not in g['parts'] or data==g['parts'][seq],'Conflicting same-fragment payloads'
        g['parts'][seq]=data; point=g['points'].setdefault((idx,direction),{'seq':set(),'first':epoch,'last':epoch,'ttl':set()}); point['seq'].add(seq); point['last']=epoch; point['ttl'].add(ttl)
    for g in groups.values():
        if set(g['parts'])==set(range(g['total'])): g['type']=json.loads(b''.join(g['parts'][i] for i in range(g['total']))).get('t')
        g.pop('parts')
    return groups,{'malformed_overlay':malformed,'invalid_ifindex':invalid_ifindex}
def router_balance(group,taps):
    incoming=set(); outgoing=set(); ins=[]; outs=[]
    for tap in taps:
        for (idx,kind),point in group['points'].items():
            if idx!=tap['ifindex']: continue
            item={'tap':tap['tap'],'interface_id':tap['interface_id'],'guest_mac':tap.get('guest_mac'),'seq':sorted(point['seq']),
              'count':len(point['seq']),'first_epoch':point['first'],'last_epoch':point['last'],'ttl':sorted(point['ttl']),'sll_packet_type':kind}
            if kind==4: incoming.update(point['seq']); ins.append(item)
            elif kind in (0,1,2,3): outgoing.update(point['seq']); outs.append(item)
    return {'ingress':ins,'egress':outs,'ingress_count':len(incoming),'egress_count':len(outgoing),'missing_seq':sorted(incoming-outgoing),'first_ingress_epoch':min((x['first_epoch'] for x in ins),default=None)}
def queue_deltas(before,after):
    out={}
    for node,b in before.items():
        end=after.get(node,{}); rows={}
        for name,start in b.get('interfaces',{}).items():
            finish=end.get('interfaces',{}).get(name)
            if not finish or start.get('mac')!=finish.get('mac'): continue
            rows[name]={'mac':start['mac'],**{k:finish[k]-start[k] if start.get(k) is not None and finish.get(k) is not None and finish[k]>=start[k] else None for k in ('rx_packets','tx_packets','tx_queue_drop')}}
        out[node]={'interfaces':rows,'before_available':b.get('counters_available',False),'after_available':end.get('counters_available',False)}
    return out
def main():
    assert not (ROOT/'ANALYSIS.json').exists(),'Preserve an existing analysis'
    host=read(ROOT/'HOST-STATUS.json'); safety=read(ROOT/'FINAL-SAFETY-CHECK.json'); assert safety['clone_stopped'] and safety['source_not_started'] and safety['passed']
    evidence=ROOT/'evidence'; mapping=read(evidence/'PATH-MAPPING.json'); static=read(evidence/'ROUTER-STATIC.json'); contract=read(ROOT/'SEALED-CONTRACT.json')
    routers={int(r['node_id']):r for r in mapping['routers']}; taps_by_node=collections.defaultdict(list)
    for tap in mapping['taps']: taps_by_node[int(tap['node_id'])].append(tap)
    jobs=[]; candidates=[]; hashes={}
    for attempt in contract['attempts']:
        w=evidence/attempt['id']
        if not (w/'RESULT.json').exists(): continue
        result=read(w/'RESULT.json'); assert result['attempt']==attempt and not result['replayed'] and not result['protocol_modified']
        capture=w/'path-capture.json'; check=read(w/'PATH-CAPTURE-CHECK.json'); assert check['stopped'] and sha(capture)==check['sha256']; hashes[capture.relative_to(ROOT).as_posix()]=sha(capture)
        for cap in check['captures']: assert sha(w/cap['pcap'])==cap['sha256']
        groups,decode_quality=decode_path(capture); qualified=check['capture_kernel_dropped']==0 and decode_quality['malformed_overlay']==decode_quality['invalid_ifindex']==0
        counters=queue_deltas(read(w/'ROUTER-BEFORE.json'),read(w/'ROUTER-AFTER.json')); messages=[]
        for key,g in groups.items():
            if not g['type'] or not g['sender'] or not g['receiver']: continue
            balances=[]
            for nid,router in routers.items():
                b=router_balance(g,taps_by_node[nid])
                if not b['ingress_count'] and not b['egress_count']: continue
                entries=counters.get(str(nid),{}).get('interfaces',{}); matched=[]
                for point in b['egress']:
                    matched.extend({'tap':point['tap'],'interface':name,'delta':row} for name,row in entries.items() if point.get('guest_mac') and row['mac']==point['guest_mac'])
                balances.append({'node_id':nid,'name':router['name'],**b,'matching_egress_queue_deltas':matched})
            balances.sort(key=lambda x:x['first_ingress_epoch'] or float('inf'))
            losses=[x for x in balances if x['missing_seq']]
            if losses:
                record={'job':attempt['id'],'sender':g['sender'],'receiver':g['receiver'],'frag_id':g['frag_id'],'type':g['type'],'total':g['total'],
                  'capture_quality_ok':qualified,'router_balances':balances,'first_loss_router_candidate':losses[0]}
                messages.append(record)
                if qualified: candidates.append(record)
        host_before=read(w/'HOST-BEFORE.json'); host_after=read(w/'HOST-AFTER.json')
        host_delta={name:{k:host_after['interfaces'][name][k]-start[k] for k in start} for name,start in host_before['interfaces'].items() if name in host_after['interfaces']}
        jobs.append({'id':attempt['id'],'success':result['connection_success'],'native_s':result['up']['elapsed_seconds'],'qualified_capture':qualified,'capture_quality':check,'decode_quality':decode_quality,'router_queue_deltas':counters,'host_interface_deltas':host_delta,'messages_with_unequal_router_counts':messages})
        for p in w.rglob('*.pcap'):
            assert p.stat().st_size<=64*1024**2; hashes[p.relative_to(ROOT).as_posix()]=sha(p)
    counts=collections.Counter(x['first_loss_router_candidate']['name'] for x in candidates)
    analysis={'host_stage':host['stage'],'completed_jobs':len(jobs),'planned_jobs':3,'router_inventory_count':len(routers),'tap_inventory_count':len(mapping['taps']),
      'qualified_messages_with_router_ingress_egress_difference':len(candidates),'first_loss_candidates_by_router':dict(counts),'jobs':jobs,
      'license_levels':{r['name']:static.get(str(nid),{}).get('license_level') for nid,r in routers.items()},
      'limitations':['An ingress/egress difference locates a router/virtual-adapter boundary, not automatically a particular RouterOS queue.','Counters are full-job deltas and can include other protocol branches or routing traffic.','Validate SLL2 host→TAP ingress direction using endpoint/bridge observations and TTL before declaring the router accepted.','License limits are not causal proof without matching capture and counter evidence.','Non-reproduction does not prove no fault.'],'safety':safety}
    (ROOT/'ANALYSIS.json').write_text(json.dumps(analysis,indent=2),encoding='utf-8'); (ROOT/'CAPTURE-HASHES.json').write_text(json.dumps(hashes,indent=2),encoding='utf-8')
    lines=['Локализация потерь по маршрутизаторам в изолированной копии','',f'Сохранено соединений: {len(jobs)} из 3. Сопоставлено виртуальных интерфейсов: {len(mapping["taps"])}.',f'Сообщений с различием входа и выхода маршрутизатора при качественном захвате: {len(candidates)}.',
      'Первые кандидаты по маршрутизаторам: '+json.dumps(dict(counts),ensure_ascii=False), '']
    for j in jobs:
        lines.append(f"{j['id']}: успех={j['success']}; внутреннее время={j['native_s']:.6f} с; захват пригоден={j['qualified_capture']}; сообщений с потерями={len(j['messages_with_unequal_router_counts'])}.")
        for m in j['messages_with_unequal_router_counts'][:12]:
            b=m['first_loss_router_candidate']; lines.append(f"  {m['type']} {m['sender']} → {m['receiver']}: кандидат {b['name']}, на входе {b['ingress_count']}, на выходах суммарно {b['egress_count']}, недостаёт {len(b['missing_seq'])}; счётчики выходов: "+json.dumps(b['matching_egress_queue_deltas'],ensure_ascii=False))
    lines+=['','Это машинная локализация кандидата, а не автоматическое доказательство конкретной очереди. До окончательного вывода проверить направленность TAP, соседние мосты, TTL, снимки tc и счётчики RouterOS. Ничего не исправлялось: код, очереди, ограничения, маршруты и лицензии не менялись. Исходный стенд и старые материалы сохранены; собственная копия выключена.']
    (ROOT/'REPORT-RU.txt').write_text('\n'.join(lines)+'\n',encoding='utf-8'); print(json.dumps({'jobs':len(jobs),'first_loss_candidates_by_router':dict(counts),'clone_stopped':True}))
if __name__=='__main__': main()
