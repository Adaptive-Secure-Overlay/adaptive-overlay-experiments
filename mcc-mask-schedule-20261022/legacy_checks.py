"""Offline only. Reuse validated per-TAP decoder and MAC/TTL direction checks."""
import collections,hashlib,json,re,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parent;sys.path.insert(0,str(ROOT))
import legacy_capture_decode as decoder
import legacy_analysis as helpers
def read(p):return json.loads(p.read_text(encoding='utf-8'))
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def normalize_config(text):
 records=[];current=[]
 for line in text.splitlines():
  if re.match(r'^\s*\d+\s+',line):
   if current:records.append(current)
   current=[line]
  elif current and '=' in line and not any(x in line for x in ('/queue',':put','DONE_READ','<')):current.append(line)
 if current:records.append(current)
 return sorted([sorted(re.findall(r'([A-Za-z][A-Za-z0-9-]*)=("[^"]*"|[^\s;]+)',' '.join(lines))) for lines in records])
def diffs(before,after):
 out={}
 for nid,start in before.items():
  finish=after[nid];rows={}
  for name,initial in start.get('interfaces',{}).items():
   final=finish.get('interfaces',{}).get(name)
   if not final or final['mac']!=initial['mac']:continue
   rows[name]={'mac':initial['mac'],**{k:final[k]-initial[k] if initial.get(k) is not None and final.get(k) is not None and final[k]>=initial[k] else None for k in ('rx_packets','tx_packets','rx_drop','tx_drop','tx_queue_drop','rx_error','tx_error')}}
  out[nid]={'name':start['name'],'interfaces':rows,'before_error':start.get('error'),'after_error':finish.get('error')}
 return out
def queue_summary(snapshot):
 out={}
 for nid,item in snapshot.items():
  c=item.get('commands',{});text=c.get('tree_config','');types=c.get('types','')
  out[nid]={'name':item['name'],'error':item.get('error'),'license':item.get('license_level'),
   'own_queue_names':re.findall(r'\bname="?(candidate-frag-20261015-[^\s"]+)',text),
   'own_512_type_present':bool(re.search(r'name="?candidate-frag-pfifo-20261015"?\s+kind=pfifo\s+pfifo-limit=512',types)),
   'raw_interface_queues':c.get('queues'),'raw_types':c.get('types'),'raw_tree_config':text,'raw_simple_config':c.get('simple_config')}
 return out
def main():
 assert not (ROOT/'ANALYSIS.json').exists()
 host=read(ROOT/'HOST-STATUS.json');safe=read(ROOT/'FINAL-SAFETY-CHECK.json')
 assert host['owned_clone_stopped'] and safe['passed'] and safe['copy_stopped']
 if (ROOT/'RECOVERY.json').exists():
  receipt=read(ROOT/'RECOVERY.json');assert receipt['stage']=='diagnostic_export_verified' and receipt['jobs_repeated']==0 and receipt['copy_stopped']
  e=Path(receipt['evidence_root'])
 else:e=ROOT/'evidence'
 mapping=read(e/'PATH-MAPPING.json');plan=read(ROOT/'SEALED-CONTRACT.json')
 old=plan['old_artifact_hashes'];assert all(sha(Path(n))==v for n,v in old.items())
 routers={r['node_id']:r for r in mapping['routers']};by_node=collections.defaultdict(list)
 for tap in mapping['taps']:by_node[tap['node_id']].append(tap)
 endpoints={f'User{u}':next(t for t in mapping['taps'] if t['node_id']==2*u) for u in range(6,11)}
 jobs=[];hashes={};counts=collections.Counter()
 for item in plan['attempts']:
  work=e/item['id'];result=read(work/'RESULT.json');check=read(work/'PATH-CAPTURE-CHECK.json')
  assert result['attempt']==item and not result['protocol_modified'] and result['queue_changes']==0
  assert check['stopped'] and check['capture_kernel_dropped']==0 and sha(work/'path-capture.json')==check['sha256']
  for c in check['captures']:
   p=work/c['pcap'];assert sha(p)==c['sha256'] and c['kernel_drops']==0;hashes[str(p)]=c['sha256']
  groups,quality=decoder.decode(work/'path-capture.json');assert not quality['invalid_real_udp']
  counters=diffs(read(work/'ROUTER-BEFORE.json'),read(work/'ROUTER-AFTER.json'))
  host_after=read(work/'HOST-AFTER.json')
  observations=[];direction_checks=[];bridge_losses=[]
  by_bridge=collections.defaultdict(list)
  for tap in mapping['taps']:by_bridge[tap['bridge']].append(tap)
  for group in groups.values():
   if group['sender'] not in endpoints or group['receiver'] not in endpoints:continue
   src=endpoints[group['sender']];dst=endpoints[group['receiver']]
   sent=group['points'].get((src['ifindex'],0));received=group['points'].get((dst['ifindex'],4))
   # Sender MAC -> host and receiver host -> MAC must have expected directions.
   if sent:
    assert sent['ttl']=={64};direction_checks.append({'sender':group['sender'],'tap':src['tap'],'kind':0,'ttl':[64]})
   balances=[]
   for nid,router in routers.items():
    b=helpers.router_balance(group,by_node[nid])
    if not b['ingress_count'] and not b['egress_count']:continue
    for p in b['ingress']+b['egress']:
     p['interface_names']=[name for name,v in counters.get(str(nid),{}).get('interfaces',{}).items() if v['mac']==p['guest_mac']]
    balances.append({'node_id':nid,'name':router['name'],**b})
   balances.sort(key=lambda b:b['first_ingress_epoch'] or float('inf'))
   losses=[b for b in balances if b['missing_seq']]
   tail_margin=host_after['epoch']-sent['last'] if sent else None
   qualified=bool(sent and len(sent['seq'])==group['total'] and tail_margin>=10)
   if qualified:
    for b in losses:counts[b['name']]+=len(b['missing_seq'])
   if losses:
    observations.append({'sender':group['sender'],'receiver':group['receiver'],'frag_id':group['frag_id'],'total':group['total'],'type':group['type'],'sender_sent':len(sent['seq']) if sent else None,'destination_received':len(received['seq']) if received else 0,'qualified_source_complete_tail_10s':qualified,'source_last_to_host_after_s':tail_margin,'balances':balances,'loss_router_names':[b['name'] for b in losses]})
   for bridge,taps in by_bridge.items():
    if len(taps)!=2:continue  # No guessed destination on non-point-to-point bridges.
    for src_tap,dst_tap in (taps,list(reversed(taps))):
     out=group['points'].get((src_tap['ifindex'],0));inc=group['points'].get((dst_tap['ifindex'],4))
     if not out:continue
     missing=out['seq']-(inc['seq'] if inc else set())
     if missing:bridge_losses.append({'sender':group['sender'],'receiver':group['receiver'],'frag_id':group['frag_id'],'bridge':bridge,'from_node':src_tap['node_name'],'from_tap':src_tap['tap'],'to_node':dst_tap['node_name'],'to_tap':dst_tap['tap'],'egress_count':len(out['seq']),'adjacent_ingress_count':len(inc['seq']) if inc else 0,'missing_seq':sorted(missing),'qualified_source_complete_tail_10s':qualified})
  job={'id':item['id'],'success':result['success'],'native_s':result['up']['elapsed_seconds'],'packet_counts':result['packet_counts'],'capture_quality':quality,'router_counters':counters,'groups':len(groups),'messages_with_router_difference':observations,'point_to_point_bridge_losses':bridge_losses,'direction_checks':direction_checks}
  jobs.append(job)
 static=read(e/'ROUTER-STATIC.json');preservation=read(e/'QUEUE-CONFIG-PRESERVATION.json');final=read(e/'ROUTER-FINAL.json')
 normalized={nid:{kind:normalize_config(item['commands'][kind])==normalize_config(final[nid]['commands'][kind]) for kind in ('queues','types','tree_config','simple_config')} for nid,item in static.items()}
 assert all(all(v.values()) for v in normalized.values()),'Meaningful queue configuration differs; do not claim unchanged'
 analysis={'jobs':jobs,'router_fragment_differences':dict(counts),'queue_summary':queue_summary(static),'queue_configuration_preservation_raw':preservation,'queue_configuration_preservation_normalized':normalized,'router_count':len(routers),'tap_count':len(mapping['taps']),'capture_hashes':hashes,'safety':safe,
 'limitations':['Per-TAP differences locate a router/virtual-adapter boundary, not automatically a particular internal queue.','Router drop counters cover the full job including other traffic; unknown fields are not zero.','MAC establishes direction; adjacent bridge taps and TTL must agree before final attribution.','Full capture starts before actors and stops after the connection; partial captures must not be used.']}
 (ROOT/'ANALYSIS.json').write_text(json.dumps(analysis,ensure_ascii=False,indent=2),encoding='utf-8')
 print(json.dumps({'jobs':len(jobs),'routers':len(routers),'taps':len(mapping['taps']),'router_fragment_differences':dict(counts),'verified_pcaps':len(hashes)},ensure_ascii=False))
if __name__=='__main__':main()
