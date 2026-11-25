"""Copy-only capacity admission and one bounded User6 OS-reboot comparison.

Existing current-tail console, owned TAP capture and synthetic UDP helpers reused.
No image/license/queue/buffer/OS package changes. No IKE during capacity phase.
"""
import base64,hashlib,json,math,re,secrets,signal,subprocess,time,traceback
from pathlib import Path
import guest_setup as v
import admission
import path_capture as pc
import router_read as rr
from series_common import canonical,verify_queues
ROOT=Path(__file__).resolve().parent
MIN_BPS=22_000_000
GUEST_PY='/root/candidate-mcc-runtime3148-5002-restored-20261015/python/bin/python3.14'

def pure_rate(text):
    rows=[]
    for line in text.splitlines():
        m=re.match(r'^([0-9]+\.[0-9]+).*UDP, length ([0-9]+)\s*$',line)
        if m:rows.append((float(m[1]),int(m[2])+28))
    if len(rows)<2:return {'packets':len(rows),'ip_bps':None,'span_s':None}
    span=rows[-1][0]-rows[0][0]
    return {'packets':len(rows),'ip_bytes':sum(n for _,n in rows),'span_s':span,'ip_bps':8*sum(n for _,n in rows)/span if span>0 else None}

def check_rows(nodes,egress):
    def finite(v):return isinstance(v,(int,float)) and not isinstance(v,bool) and math.isfinite(v)
    def at_least(v,limit):return finite(v) and v>=limit
    source_ok=set(nodes)=={'6','7'} and all(not n.get('error_type') and not n.get('sender_errors') and at_least(n.get('tx_ip_bps'),MIN_BPS) and at_least(n.get('tx_span_s'),1.8) and n.get('socket_drops')==0 and n.get('buffer_options_changed') is False for n in nodes.values())
    delivery_ok=source_ok and all(n.get('received')==n.get('expected_count')==n.get('sent') and at_least(n.get('sent'),1) and n.get('duplicates')==0 and n.get('invalid')==0 and at_least(n.get('rx_ip_bps'),MIN_BPS) for n in nodes.values())
    physical_ok=set(egress)=={'ether1','ether2'} and all(at_least(r.get('ip_bps'),MIN_BPS) and at_least(r.get('span_s'),1.8) for r in egress.values())
    limit_pattern=source_ok and set(egress)=={'ether1','ether2'} and all(finite(r.get('ip_bps')) and 500_000<=r['ip_bps']<=2_000_000 and at_least(r.get('span_s'),1.8) for r in egress.values())
    return {'passed':bool(delivery_ok and physical_ok),'source_qualified':bool(source_ok),'delivery_qualified':bool(delivery_ok),'physical_egress_qualified':bool(physical_ok),'low_egress_pattern':bool(limit_pattern),'minimum_required_ip_bps':MIN_BPS}

def install_helpers():
    data=(ROOT/'capacity_probe.py').read_bytes();encoded=base64.b64encode(data).decode();digest=hashlib.sha256(data).hexdigest()
    for u in (6,7):
        cmd=f"{GUEST_PY} -B - <<'PY'\nimport ast,base64,hashlib,os\nfrom pathlib import Path\np=Path('{ROOT}/capacity_probe.py'); assert not p.exists()\nd=base64.b64decode('{encoded}');assert hashlib.sha256(d).hexdigest()=='{digest}';ast.parse(d.decode());fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o700)\nwith os.fdopen(fd,'wb') as f:f.write(d)\nPY"
        v.g.ssh(u,cmd,timeout=25)

def needs_reboot(checks,level):
    return checks['source_qualified'] and ((not checks['passed'] and checks['low_egress_pattern']) or level=='free')

def node(u,action,job,peer,token):
    return admission.remote_json(u,f'{GUEST_PY} -B {ROOT}/capacity_probe.py {action} {job} --peer {peer} --token {token}',timeout=25)

def probe(mapping,name):
    work=ROOT/'capacity'/name;work.mkdir(parents=True,mode=0o700,exist_ok=False)
    router=next(r for r in mapping['routers'] if r['node_id']==13)
    before=rr.snapshot(router,False);v.atom(work/'ROUTER-BEFORE.json',before)
    assert not before.get('error') and before.get('logout_confirmed') and before['interfaces'],'Fresh User6 counter ownership unknown'
    taps=[t for t in mapping['taps'] if t['node_id']==13];assert len(taps)==2
    manifest=[];children=[];token=secrets.token_hex(16);job='cap4_'+name+'_00'
    try:
        for tap in taps:
            names=[n for n,row in before['interfaces'].items() if row['mac']==tap['guest_mac'].lower()];assert len(names)==1
            interface=names[0];cap=work/(interface+'.pcap');stream=(work/(interface+'.log')).open('x')
            bpf='ether src '+tap['guest_mac']+' and ip and udp port 9000 and (host 192.168.106.10 and host 192.168.107.10)'
            child=subprocess.Popen(['tcpdump','-i',tap['tap'],'-nn','-s','96','-B','1024','-U','-w',str(cap),bpf],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=stream)
            children.append((child,stream,interface));manifest.append({**tap,'interface':interface,'pcap':cap.name})
        assert all(p.poll() is None for p,_,_ in children)
        starts={str(u):node(u,'start',job,f'192.168.{100+peer}.10',token) for u,peer in ((6,7),(7,6))}
        v.atom(work/'STARTS.json',starts)
        nodes={str(u):node(u,'collect',job,f'192.168.{100+peer}.10',token) for u,peer in ((6,7),(7,6))}
        v.atom(work/'NODE-RESULTS.json',nodes)
    finally:
        for child,stream,interface in children:
            if child.poll() is None:child.send_signal(signal.SIGINT)
        for child,stream,interface in children:
            child.wait(timeout=8);stream.close()
    egress={}
    for _,_,interface in children:
        cap=work/(interface+'.pcap');assert cap.stat().st_size<=8*1024**2
        m=re.search(r'(\d+) packets dropped by kernel',(work/(interface+'.log')).read_text());assert m and int(m[1])==0,'Capture loss is unknown, not network loss'
        decoded=subprocess.run(['tcpdump','-r',str(cap),'-tt','-nn','-q'],capture_output=True,text=True,timeout=20,check=True)
        egress[interface]=pure_rate(decoded.stdout);egress[interface]['pcap_sha256']=hashlib.sha256(cap.read_bytes()).hexdigest()
    after=rr.snapshot(router,False);v.atom(work/'ROUTER-AFTER.json',after)
    assert not after.get('error') and after.get('logout_confirmed'),'Fresh User6 final counters unknown'
    result={'name':name,'nodes':nodes,'egress':egress,'capture_manifest':manifest,'checks':check_rows(nodes,egress),
            'queue_drop_deltas':{n:after['interfaces'][n]['tx_queue_drop']-before['interfaces'][n]['tx_queue_drop'] for n in before['interfaces']}}
    v.atom(work/'MEASUREMENT.json',result);return result

def uptime_seconds(text):
    lines=[s.strip().split('|',1)[1] for s in text.splitlines() if s.strip().startswith('UPTIME|')]
    assert len(lines)==1,'Fresh uptime missing'
    value=lines[0]
    assert re.fullmatch(r'(?:\d+w)?(?:\d+d)?(?:\d+h)?(?:\d+m)?(?:\d+s)?',value) and value,'Unknown RouterOS uptime format'
    return sum(int(n)*{'w':604800,'d':86400,'h':3600,'m':60,'s':1}[unit] for n,unit in re.findall(r'(\d+)([wdhms])',value))

def read_uptime(router):
    tn=rr.Console('127.0.0.1',router['console_port'])
    try:
        rr.login(tn,[]);value=uptime_seconds(rr.run(tn,'uptime','READ1399'));assert rr.logout(tn)
        return value
    finally:tn.close()

def warm_reboot(router):
    assert router['node_id']==13 and router['name']=='MikroTik-U6' and router['console_verified_from_owned_qemu']
    old_uptime=read_uptime(router)
    assert old_uptime>90,'Too early for a verified reboot comparison'
    tn=rr.Console('127.0.0.1',router['console_port'])
    try:
        rr.login(tn,[]);tn.read();tn.write(b'/system reboot\r\n');buf=b'';deadline=time.monotonic()+8
        while time.monotonic()<deadline:
            buf+=tn.read();assert len(buf)<=131072
            if re.search(rb'(?i)reboot[^\r\n]*\[y/n\][^\r\n]*\s*\Z',rr.view(buf)):
                tn.write(b'y\r\n');break
            if rr.TAIL_LOGIN.search(rr.view(buf)) or rr.TAIL_PASSWORD.search(rr.view(buf)):raise RuntimeError('Authentication changed at reboot request')
            time.sleep(.05)
        else:raise RuntimeError('Exact reboot confirmation absent; no blind answer')
    finally:tn.close()
    time.sleep(8)
    latest=None
    for attempt in range(3):
        if attempt:time.sleep(5)
        latest=rr.snapshot(router,True)
        if not latest.get('error') and latest.get('logout_confirmed') and latest.get('license_level')=='p-unlimited':
            new_uptime=read_uptime(router);assert new_uptime<90 and new_uptime<old_uptime,'Actual guest reboot not verified'
            latest['reboot_uptime_proof']={'before_s':old_uptime,'after_s':new_uptime}
            return latest
    raise RuntimeError('User6 reboot did not reach verified required readiness')

def run(mapping,initial,expected,state,status):
    assert not state['started_ids'],'Capacity admission must precede IKE'
    assert len(initial)==14 and set(initial)==set(expected)
    for nid,row in initial.items():
        assert canonical({**row,'license_level':'p-unlimited'})==expected[nid],'Provisional queue comparison differs; no change allowed'
        assert row.get('license_level')=='p-unlimited' or nid=='13' and row.get('license_level')=='free','Other router readiness is outside User6 recovery scope'
    (ROOT/'capacity').mkdir(mode=0o700,exist_ok=False);install_helpers()
    state.update(stage='measuring_User6_duplex_capacity_before_IKE');v.atom(status,state)
    before=probe(mapping,'before');report={'passed':False,'before':before,'repair':None,'buffers_changed':False,'license_commands_written':0,'image_changes':0,'window_s':2.}
    v.atom(ROOT/'CAPACITY-ACCEPTANCE.json',report)
    if needs_reboot(before['checks'],initial['13']['license_level']):
        assert before['checks']['source_qualified'],'Unqualified sender/socket/capture; no speculative router restart'
        state.update(stage='one_User6_guest_OS_reboot_for_capacity');v.atom(status,state)
        router=next(r for r in mapping['routers'] if r['node_id']==13)
        after_snapshot=warm_reboot(router)
        assert canonical(after_snapshot)==expected['13'],'Queue/buffer configuration changed at reboot'
        fresh=pc.discover(str(v.LAB),v.IDS)
        assert fresh==mapping,'Guest reboot changed owned QEMU/TAP/interface mapping; stop'
        report['repair']={'action':'one_existing_User6_guest_OS_reboot','queue_configuration_preserved':True,'no_disk_replacement':True,'no_license_command':True}
        v.atom(ROOT/'CAPACITY-ACCEPTANCE.json',report)
        state.update(stage='measuring_User6_duplex_capacity_after_reboot');v.atom(status,state)
        report['after']=probe(mapping,'after');chosen=report['after']
    else:chosen=before
    final=pc.routers_snapshot(mapping,static=True);v.atom(ROOT/'CAPACITY-ROUTER-FINAL.json',final)
    verify_queues(final,expected)
    report['passed']=chosen['checks']['passed'];v.atom(ROOT/'CAPACITY-ACCEPTANCE.json',report)
    assert report['passed'],'Actual User6 duplex capacity/delivery below profile plus margin; no IKE and no weaker buffers/window'
    return final
