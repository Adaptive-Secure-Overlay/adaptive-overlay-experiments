"""Strict clone-only, MAC-bound, reversible use of existing RouterOS HTB."""
import json,re,time
from pathlib import Path
from routeros_telnet_cmd import Console,clean,PROMPT_RE
import router_read as rr
ROOT=Path(__file__).resolve().parent; TYPE='candidate-frag-pfifo-20261015'; PREFIX='candidate-frag-20261015-'

def parse_rows(text):
    rows=[];current={};keys=('N','P','Q','R','B','D')
    for line in text.splitlines():
        line=line.strip()
        if line=='ENDROW':
            assert set(current)==set(keys),'Incomplete bounded queue readback'
            rows.append([current[k] for k in keys]);current={}
        elif len(line)>2 and line[0] in keys and line[1]=='|':
            assert line[0] not in current,'Duplicate queue readback field'
            current[line[0]]=line[2:]
    assert not current,'Truncated bounded queue readback';return rows

def validate_row(row,expected):
    name,parent,kind,rate,bucket,disabled=row
    assert name in expected and expected[name]==parent,('Wrong queue parent',row)
    assert kind==TYPE and int(rate)==0,('Wrong queue/rate',row)
    assert int(bucket)==20 and disabled=='no',('Wrong raw bucket/disabled state',row)

def add_command(item):
    assert re.fullmatch(r'ether\d+',item['interface']) and item['queue_name']==PREFIX+item['interface']
    return '/queue tree add name='+item['queue_name']+' parent='+item['interface']+' queue='+TYPE+' packet-mark=no-mark max-limit=0 bucket-size=0.02 disabled=no'

class Queues:
    def __init__(self,mapping):
        self.sessions={}; self.targets={}; self.serial=0; self.created=False
        planned=set(json.loads((ROOT/'SEALED-CONTRACT.json').read_text())['queue_candidate']['routers'])
        try:
            for router in mapping['routers']:
                nid=router['node_id']
                if nid not in planned:continue
                assert router['console_verified_from_owned_qemu']
                tn=Console('127.0.0.1',router['console_port']); events=[]; rr.login(tn,events); self.sessions[nid]=tn
                text=self.command(nid,rr.COMMANDS['interface']); interfaces={}
                for line in text.splitlines():
                    v=line.strip().split('|')
                    if len(v)==10 and v[0]=='IF':interfaces[v[2].lower()]=v[1]
                taps=[p for p in mapping['taps'] if p['node_id']==nid]; names=[]
                for tap in taps:
                    name=interfaces[tap['guest_mac']]; assert re.fullmatch(r'ether\d+',name); names.append({'interface':name,'mac':tap['guest_mac'],'tap':tap['tap'],'queue_name':PREFIX+name})
                assert len(names)==len(taps) and len({n['interface'] for n in names})==len(names)
                state=self.rows(nid); assert not state,'Existing queue tree; refuse to replace or shadow it'
                gate=self.command(nid,':put ("OWNEDTYPE|".[:len [/queue type find where name="'+TYPE+'"]]); :put ("LEVEL|".[/system license get level])')
                assert 'OWNEDTYPE|0' in gate and 'LEVEL|free' in gate
                self.targets[nid]={'name':router['name'],'interfaces':names,'login_events':events,'tree_before':state,'license_before':'free'}
            assert set(self.targets)==planned
            (ROOT/'QUEUE-BACKUP.json').write_text(json.dumps({'targets':self.targets,'rollback':'Delete only exact owned queue tree objects then exact owned type. No preexisting tree objects were present.'},indent=2))
        except Exception:
            self.close(); raise

    def command(self,nid,command):
        self.serial+=1; marker='DONE_QUEUE_'+str(self.serial); tn=self.sessions[nid]; tn.read(); tn.write((command+'; :put "'+marker+'"\r\n').encode()); end=time.monotonic()+10; buf=b''
        while time.monotonic()<end:
            buf+=tn.read(); assert len(buf)<131072
            text=clean(buf).decode(errors='replace')
            if re.search(r'(?m)^\s*'+marker+r'\s*$',text):
                assert not re.search(r'(?im)^\s*(?:failure:|syntax error|expected end|input does not match|no such item)',text),'RouterOS rejected queue command'
                return '\n'.join(v for v in text.splitlines() if marker not in v and not PROMPT_RE.search(v.encode()))
            time.sleep(.03)
        raise TimeoutError('Bounded owned queue command')

    def rows(self,nid):
        text=self.command(nid,':foreach q in=[/queue tree find] do={:put ("N|".[/queue tree get $q name]); :local pp [/queue tree get $q parent]; :local pn $pp; :do {:set pn [/interface get $pp name]} on-error={}; :put ("P|".$pn); :put ("PR|".$pp); :local qq [/queue tree get $q queue]; :local qn $qq; :do {:set qn [/queue type get $qq name]} on-error={}; :put ("Q|".$qn); :put ("QR|".$qq); :put ("R|".[/queue tree get $q max-limit]); :put ("B|".[/queue tree get $q bucket-size]); :if ([/queue tree get $q disabled]=true) do={:put "D|yes"} else={:put "D|no"}; :put "ENDROW"}')
        with (ROOT/'queue-readbacks.log').open('a') as stream:stream.write(json.dumps({'node':nid,'serial':self.serial,'text':text})+'\n')
        return parse_rows(text)

    def preflight_first(self):
        nid=next(iter(self.targets));item=self.targets[nid]['interfaces'][0];assert not self.rows(nid)
        self.command(nid,'/queue type add name='+TYPE+' kind=pfifo pfifo-limit=512')
        self.command(nid,add_command(item));rows=self.rows(nid);assert len(rows)==1
        validate_row(rows[0],{item['queue_name']:item['interface']})
        pretty=self.command(nid,'/queue tree print detail without-paging');(ROOT/'QUEUE-BUCKET-DISPLAY.log').write_text(pretty)
        assert re.search(r'\bbucket-size=0\.02(?:\s|$)',pretty),'Raw bucket 20 must correspond to standard display 0.02'
        self.command(nid,'/queue tree remove [find where name="'+item['queue_name']+'"]')
        self.command(nid,'/queue type remove [find where name="'+TYPE+'"]');assert not self.rows(nid)
        return {'passed':True,'node':nid,'readback':rows,'temporary_queue_and_type_removed':True}

    def set_candidate(self,enabled):
        receipt={}
        for nid,target in self.targets.items():
            rows=self.rows(nid)
            assert all(row[0] in {x['queue_name'] for x in target['interfaces']} for row in rows),'Unrelated queue tree found; do not change it'
            if enabled:
                if not rows:
                    # The type is scoped by unique name; create once and reuse after A2 rollback.
                    gate=self.command(nid,':put ("OWNEDTYPE|".[:len [/queue type find where name="'+TYPE+'"]])')
                    if 'OWNEDTYPE|0' in gate:self.command(nid,'/queue type add name='+TYPE+' kind=pfifo pfifo-limit=512')
                    for item in target['interfaces']:
                        self.command(nid,add_command(item))
            else:
                for row in rows:
                    assert row[2]==TYPE
                    self.command(nid,'/queue tree remove [find where name="'+row[0]+'"]')
            current=self.rows(nid)
            if enabled:
                assert len(current)==len(target['interfaces'])
                expected={x['queue_name']:x['interface'] for x in target['interfaces']}
                for row in current:validate_row(row,expected)
                pretty=self.command(nid,'/queue tree print detail without-paging');(ROOT/('queue-config-'+str(nid)+'-'+str(self.serial)+'.log')).write_text(pretty)
                assert re.search(r'\bbucket-size=0\.02(?:\s|$)',pretty),'Standard configuration bucket readback mismatch'
            else:assert not current
            receipt[str(nid)]={'name':target['name'],'queues':current}
        self.created=enabled; return receipt

    def counters(self):
        # Only three forwarding nodes on the controlled User1→User3 path.
        out={}
        for nid in (6,27,8):
            out[str(nid)]={'name':self.targets[nid]['name'],'interface':self.command(nid,rr.COMMANDS['interface']),
                           'tree_stats':self.command(nid,'/queue tree print stats without-paging')}
        return out

    @classmethod
    def attach(cls,mapping,targets,require_complete=False):
        self=object.__new__(cls);self.sessions={};self.targets={int(k):v for k,v in targets.items()};self.serial=0;self.created=True
        try:
            for router in mapping['routers']:
                nid=router['node_id']
                if nid not in self.targets:continue
                assert router['console_verified_from_owned_qemu']
                tn=Console('127.0.0.1',router['console_port']);events=[];rr.login(tn,events);self.sessions[nid]=tn
                raw=self.command(nid,rr.COMMANDS['interface']);macs={}
                for line in raw.splitlines():
                    v=line.strip().split('|')
                    if len(v)==10 and v[0]=='IF':macs[v[1]]=v[2].lower()
                target=self.targets[nid];assert all(macs.get(i['interface'])==i['mac'] for i in target['interfaces'])
                rows=self.rows(nid);expected={i['queue_name']:i['interface'] for i in target['interfaces']}
                for row in rows:validate_row(row,expected)
                if require_complete:assert len(rows)==len(expected)
            assert set(self.sessions)==set(self.targets)
            return self
        except Exception:self.close();raise

    def verify_retained(self):
        result={}
        for nid,target in self.targets.items():
            rows=self.rows(nid);expected={x['queue_name']:x['interface'] for x in target['interfaces']}
            assert len(rows)==len(expected)
            for row in rows:validate_row(row,expected)
            proof=self.command(nid,':put ("KIND|".[/queue type get [find where name="'+TYPE+'"] kind]); :put ("LIMIT|".[/queue type get [find where name="'+TYPE+'"] pfifo-limit]); :put ("LEVEL|".[/system license get level])')
            assert 'KIND|pfifo' in proof and 'LIMIT|512' in proof and 'LEVEL|free' in proof
            result[str(nid)]={'name':target['name'],'queues':rows,'pfifo_limit':512,'max_limit':0,'licence':'free'}
        assert sum(len(x['queues']) for x in result.values())==20
        return {'passed':True,'retained':True,'routers':8,'queues':20,'targets':result}

    def rollback(self):
        receipt=self.set_candidate(False)
        for nid in self.targets:
            gate=self.command(nid,':put ("OWNEDTYPE|".[:len [/queue type find where name="'+TYPE+'"]])')
            if 'OWNEDTYPE|1' in gate:self.command(nid,'/queue type remove [find where name="'+TYPE+'"]')
            elif 'OWNEDTYPE|0' not in gate:raise RuntimeError('Unexpected owned type count; stop rollback')
        return receipt

    def close(self):
        for tn in self.sessions.values():
            try:tn.write(b'/quit\r\n')
            except OSError:pass
            tn.close()
        self.sessions={}
