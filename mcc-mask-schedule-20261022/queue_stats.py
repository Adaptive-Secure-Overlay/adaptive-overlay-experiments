"""Pure bounded parsing for saved RouterOS queue stats; unknown is never zero."""
import re
def tree_counters(text):
    records=[];current=[]
    for line in text.splitlines():
        if re.match(r'^\s*\d+\s+',line):
            if current:records.append(' '.join(current))
            current=[line]
        elif current and '=' in line and not any(x in line for x in ('/queue',':put','DONE_READ','<')):current.append(line)
    if current:records.append(' '.join(current))
    result={}
    for row in records:
        fields=dict((k,v.strip('"')) for k,v in re.findall(r'([A-Za-z][A-Za-z0-9-]*)=("[^"]*"|[^\s;]+)',row))
        assert fields.get('name') and fields.get('dropped','').isdigit(),'Unknown queue-drop field'
        assert fields['name'] not in result
        result[fields['name']]=int(fields['dropped'])
    return result
def loss_deltas(before,after):
    result={}
    assert set(before)==set(after)
    for nid,start in before.items():
        end=after[nid];assert not start.get('error') and not end.get('error')
        rows={}
        assert set(start['interfaces'])==set(end['interfaces'])
        for name,b in start['interfaces'].items():
            a=end['interfaces'][name];assert a['mac']==b['mac']
            x,y=b.get('tx_queue_drop'),a.get('tx_queue_drop');assert isinstance(x,int) and isinstance(y,int) and y>=x
            rows[name]=y-x
        old=tree_counters(start['commands']['tree']);new=tree_counters(end['commands']['tree']);assert set(old)==set(new)
        assert all(new[n]>=v for n,v in old.items())
        result[nid]={'name':start['name'],'interface_tx_queue_drop':rows,'tree_dropped':{n:new[n]-v for n,v in old.items()}}
    return {'passed':all(v==0 for row in result.values() for kind in ('interface_tx_queue_drop','tree_dropped') for v in row[kind].values()),'routers':result}
