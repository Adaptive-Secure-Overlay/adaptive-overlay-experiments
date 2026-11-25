"""Read-only RouterOS console queries using the existing Console transport.

Only current clone QEMU serial ports discovered from /proc are accepted. No
configuration, license acceptance/renewal, counters reset, sniffers or retries.
"""
import re,time
from routeros_telnet_cmd import Console,clean,PROMPT_RE
READS={
 'counters':':foreach i in=[/interface find] do={:local n [/interface get $i name]; :if ([:pick $n 0 5]="ether") do={:local d "unsupported"; :do {:set d [/interface get $i tx-queue-drop]} on-error={}; :put ("IF|".$n."|".[/interface get $i mac-address]."|".[/interface get $i rx-packet]."|".[/interface get $i tx-packet]."|".$d)}}',
 'license':':put ("LEVEL|".[/system license get level]); :put ("VERSION|".[/system resource get version])',
 'interface_queues':'/queue interface print detail without-paging',
 'queue_types':'/queue type print detail without-paging',
 'simple_stats':'/queue simple print stats without-paging',
 'tree_stats':'/queue tree print stats without-paging'}
def login_once(tn,timeout=8):
    deadline=time.monotonic()+timeout; buf=b''; user_sent=False; password_sent=False
    tn.write(b'\r\n')
    while time.monotonic()<deadline:
        buf+=tn.read(); value=clean(buf).lower()
        if b'new password' in value or b'software license' in value and b'[y/n]' in value: raise RuntimeError('Interactive license/password change boundary')
        if b'login failure' in value or b'login failed' in value or b'incorrect' in value: raise RuntimeError('Existing console credential was not accepted; no retry')
        if PROMPT_RE.search(clean(buf)): return
        if b'login:' in value and not user_sent:
            tn.write(b'admin\r\n'); user_sent=True; buf=b''
        elif b'password:' in value:
            if password_sent: raise RuntimeError('Console authentication retry prohibited')
            # Reuse ONLY the first, empty credential in the established lab helper.
            tn.write(b'\r\n'); password_sent=True; buf=b''
        time.sleep(.05)
    raise TimeoutError('Console readiness deadline')
def execute(tn,kind,token,timeout=8):
    assert kind in READS and re.fullmatch(r'ROUTERREAD[0-9]+',token)
    marker='DONE_'+token; command=READS[kind]+'; :put "'+marker+'"'
    tn.write(command.encode()+b'\r\n'); deadline=time.monotonic()+timeout; buf=b''
    while time.monotonic()<deadline:
        buf+=tn.read(); assert len(buf)<131072,'Bounded router read exceeded'
        text=clean(buf).decode(errors='replace')
        # The command echo contains one marker; its standalone result is another.
        if re.search(r'(?m)^\s*'+marker+r'\s*$',text):
            if PROMPT_RE.search(clean(buf[clean(buf).rfind(marker.encode())+len(marker):])) or text.rstrip().endswith(marker):
                lines=[s for s in text.splitlines() if marker not in s and not PROMPT_RE.search(s.encode())]
                return '\n'.join(lines).strip()
        time.sleep(.05)
    raise TimeoutError('Read-only router command deadline')
def snapshot(router,static=False):
    if not router['console_verified_from_owned_qemu']:
        return {'node_id':router['node_id'],'name':router['name'],'read_only':True,'commands':{},'interfaces':{},'counters_available':False,'license_level':None,'error':{'type':'UnverifiedConsole','reason':'No unique owned local listener; do not guess or connect'}}
    assert router['console_verified_from_owned_qemu'] and router['host']=='127.0.0.1'
    tn=None; authenticated=False; result={'node_id':router['node_id'],'name':router['name'],'read_only':True,'commands':{}}
    try:
        tn=Console('127.0.0.1',router['console_port']); login_once(tn); authenticated=True
        for number,kind in enumerate(('counters','license','interface_queues','queue_types','simple_stats','tree_stats') if static else ('counters','simple_stats','tree_stats')):
            try: result['commands'][kind]=execute(tn,kind,'ROUTERREAD'+str(router['node_id']*100+number))
            except Exception as error:
                result['command_error']={'kind':kind,'type':type(error).__name__,'reason':str(error)[:180]}; break
        rows={}
        for line in result['commands'].get('counters','').splitlines():
            m=re.fullmatch(r'IF\|(ether\d+)\|([0-9A-Fa-f:]+)\|(\d+)\|(\d+)\|(\d+|unsupported)',line.strip())
            if m: rows[m[1]]={'mac':m[2].lower(),'rx_packets':int(m[3]),'tx_packets':int(m[4]),'tx_queue_drop':int(m[5]) if m[5].isdigit() else None}
        result['interfaces']=rows; result['counters_available']=bool(rows)
        license_text=result['commands'].get('license',''); m=re.search(r'(?m)^LEVEL\|([^\r\n]+)',license_text); result['license_level']=m[1].strip() if m else None
    except Exception as error: result['error']={'type':type(error).__name__,'reason':str(error)[:180]}
    finally:
        if tn:
            if authenticated:
                try: tn.write(b'/quit\r\n')
                except OSError: pass
            tn.close()
    return result
