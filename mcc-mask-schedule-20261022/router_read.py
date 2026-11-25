"""Current-tail prompt, unique response nonce, confirmed logout; read-only queries."""
import os,re,secrets,time
from routeros_telnet_cmd import Console,clean
from router_commands import COMMANDS
TAIL_PROMPT=re.compile(rb'(?:^|\n)\s*\[[^\]\r\n]+\]\s*>\s*\Z')
TAIL_LOGIN=re.compile(rb'(?:^|\n)[^\n]*login:\s*\Z',re.I)
TAIL_PASSWORD=re.compile(rb'(?:^|\n)[^\n]*password:\s*\Z',re.I)
def view(raw):return clean(raw).replace(b'\x00',b'')
def current_prompt(raw):return bool(TAIL_PROMPT.search(view(raw)))
def login(tn,events,timeout=20):
    credential=os.environ.get('ROUTER_ADMIN_CREDENTIAL');assert credential,'Missing recorded credential'
    begin=time.monotonic();deadline=begin+timeout;last_rx=begin;buf=b'';user_sent=False;pass_sent=False;resynced=False
    tn.write(b'\r\n')
    while time.monotonic()<deadline:
        chunk=tn.read()
        if chunk:buf+=chunk;last_rx=time.monotonic()
        assert len(buf)<=131072,'Console readiness buffer cap'
        value=view(buf);low=value.lower()
        if b'new password' in low or b'software license' in low and b'[y/n]' in low:raise RuntimeError('Interactive password/license boundary')
        # The CURRENT tail takes precedence over every historical prompt in this buffer.
        if TAIL_LOGIN.search(value):
            if user_sent or pass_sent:raise RuntimeError('Login repeated in this authentication attempt; no retry')
            tn.write(b'admin+ct\r\n');user_sent=True;events.append('existing_username_once');buf=b''
        elif TAIL_PASSWORD.search(value):
            if pass_sent:raise RuntimeError('Password prompt repeated; no retry')
            tn.write(credential.encode()+b'\r\n');pass_sent=True;events.append('recorded_credential_once');buf=b''
        elif current_prompt(buf) and time.monotonic()-last_rx>=.3:
            events.extend(('authenticated_prompt','current_tail_quiet_confirmed'));return
        elif pass_sent and re.search(rb'(?im)^\s*(?:login failed|incorrect username or password)',low):
            raise RuntimeError('Current recorded credential rejected; no retry')
        elif b'press enter' in low or b'press any key' in low:
            tn.write(b'\r\n');events.append('console_ready_enter');buf=b''
        elif not user_sent and not pass_sent and not resynced and time.monotonic()-begin>=2:
            tn.write(b'\x03\r\n');events.append('console_input_resync_once');resynced=True;buf=b''
        time.sleep(.03)
    raise TimeoutError('Current console state not confirmed')
def run(tn,kind,token,timeout=20):
    assert kind in COMMANDS and re.fullmatch(r'READ[0-9]+',token)
    marker='DONE_FRESH_'+secrets.token_hex(12)
    tn.read();tn.write((COMMANDS[kind]+'; :put "'+marker+'"\r\n').encode())
    end=time.monotonic()+timeout;last_rx=time.monotonic();buf=b''
    while time.monotonic()<end:
        chunk=tn.read()
        if chunk:buf+=chunk;last_rx=time.monotonic()
        assert len(buf)<=262144,'Read-only command buffer cap'
        value=view(buf);text=value.decode(errors='replace')
        if TAIL_LOGIN.search(value) or TAIL_PASSWORD.search(value):raise RuntimeError('Read command received authentication prompt; result rejected')
        if re.search(r'(?im)^\s*(?:failure:|syntax error|expected end|no such item)',text):raise RuntimeError('Read-only query rejected')
        fresh=bool(re.search(r'(?m)^\s*'+marker+r'\s*$',text))
        if fresh and current_prompt(buf) and time.monotonic()-last_rx>=.3:
            return '\n'.join(line for line in text.splitlines() if marker not in line and not re.match(r'^\s*\[[^\]]+\]\s*>',line))
        time.sleep(.03)
    raise TimeoutError('Fresh read marker and current prompt not both confirmed')
def logout(tn,timeout=4):
    tn.write(b'/quit\r\n');buf=b'';end=time.monotonic()+timeout
    while time.monotonic()<end:
        buf+=tn.read();assert len(buf)<=131072
        if TAIL_LOGIN.search(view(buf)):return True
        time.sleep(.03)
    return False
def _snapshot_once(router,static=False):
    result={'node_id':router['node_id'],'name':router['name'],'events':[],'commands':{},'interfaces':{},'read_only':True,'fresh_markers_verified':0}
    if not router.get('console_verified_from_owned_qemu'):result['error']='Unverified local listener';return result
    tn=None;authenticated=False
    try:
        tn=Console('127.0.0.1',router['console_port']);login(tn,result['events']);authenticated=True
        kinds=('interface','ethernet','raw_stats','level','queues','types','simple','tree','tree_config','simple_config') if static else ('interface','tree')
        for i,kind in enumerate(kinds):
            result['commands'][kind]=run(tn,kind,'READ'+str(router['node_id']*100+i));result['fresh_markers_verified']+=1
        for line in result['commands'].get('interface','').splitlines():
            v=line.strip().split('|')
            if len(v)==10 and v[0]=='IF':result['interfaces'][v[1]]={'mac':v[2].lower(),**{k:int(x) if x.isdigit() else None for k,x in zip(('rx_packets','tx_packets','rx_drop','tx_drop','tx_queue_drop','rx_error','tx_error'),v[3:])}}
        for line in result['commands'].get('level','').splitlines():
            if line.startswith('LEVEL|'):result['license_level']=line.split('|',1)[1].strip()
    except Exception as error:result['error']={'type':type(error).__name__,'reason':str(error)[:180]}
    finally:
        if tn:
            if authenticated and 'error' not in result:
                try:result['logout_confirmed']=logout(tn)
                except OSError:result['logout_confirmed']=False
            elif authenticated:result['logout_confirmed']=False  # Never send /quit into an unconfirmed Login/Password state.
            tn.close()
    return result
def snapshot(router,static=False):
    history=[]
    for attempt in range(2):
        result=_snapshot_once(router,static);events=result.get('events',[]);error=result.get('error')
        history.append({'attempt':attempt+1,'events':events,'error':error,'logout_confirmed':result.get('logout_confirmed')})
        retry=isinstance(error,dict) and error.get('type')=='TimeoutError' and ('recorded_credential_once' not in events or 'authenticated_prompt' in events)
        if not retry or attempt==1:break
        time.sleep(.25)
    result['read_attempts']=history
    return result
