"""Owned, temporary ESP barrier for controlled no-application-traffic pilot only.

Not a traffic queue: any attempted early ESP is counted and FAILS acceptance.
No sysctl, buffer, existing nft table or strongSwan setting is changed.
"""
import json
import subprocess
from pathlib import Path

TABLE = 'candidate_mask_pilot'

def rules_script():
    # RFC3948: IKE on4500 has a four-zero Non-ESP Marker; ESP begins with
    # nonzero SPI. Do not drop IKE, raw local reinjection or short keepalives.
    return (f'add table inet {TABLE}\n'
            f'add chain inet {TABLE} output {{ type filter hook output priority -5; policy accept; }}\n'
            f'add rule inet {TABLE} output ip protocol esp counter drop comment "native_esp"\n'
            f'add rule inet {TABLE} output udp dport 4500 udp length >= 16 @th,64,32 != 0 counter drop comment "encapsulated_esp"\n')

def udp_is_esp(payload):
    return len(payload)>=8 and payload[:4]!=bytes(4)


def run(args, **kw):
    return subprocess.run(args, capture_output=True, text=True, timeout=5, **kw)


def install(root, job):
    proof=Path(root)/'MASK-GATE-OWNER.json'
    r=run(['nft','list','table','inet',TABLE])
    assert r.returncode!=0, 'Existing ESP barrier; reconcile its owner'
    # All ESP, independent of actual receiver. Fresh actors run with no prior SA.
    script=rules_script()
    run(['nft','-c','-f','-'],input=script,check=True)
    run(['nft','-f','-'],input=script,check=True)
    proof.write_text(json.dumps({'job':job,'owned_table':TABLE,'installed':True}))


def release(root, job):
    proof=Path(root)/'MASK-GATE-OWNER.json'
    owner=json.loads(proof.read_text())
    assert owner['job']==job and owner['owned_table']==TABLE
    if owner.get('released'):
        assert run(['nft','list','table','inet',TABLE]).returncode!=0
        return owner
    value=json.loads(run(['nft','-j','list','table','inet',TABLE],check=True).stdout)
    counters=[e['counter'] for item in value['nftables'] for e in item.get('rule',{}).get('expr',[]) if 'counter' in e]
    assert len(counters)==2 and all(set(c)=={'packets','bytes'} for c in counters), 'Unknown barrier counter'
    rules={item['rule']['comment']:next(e['counter'] for e in item['rule']['expr'] if 'counter' in e)
           for item in value['nftables'] if 'rule' in item}
    assert set(rules)=={'native_esp','encapsulated_esp'}
    # The controller must fail acceptance for ANY ESP dropped by this pilot gate.
    run(['nft','delete','table','inet',TABLE],check=True)
    assert run(['nft','list','table','inet',TABLE]).returncode!=0
    owner.update(released=True,rules=rules,packets=sum(c['packets'] for c in counters),bytes=sum(c['bytes'] for c in counters)); proof.write_text(json.dumps(owner))
    return owner
