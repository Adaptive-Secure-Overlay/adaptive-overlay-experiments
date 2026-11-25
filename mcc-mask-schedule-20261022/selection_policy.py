"""Read-only startup policy observation, before timing; no packet-handler changes."""
import json,os
EXPECTED={'mode':'adaptive','window_ms':0,'deadline_ms':1000,'min_copies':3,'quiet_ms':150}
def validate(value):
    assert value==EXPECTED,'Effective adaptive selection policy differs from sealed test'
    return True
def record(node,path):
    policy=dict(node._mcc_policy);validate(policy)
    with path.open('x',encoding='utf-8') as f:json.dump({'pid':os.getpid(),'name':node.name,'policy':policy},f)
