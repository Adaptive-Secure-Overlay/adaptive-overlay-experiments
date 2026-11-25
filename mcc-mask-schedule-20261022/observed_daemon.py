"""Identical minimal entry point for both variants; no protocol instrumentation."""
import os,random,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parent
variant=os.environ['AB_VARIANT']; assert variant in ('old','new')
code=ROOT/'code'/('old' if variant=='old' else '')
sys.path.insert(0,str(code))
random.seed(int(os.environ['AB_SEED']))
import node_daemon
from selection_policy import record
OriginalNodeDaemon=node_daemon.NodeDaemon
class PolicyObservedNode(OriginalNodeDaemon):
    def __init__(self,*args,**kwargs):
        super().__init__(*args,**kwargs)
        record(self,Path(os.environ['SELECTION_POLICY_RECEIPT']))
from mask_node import wrap
node_daemon.NodeDaemon=wrap(PolicyObservedNode)
if __name__=='__main__':
    try:node_daemon.main()
    except Exception as exc:
        import json,traceback
        value={'type':type(exc).__name__,'frames':[{'file':Path(f.filename).name,'line':f.lineno,'function':f.name} for f in traceback.extract_tb(exc.__traceback__)]}
        (ROOT/(os.environ['MASK_JOB']+'-ENTRY-ERROR.json')).write_text(json.dumps(value))
        raise SystemExit(1)
