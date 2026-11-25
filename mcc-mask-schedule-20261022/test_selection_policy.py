import copy,json,os,sys,tempfile,unittest
from pathlib import Path
from types import SimpleNamespace
ROOT=Path(__file__).resolve().parent;sys.path.insert(0,str(ROOT))
from selection_policy import EXPECTED,validate,record
class SelectionPolicy(unittest.TestCase):
    def test_exact_policy(self):self.assertTrue(validate(dict(EXPECTED)))
    def test_each_drift_blocked(self):
        for k,v in {'mode':'first','window_ms':100,'deadline_ms':10000,'min_copies':1,'quiet_ms':0}.items():
            with self.subTest(field=k),self.assertRaises(AssertionError):validate({**EXPECTED,k:v})
    def test_receipt_is_exclusive_and_no_node_state_change(self):
        (ROOT/'local').mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=ROOT/'local') as tmp:
            node=SimpleNamespace(name='User6',_mcc_policy=copy.deepcopy(EXPECTED));before=copy.deepcopy(vars(node));p=Path(tmp)/'policy.json'
            record(node,p);value=json.loads(p.read_text());self.assertEqual(value,{'pid':os.getpid(),'name':'User6','policy':EXPECTED})
            self.assertEqual(vars(node),before)
            with self.assertRaises(FileExistsError):record(node,p)
    def test_wrong_policy_never_receipted(self):
        (ROOT/'local').mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=ROOT/'local') as tmp:
            p=Path(tmp)/'policy.json'
            with self.assertRaises(AssertionError):record(SimpleNamespace(name='User6',_mcc_policy={}),p)
            self.assertFalse(p.exists())
if __name__=='__main__':unittest.main()
