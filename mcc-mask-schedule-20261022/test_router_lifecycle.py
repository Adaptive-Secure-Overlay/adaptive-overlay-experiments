import copy,sys,unittest
from pathlib import Path
from unittest.mock import Mock
sys.path.insert(0,str(Path(__file__).resolve().parent))
import router_lifecycle as life
def rows():return {str(i):{'name':str(i),'license_level':'p-unlimited','logout_confirmed':True} for i in range(14)}
class Checks(unittest.TestCase):
    def test_ready_nodes_never_restarted(self):self.assertEqual(life.choose_restarts(rows()),[])
    def test_only_free_selected_no_mutation(self):
        v=rows();v['3']['license_level']='free';before=copy.deepcopy(v)
        self.assertEqual(life.choose_restarts(v),[3]);self.assertEqual(v,before)
    def test_unknown_level_blocks(self):
        v=rows();v['3']['license_level']='unknown'
        with self.assertRaises(AssertionError):life.choose_restarts(v)
    def test_reader_failure_blocks(self):
        v=rows();v['3']['error']={'type':'TimeoutError'}
        with self.assertRaises(AssertionError):life.choose_restarts(v)
    def test_mass_failure_blocks(self):
        v=rows()
        for i in range(3):v[str(i)]['license_level']='free'
        with self.assertRaises(AssertionError):life.choose_restarts(v)
    def test_incomplete_inventory_blocks(self):
        v=rows();v.pop('1')
        with self.assertRaises(AssertionError):life.choose_restarts(v)
    def test_confirmation_is_specific(self):
        self.assertTrue(life.shutdown_confirmed(b'Shutdown, yes? [y/N]: '))
        self.assertFalse(life.shutdown_confirmed(b'Reboot, yes? [y/N]: '))
        self.assertFalse(life.shutdown_confirmed(b'Software license [y/N]: '))
    def test_known_confirmation_answered_once(self):
        tn=Mock();tn.read.side_effect=[b'',b'Shutdown, yes? [y/N]: ']
        life.request_shutdown(tn)
        self.assertEqual(tn.write.call_args_list[0].args,(b'/system shutdown\r\n',))
        self.assertEqual(tn.write.call_args_list[1].args,(b'y\r\n',));self.assertEqual(tn.write.call_count,2)
    def test_auth_prompt_not_answered(self):
        tn=Mock();tn.read.side_effect=[b'',b'Password: ']
        with self.assertRaises(RuntimeError):life.request_shutdown(tn)
        self.assertEqual(tn.write.call_count,1)
if __name__=='__main__':unittest.main(verbosity=2)
