# _test_
import concurrent.futures as fut, json, tempfile as tem, unittest as uni2
from pathlib import Path
from unittest.mock import patch as pat2
import jio as io

class ShaJsonTes(uni2.TestCase):

    def test_jso_rou(self):
        with tem.TemporaryDirectory() as temp:
            p = Path(temp) / 'state.json'
            io.ato_json(p, {'n': 1})
            self.assertEqual(io.rd_json(p), {'n': 1})

    def test_con_rea_doe_not_blo_rep(self):
        with tem.TemporaryDirectory() as temp:
            p = Path(temp) / 'heartbeat.json'
            io.ato_json(p, {'n': 0})

            def wri():
                for i in range(1, 301):
                    io.ato_json(p, {'n': i, 'payload': 'x' * 4096})

            def rea():
                for _ in range(1000):
                    self.assertIsInstance(io.rd_json(p)['n'], int)
            with fut.ThreadPoolExecutor(max_workers=2) as pool:
                tas = [pool.submit(wri), pool.submit(rea)]
                for task in tas:
                    task.result()
            self.assertEqual(io.rd_json(p)['n'], 300)

    def test_tra_sha_fai_ret_bou(self):
        with tem.TemporaryDirectory() as temp:
            p = Path(temp) / 'state.json'
            with pat2.object(io.os, 'replace', side_effect=[PermissionError(), PermissionError(), None]) as rep, pat2.object(io.time, 'sleep'):
                io.ato_json(p, {'n': 1})
                self.assertEqual(rep.call_count, 3)

    def test_per_fai_sti_sto_ins_of_hid_it(self):
        with tem.TemporaryDirectory() as temp:
            with pat2.object(io.os, 'replace', side_effect=PermissionError()) as rep, pat2.object(io.time, 'sleep'):
                with self.assertRaises(PermissionError):
                    io.ato_json(Path(temp) / 'state.json', {})
                self.assertEqual(rep.call_count, 6)
if __name__ == '__main__':
    uni2.main()
