# _test_
import struct as st2
import unittest as uni2
import pp as p

def pkt(ver5=72852, sts=1, clks=1, vlts=0):
    data = bytearray(p.ver2[ver5][1])
    st2.pack_into('<5I', data, 0, ver5, 1, sts, clks, vlts)
    return data

class PktTes(uni2.TestCase):

    def test_sig_fre_del_pre(self):
        data = pkt()
        st2.pack_into('<3i', data, 40, -13000, -90000, 1000000)
        res4 = p.prs(data, 'request')
        clk = res4['states'][0]['clocks'][0]
        self.assertEqual(clk['byte_offset'], 28)
        self.assertEqual(clk['frequency_delta']['value'], -13000)
        self.assertEqual(clk['frequency_delta']['units'], 'kHz')
        self.assertEqual(res4['context'], 'request')
        self.assertEqual(res4['states'][0]['base_voltage_entries'], [])

    def test_vol_del_not_rep_bas_vol(self):
        data = pkt(vlts=1)
        off2 = 20 + 8 + 8 * 44
        st2.pack_into('<3I3i', data, off2, 0, 1, 1012500, -1000, -10000, 50000)
        vlt = p.prs(data)['states'][0]['base_voltage_entries'][0]
        self.assertEqual(vlt['reported_base_voltage_uv'], 1012500)
        self.assertEqual(vlt['voltage_delta']['value'], -1000)
        self.assertEqual(vlt['voltage_delta']['units'], 'uV')

    def test_ver_sha_sta_str_but_not_ext(self):
        for ver5 in p.ver2:
            res4 = p.prs(pkt(ver5, sts=2))
            self.assertEqual(res4['states'][1]['byte_offset'], 476)
            self.assertEqual(res4['declared_structure_bytes'], p.ver2[ver5][1])

    def test_v2_and_v3_rel_vol_tai(self):
        for ver5 in [138488, 204024]:
            data = pkt(ver5)
            st2.pack_into('<I', data, 7316, 1)
            st2.pack_into('<3I3i', data, 7320, 0, 1, 1025000, 0, 0, 50000)
            res4 = p.prs(data)
            self.assertEqual(res4['relative_voltage_entries'][0]['byte_offset'], 7320)
            self.assertEqual(res4['relative_voltage_entries'][0]['voltage_delta']['maximum'], 50000)

    def test_clo_uni_lay(self):
        data = pkt()
        st2.pack_into('<3I', data, 28, 0, 1, 1)
        st2.pack_into('<5I', data, 52, 135000, 1569500, 0, 850000, 1212500)
        det = p.prs(data)['states'][0]['clocks'][0]['reported_clock_detail']
        self.assertEqual(det['type'], 'range')
        self.assertEqual(det['minimum_voltage_uv'], 850000)
        self.assertEqual(det['maximum_frequency_khz'], 1569500)

    def test_unk_clo_typ_not_gue(self):
        data = pkt()
        st2.pack_into('<I', data, 32, 99)
        self.assertEqual(p.prs(data)['states'][0]['clocks'][0]['reported_clock_detail']['type'], 'unrecognized')

    def test_tru_and_ver_rej(self):
        for data in [bytes(19), pkt()[:-1]]:
            with self.assertRaises(p.PpErr):
                p.prs(data)
        for ver5 in [65536, 262144, 72952, 138388]:
            data = pkt()
            st2.pack_into('<I', data, 0, ver5)
            with self.assertRaises(p.PpErr):
                p.prs(data)

    def test_eac_arr_cou_is_bou(self):
        for off2, val in [(8, 17), (12, 9), (16, 5), (8, 4294967295)]:
            data = pkt()
            st2.pack_into('<I', data, off2, val)
            with self.assertRaises(p.PpErr):
                p.prs(data)
        data = pkt(138488)
        st2.pack_into('<I', data, 7316, 5)
        with self.assertRaises(p.PpErr):
            p.prs(data)

    def test_unp_ent_and_tra_byt(self):
        data = pkt(sts=0, clks=0) + b'EXTRA'
        res4 = p.prs(data)
        self.assertEqual(res4['states'], [])
        self.assertEqual(res4['trailing_bytes'], 5)

    def test_res_bit_vis_not_nor(self):
        data = pkt()
        st2.pack_into('<I', data, 4, 2147483649)
        self.assertEqual(p.prs(data)['reserved_flag_bits'], 2147483648)
        with self.assertRaises(p.PpErr):
            p.prs(data, 'safe-to-apply')
if __name__ == '__main__':
    uni2.main()
