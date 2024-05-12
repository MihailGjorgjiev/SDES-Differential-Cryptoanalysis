from sdes import SDES, change_char_in_string
import pandas as pd
import os


class DiffCrypt:
    def __init__(self):
        pair_columns = ["X", "Y"] + [format(x, "04b") for x in range(16)]
        dist_columns = ["DX"] + [format(x, "02b") for x in range(4)]
        self.sdes = SDES()
        self.diff_pair_s0 = pd.DataFrame(columns=pair_columns)
        self.diff_pair_s1 = pd.DataFrame(columns=pair_columns)
        self.diff_dist_s0 = pd.DataFrame(columns=dist_columns)
        self.diff_dist_s1 = pd.DataFrame(columns=dist_columns)
        self.dex1 = '0000'
        self.dex2 = '0000'
        self.dey1 = '00'
        self.dey2 = '00'
        self.prob1 = 0
        self.prob2 = 0

        self.r1xchar = '0000'
        self.r1ychar = '00000000'

    def save_table(self, df: pd.DataFrame, filename):
        output_dir = "./tables"
        if not os.path.exists(output_dir):
            os.mkdir(output_dir)
        path_name = os.path.join(output_dir, f"{filename}.csv")
        df.to_csv(path_name)

    def generate_diff_pair_tables(self):
        for i in range(16):
            x1 = format(i, "04b")
            y1 = self.sdes.substitution(x1, self.sdes.SBOX[0])
            deltas_y = []
            for delta_x in [format(num, "04b") for num in range(16)]:
                x2 = self.sdes.xor(x1, delta_x)
                y2 = self.sdes.substitution(x2, self.sdes.SBOX[0])
                delta_y = self.sdes.xor(y1, y2)
                deltas_y.append(delta_y)

            self.diff_pair_s0.loc[len(self.diff_pair_s0)] = [x1, y1] + deltas_y

        for i in range(16):
            x1 = format(i, "04b")
            y1 = self.sdes.substitution(x1, self.sdes.SBOX[1])
            deltas_y = []
            for delta_x in [format(num, "04b") for num in range(16)]:
                x2 = self.sdes.xor(x1, delta_x)
                y2 = self.sdes.substitution(x2, self.sdes.SBOX[1])
                delta_y = self.sdes.xor(y1, y2)
                deltas_y.append(delta_y)

            self.diff_pair_s1.loc[len(self.diff_pair_s1)] = [x1, y1] + deltas_y

        # self.save_table(self.diff_pair_s0,"Difference_Pair_Table_S0")
        # self.save_table(self.diff_pair_s1,"Difference_Pair_Table_S1")

    def generate_diff_dist_tables(self):
        for dx in [format(x, "04b") for x in range(16)]:
            dist_row = []
            dst = self.diff_pair_s0[dx].value_counts().to_dict()
            for dy in [format(y, "02b") for y in range(4)]:
                if dy in dst.keys():
                    dist_row.append(dst[dy])
                else:
                    dist_row.append(0)

            self.diff_dist_s0.loc[len(self.diff_dist_s0)] = [dx] + dist_row

        for dx in [format(x, "04b") for x in range(16)]:
            dist_row = []
            dst = self.diff_pair_s1[dx].value_counts().to_dict()
            for dy in [format(y, "02b") for y in range(4)]:
                if dy in dst.keys():
                    dist_row.append(dst[dy])
                else:
                    dist_row.append(0)

            self.diff_dist_s1.loc[len(self.diff_dist_s1)] = [dx] + dist_row

        # self.save_table(self.diff_pair_s0, "Difference_Distribution_Table_S0")
        # self.save_table(self.diff_pair_s1, "Difference_Distribution_Table_S1")

    def findDC(self, sb_inx):
        currMax = 0

        if sb_inx == 0:
            for i in range(16):
                for j in range(4):
                    bit_i = format(i, "04b")
                    bit_j = format(j, "02b")

                    currVal = self.diff_dist_s0[self.diff_dist_s0["DX"] == bit_i][bit_j].to_list()[0]

                    if currVal > currMax and currVal != 16:
                        self.dex1 = bit_i
                        self.dey1 = bit_j
                        currMax = currVal

            self.prob1 = float(currMax) / 16

        else:
            for i in range(16):
                for j in range(4):
                    bit_i = format(i, "04b")
                    bit_j = format(j, "02b")

                    currVal = self.diff_dist_s1[self.diff_dist_s1["DX"] == bit_i][bit_j].to_list()[0]

                    if currVal > currMax and currVal != 16:
                        self.dex2 = bit_i
                        self.dey2 = bit_j
                        currMax = currVal

            self.prob2 = float(currMax) / 16

    def extendDC(self):
        if self.dex1[0] == '1':
            self.r1xchar = change_char_in_string(self.r1xchar, 0, '1')
            self.r1ychar = change_char_in_string(self.r1ychar, 0, '1')
        if self.dex1[1] == '1':
            self.r1xchar = change_char_in_string(self.r1xchar, 2, '1')
            self.r1ychar = change_char_in_string(self.r1ychar, 2, '1')
        if self.dex1[2] == '1':
            self.r1xchar = change_char_in_string(self.r1xchar, 1, '1')
            self.r1ychar = change_char_in_string(self.r1ychar, 1, '1')
        if self.dex1[3] == '1':
            self.r1xchar = change_char_in_string(self.r1xchar, 3, '1')
            self.r1ychar = change_char_in_string(self.r1ychar, 3, '1')

        if self.dex2[0] == '1':
            self.r1xchar = change_char_in_string(self.r1xchar, 0, '1')
            self.r1ychar = change_char_in_string(self.r1ychar, 0, '1')
        if self.dex2[1] == '1':
            self.r1xchar = change_char_in_string(self.r1xchar, 1, '1')
            self.r1ychar = change_char_in_string(self.r1ychar, 1, '1')
        if self.dex2[2] == '1':
            self.r1xchar = change_char_in_string(self.r1xchar, 2, '1')
            self.r1ychar = change_char_in_string(self.r1ychar, 2, '1')
        if self.dex2[3] == '1':
            self.r1xchar = change_char_in_string(self.r1xchar, 3, '1')
            self.r1ychar = change_char_in_string(self.r1ychar, 3, '1')

        if self.dey1[0] == '1':
            self.r1ychar = change_char_in_string(self.r1ychar, 5, '1')
        if self.dey1[1] == '1':
            self.r1ychar = change_char_in_string(self.r1ychar, 4, '1')

        if self.dey2[0] == '1':
            self.r1ychar = change_char_in_string(self.r1ychar, 7, '1')
        if self.dey2[1] == '1':
            self.r1ychar = change_char_in_string(self.r1ychar, 6, '1')

        self.r1xchar = '0000' + self.r1xchar

    def generate_key(self, subkey_array):
        test_messages = ["10100110", "10011001", "10011000", "10001010", "11000111", "11011101", "00010101",
                                "11110011", "01010100", "01110010"]
        possible_secret_keys=[]
        inv_key_pc1 = [self.sdes.KEY_PC1.index(i) for i in range(len(self.sdes.KEY_PC1))]
        inv_key_pc2 = [self.sdes.KEY_PC2.index(i) for i in range(len(self.sdes.KEY_PC2))]
        for subkey2 in subkey_array:
            inv_subkey2 = ''.join([subkey2[x] for x in inv_key_pc2])

            for bits2 in [format(x, '02b') for x in range(4)]:
                poss_c2d2 = inv_subkey2 + bits2

                c2 = poss_c2d2[:5]
                d2 = poss_c2d2[5:]

                c1 = c2[3:] + c2[:3]
                d1 = d2[3:] + d2[:3]

                c0 = c1[4:] + c1[:4]
                d0 = d1[4:] + d1[:4]

                c0d0 = c0 + d0
                key = ''.join([c0d0[x] for x in inv_key_pc1])
                s = SDES(key=key)

                original_key_cypher=[self.sdes.encryption(bitseq) for bitseq in test_messages]
                guessed_key_cypher=[s.encryption(bitseq) for bitseq in test_messages]

                if original_key_cypher == guessed_key_cypher:
                    possible_secret_keys.append(key)


        return possible_secret_keys
