def change_char_in_string(original_string, index, new_char):
    assert len(original_string) > index
    assert index >= 0
    assert len(new_char) == 1

    return original_string[:index] + new_char + original_string[index + 1:]


class SDES:

    def __init__(self, key=None):
        self.KEY = key
        self.KEY_PC1 = [9, 7, 3, 8, 0, 2, 6, 5, 1, 4] # 10-bit key permutation table
        self.KEY_PC2 = [3, 1, 7, 5, 0, 6, 4, 2] # 8-bit key permutation table
        self.IP1 = [7, 6, 4, 0, 2, 5, 1, 3] # 8-bit initial permutation table
        self.INV_IP1 = [self.IP1.index(i) for i in range(len(self.IP1))] # 8-bit inverse initial permutation table

        self.E_BIT_SELECTION_TABLE = [0, 2, 1, 3, 0, 1, 2, 3] # 8-bit expansion table

        self.SBOX = [[ # sbox0 and sbox1
            [1, 0, 2, 3],
            [3, 1, 0, 2],
            [2, 0, 3, 1],
            [1, 3, 2, 0]
        ], [
            [0, 1, 2, 3],
            [2, 0, 1, 3],
            [3, 0, 1, 0],
            [2, 1, 0, 3]
        ]]
        self.P = [1, 0, 3, 2] #feistel function permutation table

        self.intermediary_results = {'r': 0}

    def set_key(self, key):
        self.KEY = key

    def generate_subkeys(self):
        assert type(self.KEY) == str # check if there is a key
        perm_key = ''.join([self.KEY[x] for x in self.KEY_PC1])

        c0 = perm_key[:5]
        d0 = perm_key[5:]

        c1 = c0[1:] + c0[:1]
        d1 = d0[1:] + d0[:1]

        c1d1 = c1 + d1
        c1d1 = '00' + c1d1[2:]

        k1 = ''.join([c1d1[x] for x in self.KEY_PC2])

        c2 = c1[2:] + c1[:2]
        d2 = d1[2:] + d1[:2]

        c2d2 = c2 + d2
        k2 = ''.join([c2d2[x] for x in self.KEY_PC2])

        return k1, k2

    def xor(self, bitarr1, bitarr2):
        assert len(bitarr1) == len(bitarr2)
        result = ''
        for b1, b2 in zip(bitarr1, bitarr2):
            if b1 == b2:
                result += '0'
            else:
                result += '1'
        return result

    def expansion(self, r):
        return ''.join([r[x] for x in self.E_BIT_SELECTION_TABLE])

    def substitution(self, s, sbox):
        res = bin(sbox[int(s[0] + s[-1], 2)][int(s[1:-1], 2)])[2:]

        if len(res) == 1:
            res = '0' + res

        return res

    def permutation(self, bit_str):
        return ''.join([bit_str[x] for x in self.P])

    def f(self, r, key):
        e = self.expansion(r)

        res = self.xor(e, key)

        s0 = res[:4]
        s1 = res[4:]

        s0 = self.substitution(s0, self.SBOX[0])
        s1 = self.substitution(s1, self.SBOX[1])

        s0s1 = s0 + s1

        output = self.permutation(s0s1)
        return output

    def lastRound(self, bitarray, key):
        l0 = bitarray[:4]
        r0 = bitarray[4:]

        l1 = r0
        r1 = self.xor(l0, self.f(r0, key))

        l1r1 = r1 + l1
        output = ''.join([l1r1[x] for x in self.INV_IP1])

        return output

    def block_cypher(self, bitarray, keys):
        self.intermediary_results["R1X"] = bitarray
        l0 = ''.join([bitarray[x] for x in self.IP1[:4]])
        r0 = ''.join([bitarray[x] for x in self.IP1[4:]])

        l1 = r0
        r1 = self.xor(l0, self.f(r0, keys[0]))

        l1r1 = l1 + r1
        self.intermediary_results["R1Y"] = l1r1
        l2 = r1
        r2 = self.xor(l1, self.f(r1, keys[1]))

        l2r2 = l2 + r2
        output = r2 + l2
        output = ''.join([output[x] for x in self.INV_IP1])

        if self.intermediary_results['r'] == 0:
            self.intermediary_results['C1'] = output
            self.intermediary_results['r'] += 1
        else:
            self.intermediary_results['C2'] = output
            self.intermediary_results['r'] -= 1
        return output

    def text_to_binary(self, plaintext):
        bit_str = ''.join(format(ord(char), '08b') for char in plaintext)

        return bit_str

    def binary_to_text(self, bit_str):
        result = ""
        for i in range(0, len(bit_str), 8):
            segment = bit_str[i:i + 8]
            ascii_code = int(segment, 2)
            char = chr(ascii_code)
            result += char

        return result

    def encryption(self, bit_str):
        # bit_str = self.text_to_binary(plaintext)
        output = ""

        for i in range(0, len(bit_str), 8):
            segment = bit_str[i:i + 8]
            output += self.block_cypher(segment, self.generate_subkeys())

        return output

    def decryption(self, bit_str):
        # bit_str = self.text_to_binary(cyphertext)
        output = ""

        for i in range(0, len(bit_str), 8):
            segment = bit_str[i:i + 8]
            output += self.block_cypher(segment, self.generate_subkeys()[::-1])

        return output
