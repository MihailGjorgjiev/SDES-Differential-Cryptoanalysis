from differential_cryptanalysis import DiffCrypt
import numpy as np
import argparse

parser = argparse.ArgumentParser(description="Differential Cryptalanysis for S-DES.")
parser.add_argument("key", type=str)
secret_key = parser.parse_args().key

dc = DiffCrypt()
dc.sdes.set_key(secret_key)

print("Secret key :", secret_key)
print("Generated Subkeys :", dc.sdes.generate_subkeys()[0], dc.sdes.generate_subkeys()[1])
print('\n\n')
dc.generate_diff_pair_tables()
dc.generate_diff_dist_tables()
dc.findDC(0)
dc.findDC(1)

dc.extendDC()

pk2 = [0 for _ in range(255)]
count = 0

for i in range(255):
    dc.sdes.encryption(format(i, "08b"))

    currR1Y = dc.sdes.intermediary_results["R1Y"]

    dc.sdes.encryption(dc.sdes.xor(format(i, "08b"), dc.r1xchar))

    if dc.sdes.xor(dc.sdes.intermediary_results["R1Y"], currR1Y) == dc.r1ychar:
        count += 1
        for k in range(255):
            if dc.sdes.lastRound(currR1Y, format(k, "08b")) == dc.sdes.intermediary_results["C1"] and dc.sdes.lastRound(
                    dc.sdes.intermediary_results["R1Y"], format(k, "08b")) == dc.sdes.intermediary_results["C2"]:
                pk2[k] += 1

print("Total message encryptions on the last round per key:")
for k in range(255):
    print(k, pk2[k], sep=' : ')

print('\n\n')
print("Successful message encryptions (greater than 0) on the last round per key:")
for k in range(255):
    if pk2[k] > 0:
        print(k, pk2[k], sep=' : ')

print("COUNT:", count)

filtered_pk2 = [i for i, value in enumerate(pk2) if value > 0]
sorted_keys = sorted(filtered_pk2, key=lambda i: pk2[i],reverse=True)
print("Possible subkeys sorted by probability [in decimal]:",sorted_keys,'\n')

print("Expected subkey:", dc.sdes.generate_subkeys()[1], f"[{int(dc.sdes.generate_subkeys()[1], 2)} in decimal]")
print("Most likely subkey:", format(np.argmax(pk2), '08b'), f"[{np.argmax(pk2)} in decimal]")

solution=dc.generate_key([format(k,"08b") for k in sorted_keys])

print("Secret Key:",parser.parse_args().key,f"[{int(parser.parse_args().key,2)} in decimal]")
print("Secret key generated using differential cryptanalysis:",solution[0],f"[{int(solution[0],2)} in decimal]")

