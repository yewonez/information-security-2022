# Simplified DES (Data Encryption Standard) with ECB and CBC
# S-DES Algorithm Template Code for CNU Information Security 2022

# This code requires "bitarray" package.
# Install with: pip install bitarray

from ctypes import ArgumentError
import re, random
from bitarray import bitarray, util as ba_util

# Initial Permutation (IP)
IP = [1, 5, 2, 0, 3, 7, 4, 6]

# Inverse of Initial Permutation (or Final Permutation)
IP_1 = [3, 0, 2, 4, 6, 1, 7, 5]

# Expansion (4bits -> 8bits)
EP = [3, 0, 1, 2, 1, 2, 3, 0]

# SBox (S0)
S0 = [
    [1, 0, 3, 2],
    [3, 2, 1, 0],
    [0, 2, 1, 3],
    [3, 1, 3, 2]
]

# SBox (S1)
S1 = [
    [0, 1, 2, 3],
    [2, 0, 1, 3],
    [3, 0, 1, 0],
    [2, 1, 0, 3]
]

# Permutation (P4)
P4 = [1, 3, 2, 0]

# Permutation (P10)
P10 = [2, 4, 1, 6, 3, 9, 0, 8, 7, 5]

# Permutation (P8)
P8 = [5, 2, 6, 3, 7, 4, 9, 8]

#### DES Start

MODE_ENCRYPT = 1
MODE_DECRYPT = 2

'''
schedule_keys: generate round keys for round function
returns array of round keys.
keep in mind that total rounds of S-DES is 2.
'''


def schedule_keys(key: bitarray) -> list[bitarray]:
    round_keys = []
    permuted_key = bitarray()

    for i in P10:
        permuted_key.append(key[i])

    permuted_key_left = permuted_key[0:5]
    permuted_key_right = permuted_key[5:10]

    for i in range(1, 3):
        # shift for each round
        # round 1: shift 1, round 2: shift 2
        # shifting will be accumulated for each rounds
        permuted_key_left = permuted_key_left[i:] + permuted_key_left[0:i]
        permuted_key_right = permuted_key_right[i:] + permuted_key_right[0:i]

        # merge and permutate with P8
        merge_permutation = permuted_key_left + permuted_key_right
        round_key = bitarray()

        for j in P8:
            round_key.append(merge_permutation[j])

        round_keys.append(round_key)

    return round_keys


'''
round: round function
returns the output of round function
'''


def round(text: bitarray, round_key: bitarray) -> bitarray:
    # implement round function
    expanded = bitarray()
    for i in EP:
        expanded.append(text[i])
    expanded ^= round_key

    # S0
    s0_row = expanded[0:4]
    s0_sel_row = (s0_row[0] << 1) + s0_row[3]
    s0_sel_col = (s0_row[1] << 1) + s0_row[2]
    s0_result = ba_util.int2ba(S0[s0_sel_row][s0_sel_col], length=2)

    # S1
    s1_row = expanded[4:8]
    s1_sel_row = (s1_row[0] << 1) + s1_row[3]
    s1_sel_col = (s1_row[1] << 1) + s1_row[2]
    s1_result = ba_util.int2ba(S1[s1_sel_row][s1_sel_col], length=2)

    pre_perm4 = s0_result + s1_result

    result = bitarray()
    for i in P4:
        result.append(pre_perm4[i])

    return result


'''
sdes: encrypts/decrypts plaintext or ciphertext.
mode determines that this function do encryption or decryption.
     MODE_ENCRYPT or MODE_DECRYPT available.
'''


def sdes(text: bitarray, key: bitarray, mode) -> bitarray:
    result = bitarray()
    round_keys = schedule_keys(key)

    # if decryption mode, round keys should be reserved
    if mode == MODE_DECRYPT:
        round_keys.reverse()

    # do initial permutation
    for i in IP:
        result.append(text[i])

    half_text_left = result[0:4]
    half_text_right = result[4:8]

    # do round 1
    r1_result = round(half_text_right, round_keys[0]) ^ half_text_left

    # switch and do round 2
    r2_result = round(r1_result, round_keys[1]) ^ half_text_right

    # do final permutation
    result.clear()
    round_result = r2_result + r1_result

    for i in IP_1:
        result.append(round_result[i])

    return result


def sdes_encrypt_ecb(text: bitarray, key: bitarray):
    t_p = 0
    t_l = len(text) // 8
    result = bitarray()

    for i in range(0,t_l):
        if t_p == 0:
            temp = sdes(text[0:8], key, 1)
            result.extend(temp)
        else:
            result.append(sdes(text[t_p*t_l:t_p*t_l + 8],key,1))
    return result


def sdes_decrypt_ecb(ciphertext: bitarray, key: bitarray):
    t_p = 0
    t_l = len(ciphertext) // 8
    result = bitarray()
    for i in range(0,t_l):
        if t_p == 0:
            result.extend(sdes(ciphertext[0:8], key, 2))
        else:
            result.extend(sdes(ciphertext[t_p * i:t_p * i + 8],key,2))
    return result


def sdes_encrypt_cbc(text: bitarray, key: bitarray, iv: bitarray):
    prev_vector = iv
    t_p = 0
    t_l = len(text) // 8
    result = bitarray()
    for i in range(0,t_l):
        if t_p == 0:
            temp = text[0:8] ^ prev_vector
            temp2= sdes(temp, key,1)
            result.extend(temp2)
            prev_vector = temp2
        else:
            temp = text[t_p * i: t_p * i + 8] ^ prev_vector
            temp2 = sdes(temp, key,1)
            result.extend(temp2)
            prev_vector = temp2
    return result

def sdes_decrypt_cbc(ciphertext: bitarray, key: bitarray, iv: bitarray):
    prev_vector = iv
    t_p = 0
    t_l = len(ciphertext) // 8
    result = bitarray()
    for i in range(0, t_l):
        if t_p == 0:
            temp = sdes(ciphertext[0:8], key,2)
            temp2 = temp ^ prev_vector
            result.extend(temp2)
            prev_vector = ciphertext[0:8]
        else:
            temp = sdes(ciphertext[t_p*i : t_p*i + 8], key,2)
            temp2 = temp ^ prev_vector
            result.extend(temp2)
            prev_vector = ciphertext[t_p*i : t_p*i + 8]
    return result

#### DES Sample Program Start

plaintext = input("[*] Input Plaintext in Binary: ")
key = input("[*] Input Key in Binary (10bits): ")

print(len(plaintext))

# Plaintext must be multiple of 8 and Key must be 10 bits.
if len(plaintext) % 8 != 0 or len(key) != 10:
    raise ArgumentError("Input Length Error!!!")

if re.search("[^01]", plaintext) or re.search("[^01]", key):
    raise ArgumentError("Inputs must be in binary!!!")

bits_plaintext = bitarray(plaintext)
bits_key = bitarray(key)

print(f"Plaintext: {bits_plaintext}")
print(f"Key: {bits_key}")

result_encrypt = sdes_encrypt_ecb(bits_plaintext, bits_key)

print(f"Encrypted (ECB): {result_encrypt}")

result_decrypt = sdes_decrypt_ecb(result_encrypt, bits_key)

print(f"Decrypted (ECB): {result_decrypt}, Expected: {bits_plaintext}")

if result_decrypt != bits_plaintext:
    print(f"S-DES-ECB FAILED...")
else:
    print(f"S-DES-ECB SUCCESS!!!")

# now IV will be always 8 bits
# no! u r WRONG its """9""" bits...
random_iv = bitarray(bin(random.getrandbits(7) + (1 << 7)).replace('0b', ''))
print(f"IV will be random...{random_iv}")

result_encrypt = sdes_encrypt_cbc(bits_plaintext, bits_key, random_iv)

print(f"Encrypted (CBC): {result_encrypt}")

result_decrypt = sdes_decrypt_cbc(result_encrypt, bits_key, random_iv)

print(f"Decrypted (CBC): {result_decrypt}, Expected: {bits_plaintext}")

if result_decrypt != bits_plaintext:
    print(f"S-DES-CBC FAILED...")
else:
    print(f"S-DES-CBC SUCCESS!!!")

    #