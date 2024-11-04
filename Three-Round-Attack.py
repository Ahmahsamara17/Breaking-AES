from AES_implement import *
import os
from itertools import product
import time

'''

Misc functions

'''
def bytes_to_matrix(bytes):
    if len(bytes) != 16:
        raise ValueError("Input must be exactly 16 bytes.")
    
    matrix = [list(bytes[i:i+4]) for i in range(0, len(bytes), 4)]
    
    return matrix
    
def matrix_to_bytes(matrix):
    if len(matrix) != 4 or any(len(row) != 4 for row in matrix):
        raise ValueError("Input must be a 4x4 matrix.")
    
    byte_array = bytes(sum(matrix, []))
    
    return byte_array

def inv_last_round(state_incoming, key):
    state = bytes_to_matrix(state_incoming)
    round_key = bytes_to_matrix(key)

    state = add_round_key(state, round_key) 
    state = inv_shift_rows(state) 
    state = inv_sub_bytes(state)
    
    return matrix_to_bytes(state)
    
def generate_256_list():
    result = []
    for i in range(256):
        result.append(i)

    return result

def round1_to_round2(state):
    state1 = bytes_to_matrix(state)
    state2 = sub_bytes(state1)
    state3 = shift_rows(state2)
    state4 = mix_columns(state3)
    
    return matrix_to_bytes(state4)

'''

Generate the differential table
Generate the impossible states

'''

def generate_sbox_ddt():
    table = {}
    for i in range(256):
        for j in range(256):
            diff = i ^ j
            diff_sbox = S_box[i] ^ S_box[j]

            if diff in table:
                if diff_sbox not in table[diff]:
                    table[diff].append(diff_sbox)
            else:
                table[diff] = [diff_sbox]

    return table



def generate_impossible_state(differential):
    impossible = []
    for i in range(4):
        impossible.append([])
        for j in range(256):
            if j not in S_box_ddt[differential[i]]:
                impossible[i].append(j)

    impossible_state = []
    for i in range(4):
        
        for j in impossible[i]:
            state = bytes_to_matrix(b'\x00'*(i) + bytes([j]) + b'\x00'*(15-i))
            shift_rows(state)
            mix_columns(state)
            impossible_state.append(matrix_to_bytes(state))
            
    return impossible_state

'''

Functions to handle plaintext generation
Functions to handle ciphertext loading

'''
def generate_plaintext(n=5):
    """
    Generates n unique plaintexts with the same logic as the original function but without encryption.
    """
    while True:
        bs = []
        for i in range(n):
            bs.append(os.urandom(1))

        is_unique = True
        exclude = []
        for i in range(n - 1):
            for j in range(i + 1, n):
                check = bs[i][0] ^ bs[j][0]
                if check not in exclude:
                    exclude.append(check)
                else:
                    is_unique = False

        if is_unique:
            plaintexts = [bytes(bs[i]) + b'\x00' * 15 for i in range(n)]
            return plaintexts

def receive_and_package_ciphertexts(plaintexts, ciphertexts):
   
    if len(plaintexts) != len(ciphertexts):
        raise ValueError("Number of ciphertexts must match the number of plaintexts.")

    n = len(plaintexts)
    pairs = []

    for i in range(n - 1):
        for j in range(i + 1, n):
            p1 = plaintexts[i]
            p2 = plaintexts[j]
            pairs.append([p1, p2, ciphertexts[i], ciphertexts[j]])

    return pairs

def generate_and_save_plaintext_files(n=5, directory="plain_texts"):
    # Create the directory if it doesn't exist
    if not os.path.exists(directory):
        os.makedirs(directory)

    # Use generate_plaintext() to get n plaintexts
    plaintexts = generate_plaintext(n)

    # Loop to save each plaintext as a .bin file
    for i, plaintext in enumerate(plaintexts, 1):
        file_path = os.path.join(directory, f"{i}.bin")
        with open(file_path, "wb") as f:
            f.write(plaintext)

    print(f"{n} plaintext files have been generated and saved in '{directory}'.")
    
def load_ciphertext_files(n=5, directory="Cipher_texts"):
    ciphertexts = []

    # Loop through the files named "ciphertext1.bin" through "ciphertextN.bin"
    for i in range(1, n+1):
        file_path = os.path.join(directory, f"ciphertext{i}.bin")
        
        # Open the file and read the contents
        with open(file_path, "rb") as f:
            ciphertext = f.read()
            ciphertexts.append(ciphertext)

    return ciphertexts

def load_plaintext_files(n=5, directory="plain_texts"):
    plaintexts = []

    # Loop through the files named "1.bin" through "n.bin"
    for i in range(1, n+1):
        file_path = os.path.join(directory, f"{i}.bin")
        
        # Open the file and read the contents
        with open(file_path, "rb") as f:
            plaintext = f.read()
            plaintexts.append(plaintext)

    return plaintexts

real_key = b'\x00'

plaintexts = load_plaintext_files(n=5)
print("Plaintexts loaded successfully!")

ciphertexts = load_ciphertext_files(n=5)
print("Ciphertexts loaded successfully!")

test_pair = receive_and_package_ciphertexts(plaintexts, ciphertexts)

shifted = [0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11]

S_box_ddt = generate_sbox_ddt()

impossible_key = [None] * 256
possible_rk0 = -1

for x in range(256):
    print("[+] Testing Round Key = " + str(x))
    impossible_key[x] = [None] * 16
    
    for plain1, plain2, cipher1, cipher2 in test_pair:
        
        plain1_xor_plain2 = xor(plain1, plain2)
        cipher_a = cipher1
        cipher_b = cipher2
        
        round0_key = bytes([x]) + b'\x00'*15
        a = xor(plain1, round0_key)
        b = xor(plain2, round0_key)
      
        a_imp = round1_to_round2(a)
        b_imp = round1_to_round2(b)
        
        
        
        plain_diff = xor(a_imp, b_imp)
        
        impossible_state = generate_impossible_state(plain_diff)
        # Brute-force last round key one byte at time by comparing against impossible_state
        for i in range(16):
            if impossible_key[x][i] is None:
                impossible_key[x][i] = []

            shifted_index = shifted[i]
            
            for j in range(256):
                if j in impossible_key[x][i]:
                    continue

                # Inverse ciphertext to start of round 3 (ciphertext -> AddRoundKey -> InvShiftRows -> InvSubBytes)
                guess_key = b'\x00'*(i) + bytes([j]) + b'\x00'*(15-i)
                inv_a = inv_last_round(cipher_a, guess_key)
                
                
                inv_b = inv_last_round(cipher_b, guess_key)
                inv_diff = xor(inv_a, inv_b)

                # Check if inv_diff contained in one of impossible_state
                for imp in impossible_state:
                    if inv_diff[shifted_index] == imp[shifted_index]:
                        impossible_key[x][i].append(j)
    n = []
    for z in range(16):
        n.append(len(impossible_key[x][z]))
    
    if 256 not in n:
        print('[+] Found correct Rk0')
        possible_rk0 = x
        print(possible_rk0)
        break    

list_256 = generate_256_list()

possible_key = []
for imp_key in impossible_key[possible_rk0]:
    possible_key.append(list(set(list_256) - set(imp_key)))
    
all_possible_key = product(*possible_key)


# Enumerate all remaining possible_key
ciphertext_check = test_pair[0][2]
for possible_round_key in all_possible_key:
    print(1)
    master_key = inv_key_expansion(list(possible_round_key), 3)
    print(master_key)
    
    decrypt_check = decrypt(ciphertext_check, master_key)
    if decrypt_check == test_pair[0][0]:
        print('[+] Possible Master Key:', master_key)
        print('[+] Actual Master Key  :', real_key) #KEY)
        break
        