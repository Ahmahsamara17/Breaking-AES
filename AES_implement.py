from Tables import *

'''

Key Expansion function: 
- rot_word (rotate a 4 byte_word)
- sub_word (S_box substitution)
- rcon (rcon lookup function)
- xor bytes

'''
def xor_bytes(a, b):
    return bytes(i ^ j for i, j in zip(a, b))

def rot_word(word):
    if len(word) != 4:
        raise ValueError("Input must be exactly 4 bytes")
    return word[1:] + word[:1]

def sub_word(word):
    
    substituted_word = bytearray()
    
    for byte in word:
        substituted_word.append(S_box[byte]) 
    
    return bytes(substituted_word)

def rcon_lookup(i):
    return [rcon[i], 0x00, 0x00, 0x00]

def KeyExpansion(key, num_rounds):
    
    key_columns = [list(key[i:i + 4]) for i in range(0, len(key), 4)]
    iteration_size = len(key) // 4
        
    i = 1  # Rcon index
    
    # print("Initial key columns:")
    # for idx, col in enumerate(key_columns):
    #     print(f"Column {idx}: {col}")

    while len(key_columns) < (num_rounds + 1) * 4:
        word = (key_columns[-1]).copy()
        
        if len(key_columns) % iteration_size == 0:
            word.append(word.pop(0))
            word = [S_box[b] for b in word]
            rcon_value = rcon_lookup(i)
            word[0] ^= rcon_value
            i += 1
        elif len(key) == 32 and len(key_columns) % iteration_size == 4:
            word = [S_box[b] for b in word]

        word = xor_bytes(bytes(word), bytes(key_columns[-iteration_size]))
        key_columns.append(list(word))

    round_keys = [key_columns[4 * i: 4 * (i + 1)] for i in range(len(key_columns) // 4)]
    
    #print(f"Raw round keys: {round_keys}")
    
    # print("\nFinal round keys:")
    # for idx, round_key in enumerate(round_keys):
    #     print(f"Round {idx} Key:")
    #     for col in round_key:
    #         print(" ".join(f"{byte:02x}" for byte in col))
    
    return round_keys


'''

inverse Key Expansion function: 

'''
def xor(s1, s2):
    s = b""
    for x,y in zip(s1, s2):
        s += bytes([y ^ x])
    return s

def inv_key_expansion(key, current_round):

    key_schedule = []
    key_schedule.append(key)

    for r in range(current_round, 0, -1):
      
        target_key = key_schedule[0]
        prev_key_round = [None] * 4

        prev_key_round[3] = xor(target_key[12:], target_key[8:12])
        prev_key_round[2] = xor(target_key[8:12], target_key[4:8])
        prev_key_round[1] = xor(target_key[4:8], target_key[:4])

        xored_rcon = xor(rcon_lookup(r), target_key[:4])

        prev_key_round[0] = xor(sub_word(rot_word(prev_key_round[3])), xored_rcon)

        prev_key_round = (prev_key_round[0] + prev_key_round[1] + prev_key_round[2] + prev_key_round[3])

        key_schedule.insert(0, prev_key_round)

    return key_schedule[0]
'''

AES Round Operations:

- Add Round Key 
- Sub bytes
- Shift Rows
- Mix columns

'''

'''

Normal Round Operations + inverses

'''
def add_round_key(state, round_key):
    

    if len(state) == 16:
        state = [state[i:i + 4] for i in range(0, len(state), 4)]
    
    if len(round_key) == 16:
        round_key = [round_key[i:i + 4] for i in range(0, len(round_key), 4)]
    
    #print(f"this is one byte of state: {state[0][0]} and this is one byte of round key: {round_key[0][0]}")
    for i in range(4):
        for j in range(4):
            state[i][j] ^= round_key[i][j]
    
    return state

def sub_bytes(state):
    
    for i in range(4):
        for j in range(4):
            byte = state[i][j]
            state[i][j] = S_box[byte]
    
    return state

def inv_sub_bytes(state):
    for i in range(4):
        for j in range(4):
            byte = state[i][j]
            state[i][j] = inv_sbox[byte]
    
    return state

def shift_rows(s):
    s[0][1], s[1][1], s[2][1], s[3][1] = s[1][1], s[2][1], s[3][1], s[0][1]
    s[0][2], s[1][2], s[2][2], s[3][2] = s[2][2], s[3][2], s[0][2], s[1][2]
    s[0][3], s[1][3], s[2][3], s[3][3] = s[3][3], s[0][3], s[1][3], s[2][3] 
    
    return s

def inv_shift_rows(s):
    s[0][1], s[1][1], s[2][1], s[3][1] = s[3][1], s[0][1], s[1][1], s[2][1]
    s[0][2], s[1][2], s[2][2], s[3][2] = s[2][2], s[3][2], s[0][2], s[1][2]
    s[0][3], s[1][3], s[2][3], s[3][3] = s[1][3], s[2][3], s[3][3], s[0][3]
    return s

xtime = lambda a: (((a << 1) ^ 0x1B) & 0xFF) if (a & 0x80) else (a << 1)

def mix_single_column(a):
    # see Sec 4.1.2 in The Design of Rijndael
    t = a[0] ^ a[1] ^ a[2] ^ a[3]
    u = a[0]
    a[0] ^= t ^ xtime(a[0] ^ a[1])
    a[1] ^= t ^ xtime(a[1] ^ a[2])
    a[2] ^= t ^ xtime(a[2] ^ a[3])
    a[3] ^= t ^ xtime(a[3] ^ u)
    
    return a
    
    
def mix_columns(state):
    
    for i in range(4):
        mix_single_column(state[i])

    return state

def inv_mix_columns(s):
    for i in range(4):
        u = xtime(xtime(s[i][0] ^ s[i][2]))
        v = xtime(xtime(s[i][1] ^ s[i][3]))
        s[i][0] ^= u
        s[i][1] ^= v
        s[i][2] ^= u
        s[i][3] ^= v

    mix_columns(s)

'''

Encryption function for n rounds:

- text_to_state (converts plaintexts/ciphertexts into an AES state)
- printState (print the state for debugging)
'''

def text_to_state(text):
    
    if isinstance(text, str):
        text_bytes = text.encode('utf-8')
    else:
        text_bytes = text

    if len(text_bytes) < 16:
        text_bytes += b' ' * (16 - len(text_bytes))
    elif len(text_bytes) > 16:
        text_bytes = text_bytes[:16]

    state = [[0] * 4 for _ in range(4)]
    for i in range(16):
        row = i % 4
        col = i // 4
        state[row][col] = text_bytes[i]

    return state

def printState(state):
    for row in state:
        print(" ".join(f"{byte:02x}" for byte in row))


def encrypt(plaintext, key, num_rounds, verbose = False):
    
    state = text_to_state(plaintext)
    if verbose:
        print("Initial State (plaintext):")
        printState(state)
    
    round_keys = KeyExpansion(key, num_rounds)
    
    state = add_round_key(state, round_keys[0])
    if verbose:
        print("\nAfter AddRoundKey (Round 0):")
        printState(state)
    
    
    for round_num in range(1, num_rounds):
        # SubBytes
        state = sub_bytes(state)
        if verbose:
            print(f"\nAfter SubBytes (Round {round_num}):")
            printState(state)
        
        # ShiftRows
        state = shift_rows(state)
        if verbose:
            print(f"\nAfter ShiftRows (Round {round_num}):")
            printState(state)
        
        # MixColumns (only for rounds before the final round)
        if round_num < num_rounds:
            state = mix_columns(state)
            if verbose:
                print(f"\nAfter MixColumns (Round {round_num}):")
                printState(state)
        
        # AddRoundKey
        state = add_round_key(state, round_keys[round_num])
        if verbose:
            print(f"\nAfter AddRoundKey (Round {round_num}):")
            printState(state)
    
    # Final Round (without MixColumns)
    state = sub_bytes(state)
    if verbose:
        print(f"\nAfter SubBytes (Round {num_rounds}):")
        printState(state)
    
    state = shift_rows(state)
    if verbose:
        print(f"\nAfter ShiftRows (Round {num_rounds}):")
        printState(state)
    
    state = add_round_key(state, round_keys[-1])
    if verbose:
        print(f"\nAfter AddRoundKey (Round {num_rounds}):")
        printState(state)
    
    return state


'''
Decryption function for n rounds:

- state_to_text (debugging function)

'''
def state_to_text(state):
    text_bytes = [state[row][col] for col in range(4) for row in range(4)]
    text = ''.join(chr(byte) for byte in text_bytes)
    
    return text

def decrypt(ciphertext, key, num_rounds = 3, verbose=False):
    
    if isinstance(ciphertext, str):
        state = text_to_state(ciphertext)
    else:
        state = (ciphertext)
        
    if verbose:
        print("Initial State (ciphertext):")
        printState(state)
    
    
    round_keys = KeyExpansion(key, num_rounds)
    
    
    state = add_round_key(state, round_keys[-1])
    if verbose:
        print("\nAfter Initial AddRoundKey:")
        printState(state)
    
    state = inv_shift_rows(state)
    if verbose:
        print(f"\nAfter Initial Inverse ShiftRows:")
        printState(state)
    
    state = inv_sub_bytes(state)
    if verbose:
        print(f"\nAfter Initial Inverse SubBytes:")
        printState(state)
    
    
    for round_num in range(num_rounds - 1 , 0, -1):
        
        # AddRoundKey
        state = add_round_key(state, round_keys[round_num])
        if verbose:
            print(f"\nAfter AddRoundKey (Round {round_num}):")
            printState(state)
        
        # Inverse MixColumns (not in the last round)
        state = inv_mix_columns(state)
        if verbose:
            print(f"\nAfter Inverse MixColumns (Round {round_num}):")
            printState(state)
    
        # Inverse ShiftRows
        state = inv_shift_rows(state)
        if verbose:
            print(f"\nAfter Inverse ShiftRows (Round {round_num}):")
            printState(state)
        
        # Inverse SubBytes
        state = inv_sub_bytes(state)
        if verbose:
            print(f"\nAfter Inverse SubBytes (Round {round_num}):")
            printState(state)
        
    # Final AddRoundKey with the first round key
    state = add_round_key(state, round_keys[0])
    if verbose:
        print("\nAfter Final AddRoundKey (Round 0):")
        printState(state)
    
    return state


'''

Testing

'''

# key = b'\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x88\x09\xcf\x4f\x3c\x03'


# cipher_state = encrypt("yourplaintext16c", key, num_rounds=5, verbose=True)  # Print states
# #cipher_state = encrypt("yourplaintext16c", key, num_rounds=3, verbose=False)  # Do not print states

# #cipher_text = ''.join(chr(byte) for row in cipher_state for byte in row)

# #print(f"this is the cipher text: {cipher_text}")
# #print(f"this is the cipher state: {printState((cipher_state))}\n")

# print("starting decryption\n")

# decrypted_state = decrypt(cipher_state, key, num_rounds=5, verbose=True)

# decrypted_text = state_to_text(decrypted_state)

# print("\nDecrypted text:")
# print(decrypted_text)



