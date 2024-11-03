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
    if 1 <= i < len(rcon):
        return rcon[i]  # Return a single byte
    else:
        raise ValueError("Rcon value out of bounds for given input.")

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

def shift_rows(state):
    state[1] = state[1][1:] + state[1][:1]  
    state[2] = state[2][2:] + state[2][:2]  
    state[3] = state[3][3:] + state[3][:3]  
    
    return state

def inv_shift_rows(state):
    state[1] = state[1][-1:] + state[1][:-1]
    state[2] = state[2][-2:] + state[2][:-2]
    state[3] = state[3][-3:] + state[3][:-3]
    
    return state

def mix_columns(state):
    
    for col in range(4):
        a0 = state[0][col]
        a1 = state[1][col]
        a2 = state[2][col]
        a3 = state[3][col]

        state[0][col] = multiplication_by_2[a0] ^ multiplication_by_3[a1] ^ a2 ^ a3
        state[1][col] = a0 ^ multiplication_by_2[a1] ^ multiplication_by_3[a2] ^ a3
        state[2][col] = a0 ^ a1 ^ multiplication_by_2[a2] ^ multiplication_by_3[a3]
        state[3][col] = multiplication_by_3[a0] ^ a1 ^ a2 ^ multiplication_by_2[a3]

    return state

def inv_mix_columns(state):
   
    for col in range(4):
        a0 = state[0][col]
        a1 = state[1][col]
        a2 = state[2][col]
        a3 = state[3][col]

        state[0][col] = multiplication_by_14[a0] ^ multiplication_by_11[a1] ^ multiplication_by_13[a2] ^ multiplication_by_9[a3]
        state[1][col] = multiplication_by_9[a0] ^ multiplication_by_14[a1] ^ multiplication_by_11[a2] ^ multiplication_by_13[a3]
        state[2][col] = multiplication_by_13[a0] ^ multiplication_by_9[a1] ^ multiplication_by_14[a2] ^ multiplication_by_11[a3]
        state[3][col] = multiplication_by_11[a0] ^ multiplication_by_13[a1] ^ multiplication_by_9[a2] ^ multiplication_by_14[a3]

    return state

'''

Encryption function for n rounds:
- text_to_state (converts plaintexts/ciphertexts into an AES state)

'''

def text_to_state(text) -> list:
    
    # Ensure the input is bytes
    if isinstance(text, str):
        text_bytes = text.encode('utf-8')
    else:
        text_bytes = text

    # Padding or truncating
    if len(text_bytes) < 16:
        text_bytes += b' ' * (16 - len(text_bytes))
    elif len(text_bytes) > 16:
        text_bytes = text_bytes[:16]

    # Fill state in column-major order
    state = [[0] * 4 for _ in range(4)]
    for i in range(16):
        row = i % 4
        col = i // 4
        state[row][col] = text_bytes[i]

    return state

def printState(state: list):
    for row in state:
        print(" ".join(f"{byte:02x}" for byte in row))


def encrypt(plaintext, key, num_rounds, verbose = True) -> list:
    
    
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

Testing

'''

key = b'\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x88\x09\xcf\x4f\x3c\x03'


cipher_state = encrypt("yourplaintext16c", key, num_rounds=3, verbose=True)  # Print states
#cipher_state = encrypt("yourplaintext16c", key, num_rounds=3, verbose=False)  # Do not print states

cipher_text = ''.join(chr(byte) for row in cipher_state for byte in row)
print(cipher_text)

