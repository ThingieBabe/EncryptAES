import sys, string, random

# S-Box
def generate_s_box():
    return [[0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76],
            [0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0],
            [0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15],
            [0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75],
            [0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84],
            [0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF],
            [0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8],
            [0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2],
            [0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73],
            [0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB],
            [0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79],
            [0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08],
            [0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A],
            [0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E],
            [0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF],
            [0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16]]

# Convertir une chaîne hexadécimale en matrice 4x4
def hex_string_to_matrix(hex_string):
    assert len(hex_string) == 32, "Le texte doit contenir 32 caractères hexadécimaux (16 octets)"
    return [[int(hex_string[2*(i*4 + j):2*(i*4 + j)+2], 16) for j in range(4)] for i in range(4)]

# Convertir une matrice 4x4 en chaîne hexadécimale
def matrix_to_hex_string(matrix):
    return ''.join(f'{byte:02x}' for row in matrix for byte in row)

# Fonction SubBytes
def encrypt(tab):
    s_box = generate_s_box()
    res = [[0 for _ in range(4)] for _ in range(4)]
    for i in range(4):
        for j in range(4):
            byte = tab[i][j]
            res[i][j] = s_box[byte >> 4][byte & 0x0F]
    return res

# Fonction ShiftRows
def shift(state):
    for i in range(1, 4):
        state[i] = state[i][i:] + state[i][:i]
    return state

def inv_shift(state):
    for i in range(1, 4):
        # Décalage circulaire des lignes vers la droite
        state[i] = state[i][-i:] + state[i][:-i]
    return state

def inv_encrypt(state):
    inv_s_box = generate_inv_s_box()
    for i in range(4):
        for j in range(4):
            byte = state[i][j]
            row = (byte >> 4) & 0x0F
            col = byte & 0x0F
            state[i][j] = inv_s_box[row][col]
    return state

def generate_inv_s_box():
    s_box = generate_s_box()
    inv_s_box = [[0 for _ in range(16)] for _ in range(16)]
    for i in range(16):
        for j in range(16):
            inv_s_box[s_box[i][j] >> 4][s_box[i][j] & 0x0F] = i << 4 | j
    return inv_s_box

def inv_mix_columns(state):
    for col in state:
        a = col[:]
        col[0] = galois_multiply(a[0], 0x0E) ^ galois_multiply(a[1], 0x0B) ^ galois_multiply(a[2], 0x0D) ^ galois_multiply(a[3], 0x09)
        col[1] = galois_multiply(a[0], 0x09) ^ galois_multiply(a[1], 0x0E) ^ galois_multiply(a[2], 0x0B) ^ galois_multiply(a[3], 0x0D)
        col[2] = galois_multiply(a[0], 0x0D) ^ galois_multiply(a[1], 0x09) ^ galois_multiply(a[2], 0x0E) ^ galois_multiply(a[3], 0x0B)
        col[3] = galois_multiply(a[0], 0x0B) ^ galois_multiply(a[1], 0x0D) ^ galois_multiply(a[2], 0x09) ^ galois_multiply(a[3], 0x0E)
    return state


# Galois Field multiplication
def galois_multiply(a, b):
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi_bit_set = a & 0x80
        a <<= 1
        if hi_bit_set:
            a ^= 0x1B
        b >>= 1
    return p & 0xFF

# Fonction MixColumns
def mix_columns(state):
    for col in state:
        a = col[:]
        col[0] = galois_multiply(a[0], 2) ^ galois_multiply(a[1], 3) ^ a[2] ^ a[3]
        col[1] = a[0] ^ galois_multiply(a[1], 2) ^ galois_multiply(a[2], 3) ^ a[3]
        col[2] = a[0] ^ a[1] ^ galois_multiply(a[2], 2) ^ galois_multiply(a[3], 3)
        col[3] = galois_multiply(a[0], 3) ^ a[1] ^ a[2] ^ galois_multiply(a[3], 2)
    return state

# Fonction AddRoundKey
def add_round_key(state, key):
    return [[state[i][j] ^ key[i][j] for j in range(4)] for i in range(4)]

# Fonction RotWord
def rot_word(word):
    return word[1:] + word[:1]

# Fonction SubWord
def sub_word(word, s_box):
    return [s_box[byte >> 4][byte & 0x0F] for byte in word]

# Fonction KeyExpansion
def key_expansion(key, s_box, Nk, Nr):
    rcon = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36,
            0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6,
            0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91]
    Nb = 4
    w = []
    for i in range(Nk):
        w.append([key[i][j] for j in range(4)])
    for i in range(Nk, Nb * (Nr + 1)):
        temp = w[i - 1][:]
        if i % Nk == 0:
            temp = sub_word(rot_word(temp), s_box)
            temp[0] ^= rcon[i // Nk - 1]
        elif Nk > 6 and i % Nk == 4:
            temp = sub_word(temp, s_box)
        w.append([w[i - Nk][j] ^ temp[j] for j in range(4)])
    return w

def string_to_hex(text):
    # Convertit une chaîne de caractères en une chaîne hexadécimale de 32 caractères (16 octets)
    hex_string = ''.join(format(ord(char), '02x') for char in text)
    hex_string = hex_string.zfill(32)  # Remplir avec des zéros à gauche si la longueur est inférieure à 32
    return hex_string

def matrix_to_string(state):
    string = ""
    for col in state:
        for byte in col:
            string += chr(byte)
    return string
    
def generate_hex_key(length):
    hex_chars = string.hexdigits[:-6]  # Liste des caractères hexadécimaux (0-9, A-F)
    num_chars = length * 2  # Le nombre total de caractères hexadécimaux requis
    hex_key = ''.join(random.choice(hex_chars) for _ in range(num_chars))
    return hex_key

def AESEncrypt(plain_text, key_length=128):
    assert key_length in [128, 192, 256], "La longueur de la clé doit être de 128, 192, ou 256 bits"
    
    Nk = key_length // 32
    Nr = {128: 10, 192: 12, 256: 14}[key_length]
    
    key_hex = generate_hex_key(Nk * 4)  # Taille de la clé en octets
    s_box = generate_s_box()
    plain_text_hex = string_to_hex(plain_text)
    assert len(plain_text_hex) == 32, "Le texte doit être converti en une chaîne hexadécimale de 32 caractères (16 octets)"
    
    key = hex_string_to_matrix(key_hex)
    expanded_key = key_expansion(key, s_box, Nk, Nr)
    
    state = add_round_key(hex_string_to_matrix(plain_text_hex), key)
    for round in range(1, Nr):
        state = encrypt(state)
        state = shift(state)
        state = mix_columns(state)
        round_key = [[expanded_key[round * 4 + i][j] for j in range(4)] for i in range(4)]
        state = add_round_key(state, round_key)
    
    state = encrypt(state)
    state = shift(state)
    final_round_key = [[expanded_key[Nr * 4 + i][j] for j in range(4)] for i in range(4)]
    state = add_round_key(state, final_round_key)
    
    cipher_text_hex = matrix_to_hex_string(state)
    print(f"Texte chiffré: {cipher_text_hex}")
    print(f"Clé: {key_hex}")

def AESDecrypt(cipher_text_hex, key_hex):
    key_length = len(key_hex) * 4  # La longueur de la clé en bits

    assert key_length in [128, 192, 256], "La longueur de la clé doit être de 128, 192, ou 256 bits"

    Nk = key_length // 32
    Nr = {128: 10, 192: 12, 256: 14}[key_length]

    s_box = generate_s_box()
    cipher_text = hex_string_to_matrix(cipher_text_hex)
    key = hex_string_to_matrix(key_hex)
    expanded_key = key_expansion(key, s_box, Nk, Nr)

    # Dernière clé de tour
    final_round_key = [[expanded_key[Nr * 4 + i][j] for j in range(4)] for i in range(4)]

    # Ajout de la clé de tour finale
    state = add_round_key(cipher_text, final_round_key)
    # Inverser ShiftRows
    state = inv_shift(state)
    # Inverser SubBytes
    state = inv_encrypt(state)

    # Inverser chaque tour
    for round in range(Nr - 1, 0, -1):
        round_key = [[expanded_key[round * 4 + i][j] for j in range(4)] for i in range(4)]
        state = add_round_key(state, round_key)
        state = inv_mix_columns(state)
        state = inv_shift(state)
        state = inv_encrypt(state)

    # Ajout de la clé initiale
    initial_round_key = [[expanded_key[0 * 4 + i][j] for j in range(4)] for i in range(4)]
    state = add_round_key(state, initial_round_key)

    print("Texte déchiffré :", matrix_to_string(state))



input = sys.argv[1]
if len(sys.argv[2]) == 3:
	length = int(sys.argv[2])
	AESEncrypt(input,key_length=length)
else:
	key_hex = sys.argv[2]
	AESDecrypt(input, key_hex)




