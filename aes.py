rounds = 10

sbox = [
    144, 97, 98, 114, 152, 210, 81, 65, 49, 33, 184, 72, 5, 16, 44, 12,
    64, 219, 47, 112, 46, 36, 61, 239, 162, 211, 247, 43, 85, 130, 131, 60,
    202, 190, 59, 110, 4, 45, 157, 245, 160, 111, 68, 6, 140, 147, 124, 143,
    28, 29, 10, 91, 241, 230, 253, 167, 116, 246, 192, 209, 113, 53, 225, 31,
    51, 189, 213, 137, 55, 75, 237, 161, 99, 138, 175, 84, 2, 234, 150, 238,
    22, 218, 153, 146, 199, 100, 212, 56, 248, 104, 250, 37, 11, 92, 1, 169,
    101, 52, 17, 182, 164, 165, 186, 78, 252, 26, 83, 236, 179, 119, 30, 254,
    173, 251, 120, 71, 206, 228, 196, 163, 32, 94, 188, 204, 178, 229, 9, 57,
    168, 185, 148, 166, 180, 25, 223, 70, 183, 226, 200, 86, 115, 35, 231, 159,
    93, 3, 194, 109, 20, 220, 197, 121, 255, 74, 172, 40, 242, 87, 79, 7,
    107, 105, 73, 18, 80, 139, 155, 181, 15, 42, 27, 24, 69, 95, 221, 151,
    240, 201, 154, 23, 89, 177, 123, 176, 21, 222, 58, 244, 249, 208, 216, 8,
    127, 77, 136, 48, 63, 243, 191, 232, 158, 13, 50, 129, 39, 187, 156, 198,
    193, 66, 145, 117, 125, 126, 171, 233, 118, 227, 0, 14, 149, 106, 235, 141,
    103, 132, 122, 19, 203, 215, 142, 82, 38, 135, 133, 34, 128, 134, 174, 195,
    88, 224, 67, 170, 205, 214, 54, 41, 217, 207, 90, 76, 62, 102, 96, 108,
]

inv_sbox = [
    218, 94, 76, 145, 36, 12, 43, 159, 191, 126, 50, 92, 15, 201, 219, 168,
    13, 98, 163, 227, 148, 184, 80, 179, 171, 133, 105, 170, 48, 49, 110, 63,
    120, 9, 235, 141, 21, 91, 232, 204, 155, 247, 169, 27, 14, 37, 20, 18,
    195, 8, 202, 64, 97, 61, 246, 68, 87, 127, 186, 34, 31, 22, 252, 196,
    16, 7, 209, 242, 42, 172, 135, 115, 11, 162, 153, 69, 251, 193, 103, 158,
    164, 6, 231, 106, 75, 28, 139, 157, 240, 180, 250, 51, 93, 144, 121, 173,
    254, 1, 2, 72, 85, 96, 253, 224, 89, 161, 221, 160, 255, 147, 35, 41,
    19, 60, 3, 140, 56, 211, 216, 109, 114, 151, 226, 182, 46, 212, 213, 192,
    236, 203, 29, 30, 225, 234, 237, 233, 194, 67, 73, 165, 44, 223, 230, 47,
    0, 210, 83, 45, 130, 220, 78, 175, 4, 82, 178, 166, 206, 38, 200, 143,
    40, 71, 24, 119, 100, 101, 131, 55, 128, 95, 243, 214, 154, 112, 238, 74,
    183, 181, 124, 108, 132, 167, 99, 136, 10, 129, 102, 205, 122, 65, 33, 198,
    58, 208, 146, 239, 118, 150, 207, 84, 138, 177, 32, 228, 123, 244, 116, 249,
    189, 59, 5, 25, 86, 66, 245, 229, 190, 248, 81, 17, 149, 174, 185, 134,
    241, 62, 137, 217, 117, 125, 53, 142, 199, 215, 77, 222, 107, 70, 79, 23,
    176, 52, 156, 197, 187, 39, 57, 26, 88, 188, 90, 113, 104, 54, 111, 152,
]

# r_con
r_con = (0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D, 0x9A, 0x2F, 0x5E, 0xBC, 0x63, 0xC6, 0x97, 0x35, 0x6A, 0xD4, 0xB3, 0x7D, 0xFA, 0xEF, 0xC5, 0x91, 0x39)

mix_column_transform_matrix = [
    [0x02, 0x03, 0x01, 0x01, ],
    [0x01, 0x02, 0x03, 0x01, ],
    [0x01, 0x01, 0x02, 0x03, ],
    [0x03, 0x01, 0x01, 0x02, ],
]
inv_mix_column_transform_matrix = [
    [0x0E, 0x0B, 0x0D, 0x09, ],
    [0x09, 0x0E, 0x0B, 0x0D, ],
    [0x0D, 0x09, 0x0E, 0x0B, ],
    [0x0B, 0x0D, 0x09, 0x0E, ],
]


def bytes_to_matrix(text):
    return [list(text[i:i + 4]) for i in range(0, len(text), 4)]


def hex_to_matrix(hex):
    key = []
    for i in range(16):
        key.append(hex >> 8 * (16 - i - 1) & 0xFF)
    return [list(key[i:i + 4]) for i in range(0, len(key), 4)]


# def generate_sbox():
#     a = [i for i in range(256)]
#     a_rand = []
#     a_inv = {}
#     while len(a) > 0:
#         idx = random.randrange(0, len(a))
#         b = a.pop(idx)
#         a_rand.append(b)
#         a_inv["{0}".format(b)] = len(a_rand) - 1
#     x = 1
#     print("[")
#     for item in a_rand:
#         print("{}".format(item), end=", ")
#         if x % 16 == 0:
#             print("")
#         x += 1
#     print("]")
#
#     inv_a_rand = []
#     for i in range(len(a_inv)):
#         inv_a_rand.append(a_inv["{0}".format(i)])
#
#     print("[")
#     for item in inv_a_rand:
#         print("{}".format(item), end=", ")
#         if x % 16 == 0:
#             print("")
#         x += 1
#     print("]")
#
#     coba = a_rand[100]
#     print(coba)
#     print(inv_a_rand[coba])

def generate_round_keys(cipherkey_matrix):
    keys = cipherkey_matrix.copy()
    for idx_word in range(4, (rounds + 1) * 4):
        first_word = keys[idx_word - 4].copy()
        prev_word = keys[idx_word - 1].copy()
        prev_word.append(prev_word.pop(0))

        if idx_word % 4 == 0:
            new_word = [sbox[byte] for byte in prev_word]
            new_word[0] ^= r_con[idx_word//4]
        else:
            new_word = prev_word

        new_word = [i ^ j for i, j in zip(new_word, first_word)]
        keys.append(new_word)

    return [list(keys[i:i + 4]) for i in range(0, len(keys), 4)]


def substitute_bytes(block, inverse = False):
    for i in range(4):
        for j in range(4):
            if inverse:
                block[i][j] = inv_sbox[block[i][j]]
            else:
                block[i][j] = sbox[block[i][j]]


def shift_rows(block, inverse = False):
    for i in range(4):
        for id_rotate in range(i):
            if inverse:
                block[i].insert(0, block[i].pop(len(block[i])-1))
            else:
                block[i].append(block[i].pop(0))


xdot2 = lambda x: (((x << 1) ^ 0x1B) & 0xFF) if (x & 0x80) else (x << 1)


# references http://www.angelfire.com/biz7/atleast/mix_columns.pdf
def forward_mix_column(block, i, j):
    value = 0x00
    for x in range(4):
        temp = block[x][j]
        mult = mix_column_transform_matrix[i][x]
        if mult == 3:
            temp_value = xdot2(temp) ^ temp
        elif mult == 2:
            temp_value = xdot2(temp)
        else:
            temp_value = temp
        value ^= temp_value
    return value


# references https://crypto.stackexchange.com/questions/2569/how-does-one-implement-the-inverse-of-aes-mixcolumns
def backward_mix_column(block, i, j):
    value = 0x00
    for x in range(4):
        temp = block[x][j]
        mult = inv_mix_column_transform_matrix[i][x]
        temp_value = 0
        if mult == 14:
            temp_value = xdot2(xdot2(xdot2(temp) ^ temp) ^ temp)
        elif mult == 13:
            temp_value = xdot2(xdot2(xdot2(temp) ^ temp)) ^ temp
        elif mult == 11:
            temp_value = xdot2(xdot2(xdot2(temp)) ^ temp) ^ temp
        elif mult == 9:
            temp_value = xdot2(xdot2(xdot2(temp))) ^ temp
        value ^= temp_value
    return value


def mix_columns(block, inverse=False):
    new_block = []
    for i in range(4):              # i baris, 1 word =  1 baris
        temp_word = []
        for j in range(4):          # j kolom
            val = forward_mix_column(block, i, j) if not inverse else backward_mix_column(block, i, j)
            temp_word.insert(j, val)
        new_block.append(temp_word)
    return new_block


def add_roundkey(block, roundkey, inverse=False):
    for i in range(len(block)):
        for j in range(len(block[i])):
            block[i][j] ^= roundkey[i][j]


def plaintext_to_blocks(plaintext):
    added_plaintext = plaintext + ((16 - len(plaintext) % 16) * b" ")
    group_plaintext = [added_plaintext[i:i + 16] for i in range(0, len(added_plaintext), 16)]
    return group_plaintext


def block_to_string(block):
    string = ""
    for i in block:
        for j in i:
            string += chr(j)
    return string


def block_to_hex(block, with_prefix=True):
    string = ""
    if with_prefix:
        string += "0x"
    for i in block:
        for j in i:
            string += "{:02x}".format(j)
    return string


def print_block(block, as_char=False):
    for i in block:
        for j in i:
            if as_char:
                print(ascii(j), end=" ")
            else:
                print(hex(j), end=" ")
        print("")
    print("")


def encrypt(plaintext, cipherkey, to_hex=False):
    plaintext = bytes(plaintext, "utf-8")
    blocks = plaintext_to_blocks(plaintext)
    cipherkey_matrix = hex_to_matrix(cipherkey)
    round_key = generate_round_keys(cipherkey_matrix)

    ciphertext = ""
    first_block = True
    for block in blocks:
        block_matrix = bytes_to_matrix(block)
        add_roundkey(block_matrix, round_key[0])
        for i in range(1, rounds):
            substitute_bytes(block_matrix)
            shift_rows(block_matrix)
            block_matrix = mix_columns(block_matrix)
            add_roundkey(block_matrix, round_key[i])

        substitute_bytes(block_matrix)
        shift_rows(block_matrix)
        add_roundkey(block_matrix, round_key[rounds])

        if to_hex:
            ciphertext += block_to_hex(block_matrix, first_block)
        else:
            ciphertext += block_to_string(block_matrix)

        first_block = False

    return ciphertext


def decrypt(ciphertext, cipherkey, to_hex=False):
    ciphertext = bytes(ciphertext, "utf-8")
    blocks = plaintext_to_blocks(ciphertext)
    print(blocks)
    cipherkey_matrix = hex_to_matrix(cipherkey)
    round_key = generate_round_keys(cipherkey_matrix)

    plaintext = ""
    first_block = True
    for block in blocks:
        block_matrix = hex_to_matrix(block)
        add_roundkey(block_matrix, round_key[10])
        for i in range(rounds-1, 0, -1):
            shift_rows(block_matrix, True)
            substitute_bytes(block_matrix, True)
            add_roundkey(block_matrix, round_key[i])
            block_matrix = mix_columns(block_matrix, True)

        shift_rows(block_matrix, True)
        substitute_bytes(block_matrix, True)
        add_roundkey(block_matrix, round_key[0])

        if to_hex:
            plaintext += block_to_hex(block_matrix, first_block)
        else:
            plaintext += block_to_string(block_matrix)

        first_block = False

    return plaintext


if __name__ == '__main__':
    plaintext = "cobalagicoba    mantapzzzz"

    cipherkey = 0x0102030405060708090A0B0C0D0E0F10

    ciphertext = encrypt(plaintext, cipherkey, False)
    ciphertext_hex = encrypt(plaintext, cipherkey, True)
    print(plaintext)
    print(ciphertext)
    print(ciphertext_hex)
    print(decrypt(ciphertext, cipherkey))
    0x4300666d991cce39a60f6219233d41e5
    0x6513c67dab410e6f72ef18997e06297a




    # cipherkey =2b28ab097eaef7cf15d2154f16a6883c
    # plaintext = 0x328831e0435a3137f6309807a88da234
    # cipherkey_matrix = hex_to_matrix(cipherkey)
    # a = hex_to_matrix(plaintext)
    # round_key = generate_round_keys(cipherkey_matrix)
    # add_roundkey(a, round_key[0])
    # print_block(a)
    # substitute_bytes(a)
    # print_block(a)
    # shift_rows(a)
    # print("zz")
    # print_block(a)
    # a = mix_columns(a)
    # b = mix_columns(a, True)
    # print_block(a)
    # print_block(b)
    # print("zz")
    # add_roundkey(a, round_key[1])
    # print_block(a)
