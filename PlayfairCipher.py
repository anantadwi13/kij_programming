originalplaintext = []
modifiedplaintext = []
key = []
ciphertext = []
keyMatrix = [[0 for x in range(5)] for y in range(5)]
# Alphabet list without J
alphabet = list("ABCDEFGHIKLMNOPQRSTUVWXYZ")
remainAlphabet = alphabet.copy()


def set_key_matrix(lenKey):
    for x in key:
        remainAlphabet.remove(x)

    i = 0
    for x in range(5):
        for y in range(5):
            if x * 5 + y < lenKey:
                keyMatrix[x][y] = key[x * 5 + y]
            else:
                keyMatrix[x][y] = remainAlphabet[i]
                i = i + 1


def format_plaintext():
    idx = 0
    while idx < len(modifiedplaintext):
        if idx == 0:
            idx = idx + 1
            continue
        if modifiedplaintext[idx] == modifiedplaintext[idx - 1]:
            modifiedplaintext.insert(idx, "X")
        idx = idx + 2

    if len(modifiedplaintext) % 2 != 0:
        modifiedplaintext.append("X")


def find_matrix_index(val):
    for i in range(5):
        for j in range(5):
            if keyMatrix[i][j] == val:
                return i, j


def playfair_cipher_encrypt():
    idx = 0
    while idx < len(modifiedplaintext):
        if idx == 0:
            idx = idx + 1
            continue
        iFirst, jFirst = find_matrix_index(modifiedplaintext[idx - 1])
        iSecond, jSecond = find_matrix_index(modifiedplaintext[idx])
        if jFirst == jSecond and iFirst == iSecond:
            ciphertext.append(keyMatrix[(iFirst + 1) % 5][(jFirst + 1) % 5])
            ciphertext.append(keyMatrix[(iFirst + 1) % 5][(jFirst + 1) % 5])
        elif iFirst == iSecond:
            ciphertext.append(keyMatrix[iFirst][(jFirst + 1) % 5])
            ciphertext.append(keyMatrix[iFirst][(jSecond + 1) % 5])
        elif jFirst == jSecond:
            ciphertext.append(keyMatrix[(iFirst + 1) % 5][jFirst])
            ciphertext.append(keyMatrix[(iSecond + 1) % 5][jFirst])
        else:
            ciphertext.append(keyMatrix[iFirst][jSecond])
            ciphertext.append(keyMatrix[iSecond][jFirst])
        idx = idx + 2


def playfair_cipher_decrypt():
    idx = 0
    while idx < len(ciphertext):
        if idx == 0:
            idx = idx + 1
            continue
        iFirst, jFirst = find_matrix_index(ciphertext[idx - 1])
        iSecond, jSecond = find_matrix_index(ciphertext[idx])
        if jFirst == jSecond and iFirst == iSecond:
            originalplaintext.append(keyMatrix[(iFirst - 1) % 5][(jFirst - 1) % 5])
            originalplaintext.append(keyMatrix[(iFirst - 1) % 5][(jFirst - 1) % 5])
        elif iFirst == iSecond:
            originalplaintext.append(keyMatrix[iFirst][(jFirst - 1) % 5])
            originalplaintext.append(keyMatrix[iFirst][(jSecond - 1) % 5])
        elif jFirst == jSecond:
            originalplaintext.append(keyMatrix[(iFirst - 1) % 5][jFirst])
            originalplaintext.append(keyMatrix[(iSecond - 1) % 5][jFirst])
        else:
            originalplaintext.append(keyMatrix[iFirst][jSecond])
            originalplaintext.append(keyMatrix[iSecond][jFirst])
        idx = idx + 2


if __name__ == '__main__':
    print("\n-------- Playfair Cipher --------\n")
    print("1. Encryption\n2. Decryption")
    actionType = input("Enter the action (1 / 2): ")
    if actionType == "1":
        originalplaintext = input("Enter the plaintext: ")
        modifiedplaintext = list(originalplaintext.upper().replace(" ", "").replace("J", "I"))
        format_plaintext()

        key = input("Enter the key: ")
        originalKey = ''.join(key)
        key = list(dict.fromkeys(key.upper().replace(" ", "").replace("J", "I")))
        set_key_matrix(len(key))

        playfair_cipher_encrypt()
        print("\nYour plaintext: {}".format(originalplaintext))
        print("Your plaintext after edit:")
        print(modifiedplaintext)
        print("\nYour key: {}".format(originalKey))
        print("The key matrix:")
        print(keyMatrix)
        print("\nEncryption result:")
        print(''.join(ciphertext))
    elif actionType == "2":
        ciphertext = input("Enter the ciphertext: ").upper()
        key = input("Enter the key: ")
        originalKey = ''.join(key)
        key = list(dict.fromkeys(key.upper().replace(" ", "").replace("J", "I")))
        set_key_matrix(len(key))

        playfair_cipher_decrypt()
        print("\nYour ciphertext: {}".format(ciphertext))
        print("\nYour key: {}".format(originalKey))
        print("The key matrix:")
        print(keyMatrix)
        print("\nDecryption result:")
        print(''.join(originalplaintext))
    else:
        print("Command not found!\n")
