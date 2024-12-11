# Execute using the command
# python3 Prog_Asgn_1_cs21btech11012.py

# Akshay Santoshi
# CS21BTECH11012


def validity(result):
    # To check if the xor result is valid, i.e. it has to be either an alphabet character or space.
    return (0x61 <= result <= 0x7A) or (0x41 <= result <= 0x5A) or result == 0

def check_space(var, chars):
    # SPACE xor SPACE is 0
    # SPACE xor [a-z] is [A-Z]
    # SPACE xor [A-Z] is [a-z]
    for temp in chars:
        result = temp ^ var
        if not validity(result):
            return False
    return True

def xor(b1, b2):
    # Used to xor two byte strings
    return bytes([x ^ y for x, y in zip(b1, b2)])

def ciphertexts_to_bytes(file_path):
    # Reads ciphertexts from the Set2 file and converts them (hex) into bytes line by line. 
    ciphertexts = []
    with open(file_path, "r") as f:
        for line in f:
            line = line.strip()
            ciphertext_bytes = bytes.fromhex(line)
            ciphertexts.append(ciphertext_bytes)
    return ciphertexts

def dictionary_to_bytes(file_path):
    # Reads the file dictionary.txt and converts each line into a byte-encoded string using UTF-8 encoding.
    with open(file_path, "r") as f:
        dictionary = [line.strip().encode('utf-8') for line in f]
    return dictionary

def find_k1(ciphertexts, dictionary):

    # We iterate through the plain texts present in the dictionary
    for plain_text in dictionary:

        # We guess the key by xoring 'plain_text' with the first 15 bytes of the first ciphertext. (16th byte is SPACE)
        key_k1 = xor(ciphertexts[0][:15], plain_text)
        flag = True

        # We validate the guessed key against all cipher texts to check if it decrypts correctly to words in the dictionary.
        for temp in ciphertexts:
            result = xor(temp[:15], key_k1)
            if result not in dictionary:
                flag = False
                break

        if flag:
            return key_k1

    return None

def find_k2(ciphertexts):
    # Calculates the length of the key k2 based on the longest ciphertext
    cipher_length = max(len(temp) for temp in ciphertexts)
    length = cipher_length - 15 
    k2 = bytearray(length)
    
    # Iterate over each position to identify possible spaces
    for pos in range(15, cipher_length):
        spaces_array = []
        
        # Store the possible SPACE characters in the array
        for i in range(len(ciphertexts)):

            # PERIOD ('.') is present at the end of each sentence
            if (len(ciphertexts[i]) == pos+1):
                k2[pos - 15] = ciphertexts[i][pos] ^ 0x2E # ASCII of '.' is 0x2E
            else:
                if len(ciphertexts[i]) > pos:
                    spaces_array.append(ciphertexts[i][pos])

        if(len(spaces_array) > 3):

            # Analyze each byte position from the spaces_array to check the validity of SPACE
            for char in spaces_array:
                if check_space(char, spaces_array):
                    k2[pos - 15] = char ^ 0x20  # ASCII of space is 0x20
                    break

    return k2

def update_k2_with_guess(ciphertext, k2, pos, guessed_char):
    """Update K2 with a guessed character at a specific position."""
    ciphertext_byte = ciphertext[pos]
    guessed_byte = ord(guessed_char)
    k2_byte = ciphertext_byte ^ guessed_byte
    k2[pos - 15] = k2_byte
    return k2


def decrypt_messages(ciphertexts, k1, k2):
    decrypted_messages = []
    for temp in ciphertexts:
        # Decrypt the first 16 bytes using K1 (1 excluded for SPACE)
        plaintext = xor(temp[:15], k1)
        
        # Decrypt the remaining bytes using K2
        for i in range(15, len(temp)):

            # If corresponding K2 byte is 0, we want to print "?" at that position to the plain text
            # to indicate that this position of K2 is yet to be determined.
            if(k2[i-15]==0):
                plaintext += b"?"
            else:
                # Otherwise decrypt it by xoring cipher text byte with that of K2.
                plaintext += bytes([temp[i] ^ k2[i - 15]])
        
        decrypted_messages.append(plaintext)
    return decrypted_messages

def main():
    # Read the ciphertext file and dictionary file
    ciphertexts = ciphertexts_to_bytes("Set2_streamciphertexts.txt")  
    dictionary = dictionary_to_bytes("dictionary.txt")  

    # To find the key K1
    k1 = find_k1(ciphertexts, dictionary)
    if k1 is None:
        print("No valid K1 key is present in the dictionary")
        return

    print("K1 key:", k1.hex())

    # To find the key K2
    k2 = find_k2(ciphertexts)
    print("Partial K2 key:", k2.hex())

    # NOTE
    # AFTER FINDING K2 USING find_k2(), YOU WOULD ONLY BE GETTING PARTIAL K2
    # THE REMAINING PLACES OF THE KEY K2 CAN BE EASILY GUESSED BY LOOKING AT THE
    # PLAIN TEXT WHICH WE HAVE DECRYPTED USING THE COMBINED K1 AND PARTIAL K2.
    # IN THE OUTPUT TERMINAL AS CAN BE SEEN AFTER THE PROGRAM HAS BEEN EXECUTED,
    # THERE ARE '?' CHARACTERS IN THE OUTPUT. THESE INDICATE THAT, THE POSITION IS YET TO BE DETERMINED.
    # BUT THESE CAN BE GUESSED. 
    # FOR EXAMPLE:  bio?og?sts and i?terpre?ation CAN BE EASILY IDENTIFIED AS biologists AND interpretation.
    # SO K2 CAN BE IDENTIFIED.
    # THE FINAL K1, K2 AND COMPLETE PLAIN TEXTS ARE PRESENT IN THE Prog_Asgn_1_cs21btech11012.txt FILE.

    # Decrypt messages

    print("\n********** INITIALLY OBTAINED DECRYPTED PLAINTEXTS: **********\n")

    plain_texts = decrypt_messages(ciphertexts, k1, k2)
    for message in plain_texts:
        print(message.decode('utf-8', errors='replace'))

    # In first plaintext obtained 'th?y' can be guessed as 'they'
    k2 = update_k2_with_guess(ciphertexts[0], k2, 26, 'e')

    # In first plaintext obtained '?aught' can be guessed as 'caught'
    k2 = update_k2_with_guess(ciphertexts[0], k2, 29, 'c')

    # In first plaintext obtained '?f' can be guessed as 'of'
    k2 = update_k2_with_guess(ciphertexts[0], k2, 36, 'o')

    # In first plaintext obtained 'dar?ed' can be guessed as 'darted'
    k2 = update_k2_with_guess(ciphertexts[0], k2, 57, 't')

    # In first plaintext obtained 'b?ck' can be guessed as 'back'
    k2 = update_k2_with_guess(ciphertexts[0], k2, 62, 'a')

    # In first plaintext obtained 't?e' can be guessed as 'the'
    k2 = update_k2_with_guess(ciphertexts[0], k2, 90, 'h')

    # In first plaintext obtained '?eachcomb?rs' can be guessed as 'beachcombers'
    k2 = update_k2_with_guess(ciphertexts[0], k2, 93, 'b')
    k2 = update_k2_with_guess(ciphertexts[0], k2, 102, 'e')

    # In first plaintext obtained 'wit?' can be guessed as 'with'
    k2 = update_k2_with_guess(ciphertexts[0], k2, 109, 'h')

    # In first plaintext obtained 'fl?eting' can be guessed as 'fleeting'
    k2 = update_k2_with_guess(ciphertexts[0], k2, 120, 'e')

    # In first plaintext obtained 'impressio?' can be guessed as 'impression'
    k2 = update_k2_with_guess(ciphertexts[0], k2, 136, 'n')

    # In first plaintext obtained 'c??cking' can be guessed as 'clicking'
    k2 = update_k2_with_guess(ciphertexts[0], k2, 142, 'l')
    k2 = update_k2_with_guess(ciphertexts[0], k2, 143, 'i')

    # In first plaintext obtained 'a?d' can be guessed as 'and'
    k2 = update_k2_with_guess(ciphertexts[0], k2, 157, 'n')

    # In first plaintext obtained 'mo?tled' can be guessed as 'mottled'
    k2 = update_k2_with_guess(ciphertexts[0], k2, 164, 't')

    # In second plaintext obtained 'i???ntory' can be guessed as 'inventory'
    k2 = update_k2_with_guess(ciphertexts[1], k2, 85, 'n')
    k2 = update_k2_with_guess(ciphertexts[1], k2, 86, 'v')
    k2 = update_k2_with_guess(ciphertexts[1], k2, 87, 'e')

    # In second plaintext obtained 'cust??er?' can be guessed as 'customers'
    k2 = update_k2_with_guess(ciphertexts[1], k2, 153, 'o')
    k2 = update_k2_with_guess(ciphertexts[1], k2, 154, 'm')

    # In third plaintext obtained 'i?' can be guessed as 'in'
    k2 = update_k2_with_guess(ciphertexts[2], k2, 160, 'n')

    # In fourth plaintext obtained '?er' can be guessed as 'her'
    k2 = update_k2_with_guess(ciphertexts[3], k2, 73, 'h')

    # In tenth plaintext obtained '???arium' can be guessed as 'aquarium'
    k2 = update_k2_with_guess(ciphertexts[9], k2, 16, 'a')
    k2 = update_k2_with_guess(ciphertexts[9], k2, 17, 'q')
    k2 = update_k2_with_guess(ciphertexts[9], k2, 18, 'u')

    print("\n********** PLAINTEXTS AND KEY2 AFTER FIRST ROUND OF GUESSING: **********\n")
    print("Partial K2 key:", k2.hex())
    print("\n")
    plain_texts = decrypt_messages(ciphertexts, k1, k2)
    for message in plain_texts:
        print(message.decode('utf-8', errors='replace'))

    # In first plaintext obtained '?eaving' can be guessed as 'leaving'
    k2 = update_k2_with_guess(ciphertexts[0], k2, 81, 'l')

    # In fifth plaintext obtained 'onc?' can be guessed as 'once'
    k2 = update_k2_with_guess(ciphertexts[4], k2, 77, 'e')

    print("\n********** PLAINTEXTS AND KEY2 AFTER SECOND ROUND OF GUESSING: **********\n")
    print("Partial K2 key:", k2.hex())
    print("\n")
    plain_texts = decrypt_messages(ciphertexts, k1, k2)
    for message in plain_texts:
        print(message.decode('utf-8', errors='replace'))

    # In twelfth plaintext obtained 'mult??le' can be guessed as 'multiple'
    k2 = update_k2_with_guess(ciphertexts[11], k2, 78, 'i')
    k2 = update_k2_with_guess(ciphertexts[11], k2, 79, 'p')

    print("\n********** PLAINTEXTS AND KEY2 AFTER THIRD ROUND OF GUESSING: **********\n")
    print("Partial K2 key:", k2.hex())
    print("\n")
    plain_texts = decrypt_messages(ciphertexts, k1, k2)
    for message in plain_texts:
        print(message.decode('utf-8', errors='replace'))

    # In ninth plaintext obtained '???ptability' can be guessed as 'adaptability'
    k2 = update_k2_with_guess(ciphertexts[8], k2, 69, 'a')
    k2 = update_k2_with_guess(ciphertexts[8], k2, 70, 'd')
    k2 = update_k2_with_guess(ciphertexts[8], k2, 71, 'a')

    print("\n********** PLAINTEXTS AND KEY2 AFTER FOURTH ROUND OF GUESSING: **********\n")
    print("Partial K2 key:", k2.hex())
    print("\n")
    plain_texts = decrypt_messages(ciphertexts, k1, k2)
    for message in plain_texts:
        print(message.decode('utf-8', errors='replace'))

    # In eigth plaintext obtained 's???imens' can be guessed as 'specimens'
    k2 = update_k2_with_guess(ciphertexts[7], k2, 65, 'p')
    k2 = update_k2_with_guess(ciphertexts[7], k2, 66, 'e')
    k2 = update_k2_with_guess(ciphertexts[7], k2, 67, 'c')   

    # In third plaintext obtained 'pet??' can be guessed as 'petty'
    k2 = update_k2_with_guess(ciphertexts[2], k2, 170, 't')
    k2 = update_k2_with_guess(ciphertexts[2], k2, 171, 'y')

    print("\n********** PLAINTEXTS AND KEY2 AFTER FIFTH ROUND OF GUESSING: **********\n")
    print("Partial K2 key:", k2.hex())
    print("\n")
    plain_texts = decrypt_messages(ciphertexts, k1, k2)
    for message in plain_texts:
        print(message.decode('utf-8', errors='replace'))

    # In ninth plaintext obtained 'wav??.' can be guessed as 'waves.'
    k2 = update_k2_with_guess(ciphertexts[8], k2, 172, 'e')
    k2 = update_k2_with_guess(ciphertexts[8], k2, 173, 's')

    print("\n********** PLAINTEXTS AND KEY2 AFTER SIXTH ROUND OF GUESSING: **********\n")
    print("Partial K2 key:", k2.hex())
    print("\n")
    plain_texts = decrypt_messages(ciphertexts, k1, k2)
    for message in plain_texts:
        print(message.decode('utf-8', errors='replace'))

    # In third plaintext obtained 'deb????' can be guessed as 'debates'
    k2 = update_k2_with_guess(ciphertexts[2], k2, 176, 'a')
    k2 = update_k2_with_guess(ciphertexts[2], k2, 177, 't')
    k2 = update_k2_with_guess(ciphertexts[2], k2, 178, 'e')
    k2 = update_k2_with_guess(ciphertexts[2], k2, 179, 's')


    print("\n********** FINAL DECRYPTED PLAINTEXTS AND KEYS OBTAINED ARE **********\n")

    print("K1 key:", k1.hex())
    print("K2 key:", k2.hex())
    print("\n")
    plain_texts = decrypt_messages(ciphertexts, k1, k2)
    for message in plain_texts:
        print(message.decode('utf-8', errors='replace'))


        

if __name__ == "__main__":
    main()
