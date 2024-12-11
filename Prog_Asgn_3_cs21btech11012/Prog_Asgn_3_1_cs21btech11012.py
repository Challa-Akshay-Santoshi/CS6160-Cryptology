# Execute using the command
# python3 Prog_Asgn_3_1_cs21btech11012.py

# Akshay Santoshi
# CS21BTECH11012

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def expandKey(shortKey):    
    shortKeyval1=shortKey[0]
    shortKeyval2=shortKey[1]
    #Last four bits are ignored
    shortKeyval3=shortKey[2]&0xF0
    
    ByteA=shortKeyval1.to_bytes(1,"big")
    ByteB=shortKeyval2.to_bytes(1,"big")
    ByteC=shortKeyval3.to_bytes(1,"big")
    hexByte1=0x94
    Byte1=hexByte1.to_bytes(1,"big")
    hexByte2=0x5a
    Byte2=hexByte2.to_bytes(1,"big")
    hexByte3=0xe7
    Byte3=hexByte3.to_bytes(1,"big")
    
    longKey=bytearray(ByteA)    
    longKey.extend(Byte1)
    longKey.extend(ByteB)    
    longKey.extend(Byte2)
    
    for i in range(4,9):        
        hexByte=(longKey[i-1]+longKey[i-4])%257
        if (hexByte==256):
            hexByte=0
        Byte=hexByte.to_bytes(1,"big")              
        longKey.extend(Byte)
    longKey.extend(ByteC)   
    longKey.extend(Byte3)
    for i in range(11,16):
        hexByte=(longKey[i-1]+longKey[i-4])%257
        if (hexByte==256):
            hexByte=0
        Byte=hexByte.to_bytes(1,"big")              
        longKey.extend(Byte)    
    
    return longKey

def aes_decrypt(ciphertext, key):
    iv = b'\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0'
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))

    decryptor = cipher.decryptor()
    
    decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
    
    return decrypted_data

# This function is used for getting a byte sequence(short key) from the key_guess
def gen_short_key(key_guess, short_key_length=3):
    short_key = [0] * short_key_length
    for i in range(short_key_length - 1, -1, -1):
        short_key[i] = key_guess & 0xff
        key_guess >>= 8
    return bytes(short_key)

# This function first generates short key from the key_guess,
# then it expands it to a long key and then tries to decrypt 
# the known ciphertext
def brute_force_decrypt(given_ciphertext, key_guess):
    short_key = gen_short_key(key_guess)
    long_key = expandKey(short_key)
    given_ciphertext = bytes(given_ciphertext)
    return aes_decrypt(given_ciphertext, long_key)

def main():
    plaintexts_file = "aesPlaintexts.txt"
    ciphertexts_file = "aesCiphertexts.txt"
    print("Computing!! Please wait....")
    plaintexts = []
    ciphertexts = []

    with open(plaintexts_file, 'r') as file:
        for line in file:
            byte_array = list(line.strip().encode('utf-8'))
            plaintexts.append(byte_array)

    with open(ciphertexts_file, 'r') as file:
        for line in file:
            hex_str = line.strip()
            byte_array = [int(hex_str[i:i+2], 16) for i in range(0, len(hex_str), 2)]
            ciphertexts.append(byte_array)

    i = 0
    found_key = None

    # Iterates through all possible 2^20 key_guesses, generates keys,
    # expands them and attempts to decrypt the first ciphertext. If
    # it matches the first plaintext, it identifies the key.
    while i < (1 << 20):
        decrypted_bytes = brute_force_decrypt(ciphertexts[0], i << 4)
        decrypted_text = list(decrypted_bytes)
        if decrypted_text == plaintexts[0]:
            print("20-bit key: " + hex(i))
            short_key = gen_short_key(i << 4)
            long_key = expandKey(short_key)
            print("128-bit expanded key: ", long_key.hex())
            found_key = i << 4
            break
        i += 1

    if found_key is None:
        print("NO KEY FOUND!!")
        return -1

    short_key = gen_short_key(found_key)
    long_key = expandKey(short_key)

    all_match = True
    for j, ciphertext in enumerate(ciphertexts[:-1]):  
        decrypted_bytes = aes_decrypt(bytes(ciphertext), long_key)
        decrypted_text = list(decrypted_bytes)

        if decrypted_text != plaintexts[j]:
            print(f"Mismatch found for ciphertext index {j}!")
            all_match = False
            break

    if all_match:
        print("Verification successful: All plaintexts match their corresponding ciphertexts!!")
    else:
        print("Verification failed: The key does not encrypt all plaintexts correctly!!")



    secret_plaintext = brute_force_decrypt(ciphertexts[-1], found_key)
    if secret_plaintext:
        print("Secret plaintext:", secret_plaintext.decode('utf-8'))
    else:
        print("COULDN'T FIND THE DECRYPTION OF THE CIPHERTEXT!!")

if __name__ == "__main__":
    main()