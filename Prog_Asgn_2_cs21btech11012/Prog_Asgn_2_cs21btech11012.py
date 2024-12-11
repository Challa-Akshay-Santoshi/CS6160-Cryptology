# Execute using the command 
# python3 Prog_Asgn_2_cs21btech11012.py

# Akshay Santoshi
# CS21BTECH11012


import os
import random
from collections import Counter
import json



# Pseudo-Random Generation Algorithm (PRGA)
# The function returns a list of length m containing the generated keystream values
def pseudo_random_generation(S, m):
    i = 0
    j = 0
    keystream = []
    for _ in range(m):
        i = (i + 1) % 2**5
        j = (j + S[i]) % 2**5
        S[i], S[j] = S[j], S[i]  
        keystream.append(S[(S[i] + S[j]) % 2**5])
    return keystream




# Key Schedule Algorithm (KSA)
# The function returns the modified S array
def key_schedule_algorithm(K):
    S = list(range(2**5))
    j = 0
    l = len(K)
    for i in range(2**5):
        j = (j + S[i] + K[i % l]) % 2**5
        S[i], S[j] = S[j], S[i]  
    return S


# Generates a random key
def random_key():
    return [int.from_bytes(os.urandom(1), 'big') for _ in range(5)]




def keystream_distribution():

    print("Keystreams are getting generated.....")
    # To store counts for each keystream byte position
    position_counts = [Counter() for _ in range(6)]

    # This loop generates 2^24 keystreams using random key
    for _ in range(2**24):
        K = random_key()
        S = key_schedule_algorithm(K)
        keystream = pseudo_random_generation(S, 6)
        
        # Count occurrences for each byte position
        for pos in range(6):
            position_counts[pos][keystream[pos]] += 1

    # print(position_counts)
    print("Keystreams have been generated")

    # For each position, we calculate the probability distribution from the counts
    position_probs = []
    for counter in position_counts:
        total = sum(counter.values())
        position_probs.append({k: v / total for k, v in counter.items()})

    # print(position_probs)
    
    return position_probs


# Loading ciphertexts from files
def load_ciphertexts(ciphertext_directory):
    print("Ciphertexts are being loaded.....")
    ciphertexts = []
    for file_num in range(1, 4097):  
        file_path = os.path.join(ciphertext_directory, f"ciphertexts_{file_num}.txt")
        with open(file_path, 'r') as file:
            for line in file:
                ciphertext = list(map(int, line.strip()[1:-1].split(', ')))
                ciphertexts.append(ciphertext)
    return ciphertexts


# The function computes the distribution of XOR results for a guess at a specified position in the passcode
def calculate_xor_distribution(ciphertexts, guess, position):
    xor_results = [ciphertext[position] ^ guess for ciphertext in ciphertexts]
    counter = Counter(xor_results)
    total = sum(counter.values())
    return {k: v / total for k, v in counter.items()}


# The function check if two distributions match within 0.0003
def distributions_match(dist1, dist2):
    for k in dist1:
        if abs(dist1.get(k, 0) - dist2.get(k, 0)) > 0.0003:
            return False
    return True


# The function returns the passcode after comparing distributions
def guess_passcode(keystream_probs,ciphertexts):

    print("Retrieval of encrypted passcode in progress......")
    passcode = []


    # For each position in the passcode, guesses digits 0-9 by calculating the XOR distribution
    for position in range(6):
        for guess in range(10):  

            ascii_guess = ord(str(guess))
            # Calculate distribution for XORing this guess at the current position
            xor_distribution = calculate_xor_distribution(ciphertexts, ascii_guess, position)
            # print(xor_distribution)
            
            # Compare each calculated XOR distribution with the precomputed keystream distribution for that position
            if distributions_match(xor_distribution, keystream_probs[position]):
                passcode.append(guess)
                break
    
    return passcode

# def guess_passcode(ciphertexts, output_file="xor_distributions.txt"):
#     passcode = []

#     with open(output_file, 'w') as file:
#         for position in range(6):
#             file.write(f"Position {position}:\n")  # Indicate which passcode position

#             for guess in range(10):  # Digits from 0 to 9

#                 ascii_guess = ord(str(guess))
#                 # Calculate distribution for XORing this guess at the current position
#                 xor_distribution = calculate_xor_distribution(ciphertexts, ascii_guess, position)
                
#                 file.write(f"  Guess {guess}: {json.dumps(xor_distribution, indent=4)}\n")
                

#                 # if distributions_match(xor_distribution, keystream_probs[position]):
#                 #     passcode.append(guess)
#                 #     break
    
#     return passcode


def main():
    ciphertext_directory = "./Ciphertexts/"

    keystream_probs = keystream_distribution()

    # print(keystream_probs)

    # filename="keystream_probs.txt"

    # with open(filename, 'w') as file:
    #     json.dump(keystream_probs, file, indent=4)

    ciphertexts = load_ciphertexts(ciphertext_directory)

    # print(ciphertexts)

    passcode = guess_passcode(keystream_probs, ciphertexts)
    # passcode = guess_passcode(ciphertexts, output_file="xor_distributions.txt")

    print(passcode)

if __name__ == "__main__":
    main()