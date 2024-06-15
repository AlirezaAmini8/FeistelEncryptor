import os
from hashlib import sha3_512

BLOCK_SIZE = 16  # Block size in bytes (128 bits)
KEY_SIZE = 32  # Key size in bytes (256 bits)
NUM_ROUNDS = 15  # Number of rounds
S_BOX = list(range(256))  # Simple S-box for demonstration


def sha3_hash(data):
    return sha3_512(data).digest()


def expand_key(master_key):
    hash_output = sha3_hash(master_key)
    subkeys = [hash_output[i:i + BLOCK_SIZE] for i in range(0, len(hash_output), BLOCK_SIZE)[:NUM_ROUNDS]]
    return subkeys


def round_function(data, subkey):
    L, R = data[:BLOCK_SIZE // 2], data[BLOCK_SIZE // 2:]

    # Expansion
    expanded = R + R[:BLOCK_SIZE // 4]  # Expand to 1.5 times the original size

    # Substitution and XOR with subkey
    substituted = bytes(S_BOX[b ^ subkey[i % len(subkey)]] for i, b in enumerate(expanded))

    # Simple permutation (rotate bytes)
    permuted = substituted[1:] + substituted[:1]

    # Contraction
    contracted = permuted[:BLOCK_SIZE // 2]

    # Final XOR with the left half
    new_R = bytes([x ^ y for x, y in zip(contracted, L)])
    return R, new_R


def encrypt(plaintext, key):
    assert len(plaintext) == BLOCK_SIZE
    subkeys = expand_key(key)

    L, R = plaintext[:BLOCK_SIZE // 2], plaintext[BLOCK_SIZE // 2:]

    for subkey in subkeys:
        L, R = round_function(L + R, subkey)

    final_data = L + R

    final_key_part = sha3_hash(key)[:BLOCK_SIZE]
    encrypted = bytes([x ^ y for x, y in zip(final_data, final_key_part)])
    return encrypted


key = os.urandom(KEY_SIZE)
plaintext = os.urandom(BLOCK_SIZE)
ciphertext = encrypt(plaintext, key)
print("Plaintext:", plaintext.hex())
print("Ciphertext:", ciphertext.hex())
