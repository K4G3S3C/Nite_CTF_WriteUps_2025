"""
SHA-1 Length Extension Attack Implementation.

This module implements the SHA-1 length extension attack primitives required to
forge MACs of the form sha1(secret || message) when the hash function uses raw
"""

#!/usr/bin/env python3
import struct
import hashlib


"""
    Generate SHA-1 MD-strengthening padding for a message of given length (in bytes).
    SHA-1 padding rules:
    - Append a single '1' bit (0x80 byte).
    - Append '0' bits until the message length (in bytes) is congruent to 56 mod 64.
    - Append the original message length in bits as a 64-bit big-endian integer.
    Args:
        msg_len: int, message length in bytes BEFORE padding.
    Returns:
        bytes: padding that makes (msg_len + len(padding)) a multiple of 64, with
               the final 8 bytes encoding the original bit length.
"""
def sha1_padding(msg_len):
    ml_bits = msg_len * 8
    padding = b'\x80'
    padding += b'\x00' * ((56 - (msg_len + 1) % 64) % 64)
    padding += struct.pack('>Q', ml_bits)
    return padding


"""
    Perform a SHA-1 length extension attack.
    Given the SHA-1 digest of (secret || original_data), compute the SHA-1 digest of
    (secret || original_data || padding || append_data) without knowing 'secret'.
    Args:
        original_hash_hex: str, 40 hex chars of the original SHA-1 digest.
        original_data: bytes, known suffix of the original message (e.g., b"username|amount").
        append_data: bytes, attacker-chosen suffix to append (e.g., b"|1000000000").
        secret_length: int, assumed length of the unknown 'secret' prefix in bytes.
    Returns:
        (new_hash_hex, new_data): tuple
            new_hash_hex: str, hex digest of the forged message under SHA-1.
            new_data: bytes, forged message suffix sent to the server (original_data + padding + append_data).
"""
def sha1_extend(original_hash_hex, original_data, append_data, secret_length):
    h = [int(original_hash_hex[i:i + 8], 16) for i in range(0, 40, 8)]
    original_msg_len = secret_length + len(original_data)
    padding = sha1_padding(original_msg_len)
    new_data = original_data + padding + append_data
    new_hash = sha1_extend_hash(h, append_data, previous_length=original_msg_len + len(padding))
    return new_hash.hex(), new_data


"""
    Continue SHA-1 hashing from a custom initial state over 'data',
    taking into account 'previous_length' bytes already hashed.
    Args:
        initial_state: list of 5 ints (32-bit), representing h0..h4 extracted from the original digest.
        data: bytes, the attacker-chosen suffix to process.
        previous_length: int, total bytes already hashed before 'data', including SHA-1 padding of the original message.
    Returns:
        bytes: final SHA-1 digest (20 bytes).
"""
def sha1_extend_hash(initial_state, data, previous_length):
    h0, h1, h2, h3, h4 = initial_state
    total_length = previous_length + len(data)
    padded_data = data + sha1_padding(total_length)
    for i in range(0, len(padded_data), 64):
        block = padded_data[i:i + 64]
        if len(block) < 64:
            break
        h0, h1, h2, h3, h4 = sha1_process_block(block, h0, h1, h2, h3, h4)
    return struct.pack('>5I', h0, h1, h2, h3, h4)


"""
    Process a single 64-byte block for SHA-1 with given state.
    Args:
        block: 64-byte bytes object
        h0..h4: current 32-bit state words
    Returns:
        Updated h0..h4 after processing the block.
"""
def sha1_process_block(block, h0, h1, h2, h3, h4):
    w = list(struct.unpack('>16I', block)) + [0] * 64
    for i in range(16, 80):
        w[i] = _left_rotate(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1)
    a, b, c, d, e = h0, h1, h2, h3, h4
    for i in range(80):
        if i < 20:
            f = (b & c) | ((~b) & d)
            k = 0x5A827999
        elif i < 40:
            f = b ^ c ^ d
            k = 0x6ED9EBA1
        elif i < 60:
            f = (b & c) | (b & d) | (c & d)
            k = 0x8F1BBCDC
        else:
            f = b ^ c ^ d
            k = 0xCA62C1D6
        temp = (_left_rotate(a, 5) + f + e + k + w[i]) & 0xffffffff
        e = d
        d = c
        c = _left_rotate(b, 30)
        b = a
        a = temp
    h0 = (h0 + a) & 0xffffffff
    h1 = (h1 + b) & 0xffffffff
    h2 = (h2 + c) & 0xffffffff
    h3 = (h3 + d) & 0xffffffff
    h4 = (h4 + e) & 0xffffffff
    return h0, h1, h2, h3, h4


"""Left rotate a 32-bit integer n by b bits."""
def _left_rotate(n, b):
    n &= 0xffffffff
    return ((n << b) | (n >> (32 - b))) & 0xffffffff
if __name__ == '__main__':
    secret = "mysecret"
    original_data = b"A|5"
    message = secret.encode() + original_data
    original_hash = hashlib.sha1(message).hexdigest()
    print(f"Original message: {message}")
    print(f"Original hash: {original_hash}")
    append_data = b"|1000000000"
    new_hash, new_data = sha1_extend(
        original_hash,
        original_data,
        append_data,
        len(secret)
    )
    print(f"\nNew data (suffix sent by attacker): {new_data}")
    print(f"New hash: {new_hash}")
    test_message = secret.encode() + new_data
    test_hash = hashlib.sha1(test_message).hexdigest()
    print(f"\nVerification hash: {test_hash}")
    print(f"Hashes match: {test_hash == new_hash}")
