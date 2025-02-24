#!/usr/bin/env python3

import sys, requests
from urllib.parse import urljoin

BLOCK_SIZE = 16

def oracle(ciphertext: bytes, base_url: str) -> bool:
    url = urljoin(base_url, '/quote/')
    cookies = {'authtoken': ciphertext.hex()}
    try:
        resp = requests.get(url, cookies=cookies, timeout=5)
    except Exception as e:
        print("Error connecting to server:", e)
        return False

    text = resp.text
    print("DEBUG response:", text)
    # Treat any response mentioning "incorrect" (in any case) as invalid padding.
    if "incorrect" in text.lower():
        return False
    return True

def split_blocks(data: bytes, block_size: int = BLOCK_SIZE):
    """Splits data into blocks of block_size."""
    return [data[i:i+block_size] for i in range(0, len(data), block_size)]

def decrypt_block(prev_block: bytes, curr_block: bytes, base_url: str) -> bytes:
    intermediate = bytearray(BLOCK_SIZE)
    recovered = bytearray(BLOCK_SIZE)
    modified_prev = bytearray(prev_block)
    
    for pos in range(BLOCK_SIZE - 1, -1, -1):
        pad_byte = BLOCK_SIZE - pos
        # Adjust already recovered positions
        for i in range(pos+1, BLOCK_SIZE):
            modified_prev[i] = intermediate[i] ^ pad_byte
        
        found = False
        for guess in range(256):
            modified_prev[pos] = guess
            test_ct = bytes(modified_prev) + curr_block
            if oracle(test_ct, base_url):
                intermediate[pos] = guess ^ pad_byte
                recovered[pos] = intermediate[pos] ^ prev_block[pos]
                found = True
                print(f"DEBUG: Found valid guess at position {pos}: guess={guess}, pad_byte={pad_byte}, intermediate={intermediate[pos]:02x}")
                break
        if not found:
            # Print state for debugging before failing
            print(f"DEBUG: Failed at position {pos}. Modified_prev: {modified_prev.hex()}")
            raise Exception("Failed to find a valid padding byte. (position %d)" % pos)
    return bytes(recovered)

def decrypt_ciphertext(ciphertext: bytes, base_url: str) -> bytes:
    """
    Decrypts an entire ciphertext (which includes IV as first block)
    using the padding oracle attack.
    """
    blocks = split_blocks(ciphertext, BLOCK_SIZE)
    if len(blocks) < 2:
        raise Exception("Ciphertext must be at least two blocks long (IV + one ciphertext block)")
    plaintext = b''
    # Process block-by-block: for each block, use the previous block as the “IV”
    for i in range(1, len(blocks)):
        plain_block = decrypt_block(blocks[i-1], blocks[i], base_url)
        plaintext += plain_block
    return plaintext

def encrypt_block(desired_plain: bytes, next_block: bytes, base_url: str) -> bytes:
    """
    Given a desired plaintext block (16 bytes) and an arbitrary next ciphertext block,
    this function computes a preceding ciphertext block C_prev such that when the oracle
    decrypts (C_prev, next_block) it yields desired_plain.
    
    Recall that in CBC mode:
         D_K(next_block) XOR C_prev = desired_plain.
    We can recover I = D_K(next_block) using a padding oracle attack on (dummy, next_block)
    then compute:
         C_prev = I XOR desired_plain.
    """
    # Create a dummy block (we can start with zeros)
    dummy = bytearray(BLOCK_SIZE)
    # Recover intermediate state I for next_block using our decryption procedure.
    # We run the decryption attack on (dummy, next_block). Note that dummy is arbitrary;
    # the attack will “fix” it by iterating over all positions.
    intermediate = bytearray(BLOCK_SIZE)
    modified_dummy = bytearray(dummy)
    
    for pos in range(BLOCK_SIZE - 1, -1, -1):
        pad_byte = BLOCK_SIZE - pos
        for i in range(pos+1, BLOCK_SIZE):
            modified_dummy[i] = intermediate[i] ^ pad_byte
        found = False
        for guess in range(256):
            modified_dummy[pos] = guess
            test_ct = bytes(modified_dummy) + next_block
            if oracle(test_ct, base_url):
                intermediate[pos] = guess ^ pad_byte
                found = True
                break
        if not found:
            raise Exception("Encryption oracle: Failed at position %d" % pos)
    
    # Now that we have I = D_K(next_block), compute the required preceding block:
    C_prev = bytes([intermediate[i] ^ desired_plain[i] for i in range(BLOCK_SIZE)])
    return C_prev

def encrypt_plaintext(plaintext: bytes, base_url: str) -> bytes:
    """
    Encrypts an arbitrary plaintext (of any length) using the padding oracle
    to create a valid ciphertext. This is done block by block.
    
    The process is as follows:
     1. Pad the plaintext (PKCS#7) to a multiple of BLOCK_SIZE.
     2. Choose a random final block (C_n).
     3. For each block from last to first, compute the preceding ciphertext block
        using the oracle encryption method.
        
    Finally, the IV is the first computed block.
    
    Returns the complete ciphertext (IV || C1 || ... || Cn).
    """
    from os import urandom
    padded = pkcs7_pad(plaintext, BLOCK_SIZE)
    blocks = [padded[i:i+BLOCK_SIZE] for i in range(0, len(padded), BLOCK_SIZE)]
    
    # Choose a random final ciphertext block.
    C_next = urandom(BLOCK_SIZE)
    ciphertext_blocks = [C_next]  # This will eventually be reversed.
    
    # Process blocks in reverse order (last plaintext block first)
    for plain_block in reversed(blocks):
        C_prev = encrypt_block(plain_block, C_next, base_url)
        ciphertext_blocks.append(C_prev)
        C_next = C_prev
    # The ciphertext is the reverse of the computed blocks.
    ciphertext_blocks.reverse()
    return b''.join(ciphertext_blocks)

def pkcs7_pad(data: bytes, block_size: int) -> bytes:
    """Apply PKCS#7 padding."""
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)

def extract_secret(plaintext: bytes) -> str:
    """
    Given the decrypted plaintext from the index page (which is of the form:
       b'You never figure out that "<secret>". :)'
    extract and return the secret string.
    """
    text = plaintext.decode()
    # Find text within quotes
    start = text.find('"')
    end = text.rfind('"')
    if start == -1 or end == -1 or end <= start:
        raise Exception("Secret not found in plaintext!")
    return text[start+1:end]

def main():
    if len(sys.argv) != 2:
        print("Usage: {} <base_url>".format(sys.argv[0]))
        sys.exit(1)
    base_url = sys.argv[1].rstrip('/')
    
    # Step 1: Get a valid token from the index page.
    try:
        resp = requests.get(urljoin(base_url, '/'))
    except Exception as e:
        print("Error connecting to base URL:", e)
        sys.exit(1)
    
    token_hex = resp.cookies.get('authtoken')
    if token_hex is None:
        print("No authtoken cookie found!")
        sys.exit(1)
    token = bytes.fromhex(token_hex)
    print("[*] Retrieved token from index page.")

    # Step 2: Decrypt the token to recover the plaintext.
    print("[*] Running padding oracle decryption on the token...")
    recovered_plain = decrypt_ciphertext(token, base_url)
    print("[*] Recovered plaintext:")
    print(recovered_plain.decode())

    # Step 3: Extract the secret from the plaintext.
    secret = extract_secret(recovered_plain)
    print("[*] Extracted secret:", secret)

    # Step 4: Build the new desired plaintext.
    new_plain = (secret + " plain CBC is not secure!").encode()
    print("[*] New target plaintext:")
    print(new_plain.decode())

    # Step 5: Encrypt the new plaintext using our padding oracle encryption.
    print("[*] Crafting new token using padding oracle encryption...")
    new_token = encrypt_plaintext(new_plain, base_url)
    print("[*] New token (hex):")
    print(new_token.hex())

    # Step 6: Send the new token to the /quote/ endpoint.
    quote_url = urljoin(base_url, '/quote/')
    cookies = {'authtoken': new_token.hex()}
    resp = requests.get(quote_url, cookies=cookies)
    print("[*] Server response:")
    print(resp.text)

if __name__ == '__main__':
    main()