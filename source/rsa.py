from sympy import randprime
from math import gcd

def RSA_KEYGEN(key_size):
    half_key_size = key_size // 2  # Halver key_size for at lave p og q store nok til at n får ønsket størrelse
    e = 65537

    # Find p,q så gcd(e, phi_n) == 1
    while True:
        p = randprime(2 ** (half_key_size - 1), 2 ** half_key_size)
        q = randprime(2 ** (half_key_size - 1), 2 ** half_key_size)
        while q == p:
            q = randprime(2 ** (half_key_size - 1), 2 ** half_key_size)

        n = p * q
        phi_n = (p - 1) * (q - 1)

        if gcd(e, phi_n) == 1:
            break

    d = pow(e, -1, phi_n)  # Modulære invers af e mod phi_n
    return {'e': e, 'd': d, 'n': n}

def RSA_ENCRYPT(message, public_key):
    e, n = public_key['e'], public_key['n']
    message_bytes = message.encode('utf-8')  # Besked som bytes
    max_bytes = (n.bit_length() - 1) // 8     # Rundet ned til antal bytes der kan krypteres i en chunk

    encrypted_chunks = []
    for i in range(0, len(message_bytes), max_bytes):
        chunk = message_bytes[i:i + max_bytes]
        chunk_int = int.from_bytes(chunk, 'big')  # Heltal for denne chunk
        encrypted_chunks.append(pow(chunk_int, e, n)) # Tilføj krypteret chunk til liste

    return encrypted_chunks # Returner liste af krypterede chunks

def RSA_DECRYPT(encrypted_chunks, private_key):
    d, n = private_key['d'], private_key['n']
    decrypted = bytearray() # Opret tom bytearray til dekrypteret besked
    for c in encrypted_chunks:
        dec_int = pow(c, d, n)                       # Dekrypteret integer
        length = (dec_int.bit_length() + 7) // 8     # Antal bytes nødvendig for at repræsentere denne chunk
        decrypted.extend(dec_int.to_bytes(length, 'big')) # Tilføj dekrypteret chunk til bytearray

    return decrypted.decode('utf-8')  # Returner besked som streng
