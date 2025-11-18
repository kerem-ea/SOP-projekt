from sympy import randprime

def RSA_KEYGEN(key_size):

    half_key_size = key_size // 2 # Halver nøglestørrelsen for at generere p og q til at give n af ønsket størrelse

    # Generer to primtal p og q
    p = randprime(2**(half_key_size - 1), 2**half_key_size)
    q = randprime(2**(half_key_size - 1), 2**half_key_size)

    # Sørg for at p og q er forskellige ellers kan n blive svagt
    while q == p:
        q = randprime(2**(half_key_size - 1), 2**half_key_size)

    n = p * q
    phi_n = (p - 1) * (q - 1)

    e = 65537 
    d = pow(e, -1, phi_n)  # beregn modulær invers

    return {
        'public_key': (e, n),
        'private_key': (d, n)
    }