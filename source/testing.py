from rsa import RSA_KEYGEN
from time import time

def test_rsa_keygen(key_size=1024):
    start_time = time()
    keypair = RSA_KEYGEN(key_size)
    end_time = time()
    duration = end_time - start_time
    return keypair, duration

key_sizes = [512, 1024, 2048, 4096]

for key_size in key_sizes:
    keypair, duration = test_rsa_keygen(key_size)
    print(f"Generated RSA keypair of size {key_size} bits in {duration:.4f} seconds.")

