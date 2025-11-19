from rsa import RSA_KEYGEN, RSA_ENCRYPT, RSA_DECRYPT
from time import time
import json
import os
from plot import plot_encryption_times
from datetime import datetime

# Hvis True printer scriptet resultater til konsollen
log_console = False


def append_log(message: str):
    """Append a timestamped message to run.log in the source folder."""
    log_path = os.path.join(os.path.dirname(__file__), 'run.log')
    ts = datetime.now().isoformat(sep=' ', timespec='seconds')
    line = f"[{ts}] {message}\n"
    try:
        with open(log_path, 'a', encoding='utf-8') as lf:
            lf.write(line)
    except Exception:
        pass

def test_rsa_keygen(key_size, message):
    # Måler tid for nøglegenerering
    start_gen = time()
    keypair = RSA_KEYGEN(key_size)
    gen_duration = time() - start_gen

   
    start_enc = time()
    ciphertext = RSA_ENCRYPT(message, {'e': keypair['e'], 'n': keypair['n']})
    enc_duration = time() - start_enc

    # Måler tid for dekryptering
    start_dec = time()
    decrypted = RSA_DECRYPT(ciphertext, {'d': keypair['d'], 'n': keypair['n']})
    dec_duration = time() - start_dec

    # Beregner længden af beskeden i bytes
    message_length = len(message.encode('utf-8'))

    return {
        'key_size': key_size,
        'message_length': message_length,
        'generation_time': gen_duration,
        'encryption_time': enc_duration,
        'decryption_time': dec_duration,
        'ciphertext': ciphertext,
        'decrypted_message': decrypted,
    }


# Test for forskellige nøglestørrelser og beskedlængder
key_sizes = [512, 1024, 2048, 4096]  # Nøglestørrelser i bits
message_lengths = [32, 64, 128, 256, 512, 1024, 2048]  # Antal bytes i beskeden. Tilsvarende bits: [128, 256, 512, 1024]

def main():
    results = []
    overall_start = time()
    append_log("Run started")
    for size in key_sizes:
        if log_console:
            print(f"=== Testing RSA key size: {size} bits ===")
        for length in message_lengths:
            # Simpel besked med length bytes (A gentaget)
            message = "A" * length
            result = test_rsa_keygen(size, message=message)
            results.append(result)

            if log_console:
                print(f"message_length: {length} bytes")
                print(f"  generation_time: {result['generation_time']:.4f} s")
                print(f"  encryption_time: {result['encryption_time']:.6f} s")
                print(f"  decryption_time: {result['decryption_time']:.6f} s")
                print(f"  decrypted_message: {result['decrypted_message']}")
                print("-" * 50)

        # Log progress per key size (time since overall start)
        elapsed = time() - overall_start
        append_log(f"{size} done, time since start: {elapsed:.2f} s")

    # Skriv results til results.json (overskriver tidligere fil)
    out_path = os.path.join(os.path.dirname(__file__), 'results.json')
    with open(out_path, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2, ensure_ascii=False)

    append_log(f"Wrote {len(results)} result entries to {out_path}")

    # Log and start plotting (no console output)
    plot_start_ts = datetime.now().isoformat(sep=' ', timespec='seconds')
    append_log(f"Plot started at {plot_start_ts}, time since start: {time() - overall_start:.2f} s")
    try:
        plot_encryption_times(results)
        append_log("Plot finished")
    except Exception as e:
        append_log(f"Plotting failed: {e}")

if __name__ == '__main__':
    main()
