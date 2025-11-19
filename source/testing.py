from rsa import RSA_KEYGEN, RSA_ENCRYPT, RSA_DECRYPT
from time import time
import json
import os
from plot import plot_encryption_times
from datetime import datetime

# Hvis True printer scriptet detaljerede resultater til konsollen
log_console = False


def append_log(message: str, print_console: bool = False):
    """
    Hvis print_console er True, printes beskeden også til konsolen, så brugeren kan
    se live fremskridt.
    """
    log_path = os.path.join(os.path.dirname(__file__), 'run.log')
    ts = datetime.now().isoformat(sep=' ', timespec='seconds')
    line = f"[{ts}] {message}\n"
    try:
        with open(log_path, 'a', encoding='utf-8') as lf:
            lf.write(line)
    except Exception:
        print("Logging failed")
        pass

    if print_console:
        print(line.strip())

def test_rsa_keygen(key_size, message):
    # Måler tid for nøglegenerering
    start_gen = time()
    keypair = RSA_KEYGEN(key_size)
    gen_duration = time() - start_gen

   # Måler tid for kryptering
    start_enc = time()
    ciphertext = RSA_ENCRYPT(message, {'e': keypair['e'], 'n': keypair['n']})
    enc_duration = time() - start_enc

    # Måler tid for dekryptering
    start_dec = time()
    decrypted = RSA_DECRYPT(ciphertext, {'d': keypair['d'], 'n': keypair['n']})
    dec_duration = time() - start_dec

    # Beregner længden af beskeden i bytes
    if isinstance(message, str):
        message_length = len(message.encode('utf-8'))
    else:
        message_length = len(message)

    return {
        'key_size': key_size,
        'message_length': message_length,
        'generation_time': gen_duration,
        'encryption_time': enc_duration,
        'decryption_time': dec_duration,
        # ciphertext er en liste af {'c': int, 'len': int}
        'ciphertext': ciphertext,
        'decrypted_message': decrypted,
    }


# Test for forskellige nøglestørrelser og beskedlængder
key_sizes = [512, 1024, 2048, 4096]  # Nøglestørrelser i bits
message_lengths = [512, 1024, 2048, 4096]  # Antal bytes i beskeden. Tilsvarende bits: [4096, 8192, 16384, 32768]

def main():
    results = []
    overall_start = time()
    append_log("Run started", print_console=True)
    for size in key_sizes:
        if log_console:
            print(f"=== Testing RSA key size: {size} bits ===")
        for length in message_lengths:
            # Simpel besked med length bytes (A gentaget)
            message = "A" * length
            result = test_rsa_keygen(size, message=message)
            results.append(result)

            # Log hver test til run.log uden at printe til konsollen
            append_log(
                f"Tested key={size} bits, message_length={length} bytes, "
                f"generation={result['generation_time']:.4f}s, "
                f"enc={result['encryption_time']:.6f}s, dec={result['decryption_time']:.6f}s",
                print_console=False,
            )

            if log_console:
                print(f"message_length: {length} bytes")
                print(f"  generation_time: {result['generation_time']:.4f} s")
                print(f"  encryption_time: {result['encryption_time']:.6f} s")
                print(f"  decryption_time: {result['decryption_time']:.6f} s")
                print(f"  decrypted_message: {result['decrypted_message']}")
                print("-" * 50)

    # Log progress per key size
    elapsed = time() - overall_start
    # Print en kort besked til konsollen så brugeren kan følge med i fremskridtet
    append_log(f"Key {size} finished, time since start: {elapsed:.2f} s", print_console=True)
    print(f"key{size} finished")

    # Skriv results til results.json (overskriver tidligere fil)
    out_path = os.path.join(os.path.dirname(__file__), 'results.json')
    with open(out_path, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2, ensure_ascii=False)

    append_log(f"Wrote {len(results)} result entries to {out_path}", print_console=True)

    # Log og plot tider
    plot_start_ts = datetime.now().isoformat(sep=' ', timespec='seconds')
    append_log(f"Plot started at {plot_start_ts}, time since start: {time() - overall_start:.2f} s", print_console=True)
    try:
        # Gemmer plot og viser et interaktivt vindue som standard
        plot_encryption_times(results, show=True)
        append_log("Plot finished", print_console=True)
    except Exception as e:
        append_log(f"Plotting failed: {e}", print_console=True)

if __name__ == '__main__':
    main()
