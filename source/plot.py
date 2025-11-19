import json
import os
from collections import defaultdict
import matplotlib.pyplot as plt
import matplotlib.ticker as ticker

def load_results(path=None):
    if path is None:
        path = os.path.join(os.path.dirname(__file__), 'results.json')

    if not os.path.exists(path):
        raise FileNotFoundError(f"Results file not found: {path}")

    with open(path, 'r', encoding='utf-8') as f:
        return json.load(f)

def plot_encryption_times(results, out_path=None):
    # Opret struktur: key_size -> liste af (message_length, encryption_time)
    grouped = defaultdict(list)
    message_lengths = set()

    # Grupper data efter nøglestørrelse og indsamle både enc/dec tider
    for row in results:
        key_size = row.get('key_size')
        message_length = row.get('message_length')
        encryption_time = row.get('encryption_time')
        decryption_time = row.get('decryption_time')

        # Spring rækker over med manglende data
        if key_size is None or message_length is None or encryption_time is None or decryption_time is None:
            continue

        grouped[key_size].append((message_length, encryption_time, decryption_time))
        message_lengths.add(message_length)

    if not grouped:
        raise ValueError("No valid data to plot")

    plt.figure(figsize=(8, 5))

    # Plot en solid linje for encryption_time og en stiplet linje for decryption_time
    color_cycle = plt.rcParams['axes.prop_cycle'].by_key().get('color', None)
    for i, (key_size, pairs) in enumerate(sorted(grouped.items())):
        # Sorter data efter beskedlængde
        pairs_sorted = sorted(pairs, key=lambda item: item[0])

        xs = [item[0] for item in pairs_sorted]                 # Beskedlængder
        ys_enc = [item[1] for item in pairs_sorted]             # Krypteringstider
        ys_dec = [item[2] for item in pairs_sorted]             # Dekrypteringstider

        # Vælg farve fra cyklen så begge linjer matcher
        color = None
        if color_cycle:
            color = color_cycle[i % len(color_cycle)]

        plt.plot(xs, ys_enc, marker='o', linestyle='-', color=color, label=f"Key {key_size} enc")
        plt.plot(xs, ys_dec, marker='o', linestyle='--', color=color, label=f"Key {key_size} dec")

    # Akse- og titelmærkninger (forøget skriftstørrelse)
    plt.xlabel("Message length (bytes)", fontsize=14)
    plt.ylabel("Encryption time (s, log scale)", fontsize=14)
    plt.title("RSA encryption time vs message length", fontsize=16)
    # Forøget legend-tekst og titelstørrelse så farve-/linjeforklaringer er tydelige
    plt.legend(title="Key size", fontsize=12, title_fontsize=13)

    # Brug logaritmisk skala for at vise forskelle tydeligere
    plt.yscale('log')
    ax = plt.gca()

    # Brug store ticks ved 10^n (ingen små-ticks)
    ax.yaxis.set_major_locator(
        ticker.LogLocator(base=10.0, subs=(1.0,), numticks=10)
    )
    ax.yaxis.set_major_formatter(
        ticker.LogFormatterMathtext(base=10.0)
    )
    # Ingen minor ticks mellem dekader
    ax.yaxis.set_minor_locator(ticker.NullLocator())

    plt.grid(True, which='major', linestyle='--', linewidth=0.6)

    # Brug diskrete beskedlængder som x-ticks hvis muligt
    try:
        xticks = sorted(message_lengths)
        if xticks:
            ax.set_xticks(xticks)
    except Exception:
        pass

    # Forøget skriftstørrelse på tick labels så aksetekst er nemmere at læse
    ax.tick_params(axis='both', labelsize=12)

    # Standard outputsti hvis ingen gives
    if out_path is None:
        out_path = os.path.join(os.path.dirname(__file__), 'encryption_times.png')

    plt.tight_layout()
    plt.savefig(out_path)
    # No console output; caller (testing.py) will log plot progress to run.log
    plt.show()

if __name__ == '__main__':
    results = load_results()
    plot_encryption_times(results)
