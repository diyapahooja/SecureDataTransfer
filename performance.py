import time
import pandas as pd
import matplotlib.pyplot as plt
from crypto_utils import encrypt_text_flow, decrypt_text_flow, generate_rsa_keypair

def benchmark(sizes=[1024, 10240, 102400, 1048576], aes_key_size=256, rsa_key_size=2048):
    priv, pub = generate_rsa_keypair(rsa_key_size)
    results = []
    for size in sizes:
        plaintext = b'X' * size
        # Encryption
        start = time.time()
        enc_aes_key, iv, ct, h = encrypt_text_flow(plaintext, pub, aes_key_size)
        enc_time = time.time() - start
        # Decryption
        start = time.time()
        decrypted, ok, _ = decrypt_text_flow(enc_aes_key, iv, ct, h, priv)
        dec_time = time.time() - start
        results.append({
            'size_bytes': size,
            'encryption_time': enc_time,
            'decryption_time': dec_time,
            'integrity_ok': ok
        })
    df = pd.DataFrame(results)
    # Plot
    plt.figure()
    plt.plot(df['size_bytes'], df['encryption_time'], label='Encryption')
    plt.plot(df['size_bytes'], df['decryption_time'], label='Decryption')
    plt.xlabel('Data Size (bytes)')
    plt.ylabel('Time (seconds)')
    plt.title(f'Performance (AES-{aes_key_size}, RSA-{rsa_key_size})')
    plt.legend()
    plt.grid(True)
    plt.show()
    return df