import time
import matplotlib.pyplot as plt
import seaborn as sns
from Crypto.Cipher import DES, DES3, AES, Blowfish
from cryptography.hazmat.primitives.asymmetric import ec
import os

# Define the algorithms to compare
algorithms = ['DES', '3DES', 'AES', 'Blowfish', 'ECC (secp256r1)']
key_generation_time = []  # List to store the key generation times

# Define the number of iterations for key generation
num_iterations = 100

# Define the key sizes (where applicable)
des_key_size = 8  # 64 bits
des3_key_size = 16  # 128 bits
aes_key_size = 32  # 256 bits
blowfish_key_size = 16  # 128 bits
ecc_curve = ec.SECP256R1()  # secp256r1 curve

# Define the key generation functions for each algorithm
def generate_des_key():
    start_time = time.time()
    key = os.urandom(8)
    end_time = time.time()
    return end_time - start_time

def generate_des3_key():
    start_time = time.time()
    key = os.urandom(16)
    end_time = time.time()
    return end_time - start_time

def generate_aes_key():
    start_time = time.time()
    key = os.urandom(32)
    end_time = time.time()
    return end_time - start_time

def generate_blowfish_key():
    start_time = time.time()
    key = os.urandom(16)
    end_time = time.time()
    return end_time - start_time

def generate_ecc_key():
    start_time = time.time()
    private_key = ec.generate_private_key(ecc_curve)
    end_time = time.time()
    return end_time - start_time

# Generate keys and measure the key generation time for each algorithm
for algorithm in algorithms:
    if algorithm == 'DES':
        key_generation_time.append(generate_des_key())
    elif algorithm == '3DES':
        key_generation_time.append(generate_des3_key())
    elif algorithm == 'AES':
        key_generation_time.append(generate_aes_key())
    elif algorithm == 'Blowfish':
        key_generation_time.append(generate_blowfish_key())
    elif algorithm == 'ECC (secp256r1)':
        key_generation_time.append(generate_ecc_key())


print(key_generation_time)


# Plot the key generation time comparison
sns.set_palette("pastel")
sns.set(style="whitegrid")
plt.figure(figsize=(10, 6))
ax = sns.barplot(x=algorithms, y=key_generation_time)
plt.xlabel('Algorithm')
plt.ylabel('Key Generation Time (seconds)')
plt.title('Key Generation Time Comparison')
for i, v in enumerate(key_generation_time):
    ax.text(i, v, f'{v:.2f}', ha='center', va='bottom')
plt.show()
