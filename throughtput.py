from Crypto.Cipher import AES, Blowfish, PKCS1_OAEP, DES, DES3
from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import SHA256
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
import os
import time
import matplotlib
import matplotlib.pyplot as plt
import seaborn as sns
from Crypto.PublicKey import RSA

# Generate ECC key pair for the user
private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
public_key = private_key.public_key()

file_path = 'test_file_150000000.txt'

algorithms = ['Proposed Method','DES', '3DES', 'AES', 'Blowfish']
throughput = []  # List to store the throughput values

# Define the file size for encryption and decryption (in bytes)
file_size = 1024 * 1024 

def encrypt(file_path,private_key,public_key):
    aes_key = os.urandom(32)

    with open(file_path, 'rb') as file:
        data = file.read()

# Use ECC to derive shared secret
    shared_secret = private_key.exchange(ec.ECDH(), public_key)

    # Derive encryption key using Concatenation KDF
    encryption_key = ConcatKDFHMAC(
        algorithm=hashes.SHA256(),
        length=32,  # 256 bits
        salt=None,
        otherinfo=None,
        backend=default_backend()
    ).derive(shared_secret)

    # Use AES to encrypt the data
    aes_cipher = AES.new(encryption_key, AES.MODE_ECB)
    encrypted_data = aes_cipher.encrypt(pad(data, AES.block_size))

    # Generate Blowfish key
    bf_key = os.urandom(16)

    # Use Blowfish to encrypt the AES-encrypted data
    bf_cipher = Blowfish.new(bf_key, Blowfish.MODE_ECB)
    encrypted_aes_data = bf_cipher.encrypt(pad(encrypted_data, Blowfish.block_size))

    # Generate a SHA-256 hash of the AES key
    aes_key_hash = SHA256.new()
    aes_key_hash.update(aes_key)

    # Store the encrypted AES data, ECC public key, and SHA-256 hash on the cloud server
    encrypted_aes_data_str = encrypted_aes_data.hex()
    public_key_str = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).hex()
    aes_key_hash_str = aes_key_hash.digest().hex()

    return encrypted_aes_data_str,bf_key

def decrypt(encrypted_aes_data_str, public_key,private_key, bf_key,file_path):

    with open(file_path, 'rb') as file:
        data = file.read()

    decryption_key = private_key

    # Derive shared secret using ECC key exchange
    shared_secret = decryption_key.exchange(ec.ECDH(), public_key)

    # Derive decryption key using Concatenation KDF
    decryption_key = ConcatKDFHMAC(
        algorithm=hashes.SHA256(),
        length=32,  # 256 bits
        salt=None,
        otherinfo=None,
        backend=default_backend()
    ).derive(shared_secret)

    # Use Blowfish to decrypt the AES-encrypted data
    bf_cipher = Blowfish.new(bf_key, Blowfish.MODE_ECB)
    decrypted_aes_data = unpad(bf_cipher.decrypt(bytes.fromhex(encrypted_aes_data_str)), Blowfish.block_size)

    # Use AES to decrypt the data
    aes_cipher = AES.new(decryption_key, AES.MODE_ECB)
    decrypted_data = unpad(aes_cipher.decrypt(decrypted_aes_data), AES.block_size)

    return decrypted_data

def encrypt_des():
    with open(file_path, 'rb') as file:
        data = file.read()
    
    key = os.urandom(8)

    des_cipher = DES.new(key, DES.MODE_ECB)
    encrypted_data = des_cipher.encrypt(pad(data, DES.block_size))
    
    des_cipher = DES.new(key, DES.MODE_ECB)
    decrypted_data = unpad(des_cipher.decrypt(encrypted_data), DES.block_size)
    return decrypted_data

def encrypt_3des():
    with open(file_path, 'rb') as file:
        data = file.read()
    key = os.urandom(16)
    des3_cipher = DES3.new(key, DES3.MODE_ECB)
    encrypted_data = des3_cipher.encrypt(pad(data, DES3.block_size))
    
    des3_cipher = DES3.new(key, DES3.MODE_ECB)
    decrypted_data = unpad(des3_cipher.decrypt(encrypted_data), DES3.block_size)

def encrypt_aes():
    with open(file_path, 'rb') as file:
        data = file.read()

    key = os.urandom(16)

    aes_cipher = AES.new(key, AES.MODE_ECB)
    encrypted_data = aes_cipher.encrypt(pad(data, AES.block_size))
    aes_cipher = AES.new(key, AES.MODE_ECB)
    decrypted_data = unpad(aes_cipher.decrypt(encrypted_data), AES.block_size)

def encrypt_blowfish():
    with open(file_path, 'rb') as file:
        data = file.read()

    key = os.urandom(16)

    bf_cipher = Blowfish.new(key, Blowfish.MODE_ECB)
    encrypted_data = bf_cipher.encrypt(pad(data, Blowfish.block_size))
    bf_cipher = Blowfish.new(key, Blowfish.MODE_ECB)
    decrypted_data = unpad(bf_cipher.decrypt(encrypted_data), Blowfish.block_size)

def measure_throughput(algorithm, func):
    start_time = time.time()

    # Perform encryption and decryption using the specified algorithm and function
    for _ in range(5):  # Repeat for more accurate measurement
        func()

    end_time = time.time()
    elapsed_time = end_time - start_time

    # Calculate throughput in bits per second
    throughput_value = file_size * 8 / elapsed_time

    return throughput_value

def our_encryption_decryption():
    encrypted_aes_data_str, bf_key = encrypt(file_path, private_key, public_key)
    decrypted_data = decrypt(encrypted_aes_data_str, public_key, private_key, bf_key, file_path)


# Measure throughput for each algorithm
for algorithm in algorithms:
    if algorithm == 'Proposed Method':
        throughput_value = measure_throughput(algorithm, our_encryption_decryption)

    elif algorithm == 'DES':
        throughput_value = measure_throughput(algorithm, encrypt_des)
    elif algorithm == '3DES':
        throughput_value = measure_throughput(algorithm, encrypt_3des)
    elif algorithm == 'AES':
        throughput_value = measure_throughput(algorithm, encrypt_aes)
    elif algorithm == 'Blowfish':
        throughput_value = measure_throughput(algorithm, encrypt_blowfish)

    throughput.append(throughput_value)



    print(algorithm,throughput_value)


# Plot the throughput values
sns.set_palette("pastel")
sns.set(style="whitegrid")
plt.figure(figsize=(8, 6))
ax = sns.barplot(x = algorithms, y =throughput)
plt.xlabel('Algorithm')
plt.ylabel('Throughput (bps)')
plt.title('Comparison of Throughput for Encryption and Decryption')
for i, v in enumerate(throughput):
        ax.text(i, v, f'{v:.2f}', ha='center', va='bottom')
plt.show()