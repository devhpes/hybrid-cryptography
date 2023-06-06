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


def encrypt_des(file_path, key):
    with open(file_path, 'rb') as file:
        data = file.read()

    des_cipher = DES.new(key, DES.MODE_ECB)
    encrypted_data = des_cipher.encrypt(pad(data, DES.block_size))
    return encrypted_data

def encrypt_3des(file_path, key):
    with open(file_path, 'rb') as file:
        data = file.read()

    des3_cipher = DES3.new(key, DES3.MODE_ECB)
    encrypted_data = des3_cipher.encrypt(pad(data, DES3.block_size))
    return encrypted_data

def encrypt_rsa(file_path, public_key):
    with open(file_path, 'rb') as file:
        data = file.read()

    rsa_cipher = PKCS1_OAEP.new(public_key)
    encrypted_data = rsa_cipher.encrypt(data)
    return encrypted_data

def encrypt_aes(file_path, key):
    with open(file_path, 'rb') as file:
        data = file.read()

    aes_cipher = AES.new(key, AES.MODE_ECB)
    encrypted_data = aes_cipher.encrypt(pad(data, AES.block_size))
    return encrypted_data

def encrypt_blowfish(file_path, key):
    with open(file_path, 'rb') as file:
        data = file.read()

    bf_cipher = Blowfish.new(key, Blowfish.MODE_ECB)
    encrypted_data = bf_cipher.encrypt(pad(data, Blowfish.block_size))
    return encrypted_data

def compare_encryption_time(file_path):
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key = private_key.public_key()

    start_time = time.time()
    encrypted_aes_data, bf_key = encrypt(file_path, private_key, public_key)
    ecc_blowfish_encryption_time = time.time() - start_time

    des_key = os.urandom(8)
    start_time = time.time()
    encrypted_data_des = encrypt_des(file_path, des_key)
    des_encryption_time = time.time() - start_time

    # 3DES
    des3_key = os.urandom(16)
    start_time = time.time()
    encrypted_data_3des = encrypt_3des(file_path, des3_key)
    des3_encryption_time = time.time() - start_time

    # RSA
    # private_key = RSA.generate(2048)
    # public_key = private_key.publickey()
    # start_time = time.time()
    # encrypted_data_rsa = encrypt_rsa(file_path, public_key)
    # rsa_encryption_time = time.time() - start_time

    # AES
    aes_key = os.urandom(16)
    start_time = time.time()
    encrypted_data_aes = encrypt_aes(file_path, aes_key)
    aes_encryption_time = time.time() - start_time

    # Blowfish
    bf_key = os.urandom(16)
    start_time = time.time()
    encrypted_data_bf = encrypt_blowfish(file_path, bf_key)
    blowfish_encryption_time = time.time() - start_time

    return ecc_blowfish_encryption_time, des_encryption_time, des3_encryption_time, aes_encryption_time, blowfish_encryption_time


if __name__ == '__main__':
    file_sizes = [10000000, 25000000, 50000000, 75000000, 100000000,150000000]  # List of file sizes to test (in bytes)
    file_sizes_mb = [10,25,50,75, 100, 150]
    encryption_times = []
    encryption_times_aes = []
    encryption_times_blowfish = []
    encryption_times_des = []
    encryption_times_3des = []

    for file_size in file_sizes:
        # Create a file with the specified size
        file_path = f'test_file_{file_size}.txt'
        with open(file_path, 'wb') as file:
            file.write(os.urandom(file_size))
    
        ecc_blowfish_encryption_time, des_encryption_time, des3_encryption_time, aes_encryption_time, blowfish_encryption_time = compare_encryption_time(file_path)
        encryption_times.append(ecc_blowfish_encryption_time)
        encryption_times_des.append(des_encryption_time)
        encryption_times_3des.append(des3_encryption_time)
        encryption_times_aes.append(aes_encryption_time)
        encryption_times_blowfish.append(blowfish_encryption_time)


methods = ["Proposed Method", "DES", "3DES", "AES", "Blowfish"]
print("our encryption_times",encryption_times)
print("encryption_times_des",encryption_times_des)
print("encryption_times_3des",encryption_times_3des)
print("encryption_times_aes",encryption_times_aes)
print("encryption_times_blowfish",encryption_times_blowfish)

sns.set_style("whitegrid")
plt.figure(figsize=(12, 6))
plt.plot(file_sizes_mb, encryption_times, 'h-', label='Proposed Method')
plt.plot(file_sizes_mb, encryption_times_aes, 'p-', label='AES')
plt.plot(file_sizes_mb, encryption_times_blowfish, 'D-', label='Blowfish')
plt.plot(file_sizes_mb, encryption_times_des, 'H-', label='DES')
plt.plot(file_sizes_mb, encryption_times_3des, 's-', label='3DES')
plt.xlabel('File Size (MB)')
plt.ylabel('Encryption Time (Seconds)')
plt.title('Encryption Time Comparison')
plt.legend()
plt.show()
