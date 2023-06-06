from Crypto.Cipher import AES, Blowfish
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

    return decrypted_data

encrypted_aes_data_str , bf_key = encrypt("encrypt.txt", private_key,public_key)
print(decrypt(encrypted_aes_data_str,public_key,private_key,bf_key,"encrypt.txt"))

# if __name__ == '__main__':
#     file_sizes = [10000000, 25000000, 50000000, 75000000, 100000000,150000000]  # List of file sizes to test (in bytes)
#     file_sizes_mb = [10,25,50,75, 100, 150]
#     encryption_times = []
#     decryption_times = []

#     for file_size in file_sizes:
#         # Create a file with the specified size
#         file_path = f'test_file_{file_size}.txt'
#         with open(file_path, 'wb') as file:
#             file.write(os.urandom(file_size))

#         # Perform encryption
#         start_time = time.time()
#         encrypted_aes_data_str, bf_key = encrypt(file_path, private_key, public_key)
#         encryption_time = time.time() - start_time
#         encryption_times.append(encryption_time)

#         # Perform decryption
#         start_time = time.time()
#         decrypted_data = decrypt(encrypted_aes_data_str, public_key, private_key, bf_key, file_path)
#         decryption_time = time.time() - start_time
#         decryption_times.append(decryption_time)

#         # Delete the test file
#         if file_size != 150000000:
#             os.remove(file_path)


#     sns.set_palette("pastel")
#     plt.figure(figsize=(8, 5))
#     ax = sns.barplot(x=file_sizes_mb, y=encryption_times, color='#a1c9f4')
#     plt.xlabel('File Size (MB)')
#     plt.ylabel('Encryption Time (Seconds)')
#     plt.title('Encryption Time for Different File Sizes')
#     for i, v in enumerate(encryption_times):
#         ax.text(i, v, f'{v:.2f}', ha='center', va='bottom')

#     plt.show()

#     # Visualization - Decryption Time
    
#     plt.figure(figsize=(8, 5))
#     ax = sns.barplot(x=file_sizes_mb, y=decryption_times,color='#a1c9f4')

#     plt.xlabel('File Size (MB)')
#     plt.ylabel('Decryption Time (Seconds)')
#     plt.title('Decryption Time for Different File Sizes')
#     for i, v in enumerate(decryption_times):
#         ax.text(i, v, f'{v:.2f}', ha='center', va='bottom')
#     plt.show()