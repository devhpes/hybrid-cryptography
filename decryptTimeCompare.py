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

    return decrypted_data


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

def decrypt_des(encrypted_data, key):
    des_cipher = DES.new(key, DES.MODE_ECB)
    decrypted_data = unpad(des_cipher.decrypt(encrypted_data), DES.block_size)
    return decrypted_data

def decrypt_3des(encrypted_data, key):
    des3_cipher = DES3.new(key, DES3.MODE_ECB)
    decrypted_data = unpad(des3_cipher.decrypt(encrypted_data), DES3.block_size)
    return decrypted_data

def decrypt_aes(encrypted_data, key):
    aes_cipher = AES.new(key, AES.MODE_ECB)
    decrypted_data = unpad(aes_cipher.decrypt(encrypted_data), AES.block_size)
    return decrypted_data

def decrypt_blowfish(encrypted_data, key):
    bf_cipher = Blowfish.new(key, Blowfish.MODE_ECB)
    decrypted_data = unpad(bf_cipher.decrypt(encrypted_data), Blowfish.block_size)
    return decrypted_data

def compare_decryption_time(file_path, key):
    # Encryption
    des_key = os.urandom(8)
    encrypted_data_des = encrypt_des(file_path, des_key)

    des3_key = os.urandom(16)
    encrypted_data_3des = encrypt_3des(file_path, des3_key)

    aes_key = os.urandom(16)
    encrypted_data_aes = encrypt_aes(file_path, aes_key)

    bf_key = os.urandom(16)
    encrypted_data_bf = encrypt_blowfish(file_path, bf_key)

    # Decryption
    start_time = time.time()
    decrypted_data_des = decrypt_des(encrypted_data_des, des_key)
    des_decryption_time = time.time() - start_time

    start_time = time.time()
    decrypted_data_3des = decrypt_3des(encrypted_data_3des, des3_key)
    des3_decryption_time = time.time() - start_time

    start_time = time.time()
    decrypted_data_aes = decrypt_aes(encrypted_data_aes, aes_key)
    aes_decryption_time = time.time() - start_time

    start_time = time.time()
    decrypted_data_bf = decrypt_blowfish(encrypted_data_bf, bf_key)
    blowfish_decryption_time = time.time() - start_time

    return des_decryption_time, des3_decryption_time, aes_decryption_time, blowfish_decryption_time

if __name__ == '__main__':
    file_sizes = [10000000, 25000000, 50000000, 75000000, 100000000,150000000]  # List of file sizes to test (in bytes)
    file_sizes_mb = [10,25,50,75, 100, 150]
    decryption_times = []
    decryption_times_aes = []
    decryption_times_blowfish = []
    decryption_times_des = []
    decryption_times_3des = []

    for file_size in file_sizes:
        # Create a file with the specified size
        file_path = f'test_file_{file_size}.txt'
        with open(file_path, 'wb') as file:
            file.write(os.urandom(file_size))
        
        key = b'ThisIsA16ByteKey'
        des_decryption_time, des3_decryption_time, aes_decryption_time, blowfish_decryption_time = compare_decryption_time(file_path, key)

        decryption_times_aes.append(aes_decryption_time)
        decryption_times_blowfish.append(blowfish_decryption_time)
        decryption_times_des.append(des_decryption_time)
        decryption_times_3des.append(des3_decryption_time)


        encrypted_aes_data_str, bf_key = encrypt(file_path, private_key, public_key)

        # Perform decryption
        start_time = time.time()
        decrypted_data = decrypt(encrypted_aes_data_str, public_key, private_key, bf_key, file_path)
        decryption_time = time.time() - start_time
        our_decryption_times = decryption_time

        decryption_times.append(our_decryption_times)
    


methods = ["Proposed Method","DES", "3DES", "AES", "Blowfish"]
sns.set_style("whitegrid")
print("our decryption_times",decryption_times)
print("decryption_times_3des",decryption_times_3des)
print("decryption_times_des",decryption_times_des)
print("decryption_times_blowfish",decryption_times_blowfish)
print("decryption_times_aes",decryption_times_aes)

plt.figure(figsize=(12, 6))
plt.plot(file_sizes_mb, decryption_times, 'h-', label='Proposed Method')
plt.plot(file_sizes_mb, decryption_times_aes, 'p-', label='AES')
plt.plot(file_sizes_mb, decryption_times_blowfish, 'D-', label='Blowfish')
plt.plot(file_sizes_mb, decryption_times_des, 'H-', label='DES')
plt.plot(file_sizes_mb, decryption_times_3des, 's-', label='3DES')
plt.xlabel('File Size (MB)')
plt.ylabel('Decryption Time (Seconds)')
plt.title('Decryption Time Comparison')
plt.legend()
plt.show()