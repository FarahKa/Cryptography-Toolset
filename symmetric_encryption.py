import base64
import os
from base64 import b64encode
from base64 import b64decode
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import hashlib

def pad(message, blockSize):
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(message) + padder.finalize()
    return padded_data

def unpad(message, blockSize):
    unpadder = padding.PKCS7(128).unpadder()
    data = unpadder.update(message) + unpadder.finalize()
    return(data)

def symen_AES_CBC():
    """encrypts using AES in CBC (block, padding) mode"""
    backend = default_backend()
    print("Give the message you would like to encrypt:")
    message = input().encode()
    print("Give the password you would like to use:")
    password = input()
    hasher = hashlib.new("SHA256")
    hasher.update(password.encode())
    key = hasher.digest()
    # print("key ", key) # key is bytes
    with open("iv.txt", "r") as ivfile:
        iv = ivfile.readline()
        # print(iv)
        iv= iv.encode()
        iv= b64decode(iv) #iv is bytes
        # print("iv ", iv)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()
    message = pad(message, 128)
    ct = encryptor.update(message) + encryptor.finalize()
    # print("Returned encryption: ", ct)
    plain = b64encode(ct).decode()
    print("Le message crypté est : ", plain)
    # print("in reverse:")
    # print(b64decode(plain.encode()))
    # decryptor = cipher.decryptor()
    # print(decryptor.update(ct) + decryptor.finalize())

def symdec_AES_CBC():
    """decrypts using AES in CBC (block, padding) mode"""
    backend = default_backend()
    print("Give the message you would like to decrypt:")
    message = input()
    # print("what we'll use here:")
    to_use=b64decode(message.encode())
    # print(to_use)
    print("Give the password you would like to use:")
    password = input()
    hasher = hashlib.new("SHA256")
    hasher.update(password.encode())
    key = hasher.digest()
    # print("key is ", key)
    with open("iv.txt", "r") as ivfile:
        iv = ivfile.readline()
        iv= iv.encode()
        iv= b64decode(iv)
        # print("iv ", iv)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    # encryptor = cipher.encryptor()
    # ct = encryptor.update(message.encode()) + encryptor.finalize()
    decryptor = cipher.decryptor()
    # print("Le message décrypté est:")
    dc = decryptor.update(to_use) + decryptor.finalize()
    # print(dc)
    dc = unpad(dc, 128)
    print("Le message en décrypté est: ", dc.decode())

def sym_encrypt(message, password):
    with open("salt.txt", "r") as saltfile:  # retreiving the salt from the salt file
        salt = b64decode(saltfile.readline())
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))

    fernet = Fernet(key)  # loading up the key into fernet
    encrypted = fernet.encrypt(message.encode())  # encrypting the message
    return encrypted


def symmetric_encryption():
    """Provides functionnality for encrypting a message symmetrically"""
    print("Provide the message you'd like to encrypt:")
    message = input()
    print("Provide the password you'd like to encrypt it with:")
    password = input()
    encrypted = sym_encrypt(message, password)
    print("Your symetrically encrypted message is:")
    print(encrypted.decode('ascii'))
    print("Would you like to save your encrypted message to a file? y/n")
    answer = input()
    if answer == "y":
        print("Give a filename:")
        filename = input()
        with open(filename.strip() + ".txt", "w") as messageFile:
            messageFile.write(encrypted.decode('ascii'))


def sym_decrypt(message, password):
    with open("salt.txt", "r") as saltfile:  # retreiving the salt from the salt file
        salt = b64decode(saltfile.readline())

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    fernet = Fernet(key)
    return fernet.decrypt(message.encode()).decode('ascii')


def symmetric_decryption():
    """Decrypts a symmetrically crypted message"""
    print("Provide the message you would like to decrypt:")
    message = input()
    print("Provide the password you'd like to decrypt it with:")
    password = input()
    decrypted = sym_decrypt(message, password)
    print("Your decrypted message is:")
    print(decrypted)

def symen_AES_CTR():
    """encrypts using AES in CTR (stream, no padding) mode"""
    backend = default_backend()
    print("Give the message you would like to encrypt:")
    message = input().encode()
    print("Give the password you would like to use:")
    password = input()
    hasher = hashlib.new("SHA256")
    hasher.update(password.encode())
    key = hasher.digest()
    # print("key ", key) # key is bytes
    with open("iv.txt", "r") as ivfile:
        iv = ivfile.readline()
        # print(iv)
        iv= iv.encode()
        iv= b64decode(iv) #iv is bytes
        # print("iv ", iv)
    cipher = Cipher(algorithms.AES(key), modes.CTR(iv), backend=backend)
    encryptor = cipher.encryptor()
    ct = encryptor.update(message) + encryptor.finalize()
    # print("Returned encryption: ", ct)
    plain = b64encode(ct).decode()
    print("Le message crypté est : ", plain)
    # print("in reverse:")
    # print(b64decode(plain.encode()))
    # decryptor = cipher.decryptor()
    # print(decryptor.update(ct) + decryptor.finalize())

def symdec_AES_CTR():
    """decrypts using AES in CTR (stream, no padding) mode"""
    backend = default_backend()
    print("Give the message you would like to decrypt:")
    message = input()
    # print("what we'll use here:")
    to_use=b64decode(message.encode())
    # print(to_use)
    print("Give the password you would like to use:")
    password = input()
    hasher = hashlib.new("SHA256")
    hasher.update(password.encode())
    key = hasher.digest()
    # print("key is ", key)
    with open("iv.txt", "r") as ivfile:
        iv = ivfile.readline()
        iv= iv.encode()
        iv= b64decode(iv)
        # print("iv ", iv)
    cipher = Cipher(algorithms.AES(key), modes.CTR(iv), backend=backend)
    # encryptor = cipher.encryptor()
    # ct = encryptor.update(message.encode()) + encryptor.finalize()
    decryptor = cipher.decryptor()
    # print("Le message décrypté est:")
    dc = decryptor.update(to_use) + decryptor.finalize()
    # print(dc)
    print("Le message en décrypté est: ", dc.decode())

def symen_Camellia():
    """encrypts using Camellia (block, padding) mode"""
    backend = default_backend()
    print("Give the message you would like to encrypt:")
    message = input().encode()
    print("Give the password you would like to use:")
    password = input()
    hasher = hashlib.new("SHA256")
    hasher.update(password.encode())
    key = hasher.digest()
    with open("iv.txt", "r") as ivfile:
        iv = ivfile.readline()
        iv= iv.encode()
        iv= b64decode(iv) #iv is bytes
    cipher = Cipher(algorithms.Camellia(key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()
    message = pad(message, 128)
    ct = encryptor.update(message) + encryptor.finalize()
    plain = b64encode(ct).decode()
    print("Le message crypté est : ", plain)

def symdec_Camellia():
    """decrypts using Camellia (block, padding) mode"""
    backend = default_backend()
    print("Give the message you would like to decrypt:")
    message = input()
    to_use=b64decode(message.encode())
    print("Give the password you would like to use:")
    password = input()
    hasher = hashlib.new("SHA256")
    hasher.update(password.encode())
    key = hasher.digest()
    with open("iv.txt", "r") as ivfile:
        iv = ivfile.readline()
        iv= iv.encode()
        iv= b64decode(iv)
    cipher = Cipher(algorithms.Camellia(key), modes.CBC(iv), backend=backend)
    decryptor = cipher.decryptor()
    dc = decryptor.update(to_use) + decryptor.finalize()
    dc = unpad(dc, 128)
    print("Le message en décrypté est: ", dc.decode())


def symen_ChaCha20():
    """encrypts using AES in CTR (stream, no padding) mode"""
    backend = default_backend()
    print("Give the message you would like to encrypt:")
    message = input().encode()
    print("Give the password you would like to use:")
    password = input()
    hasher = hashlib.new("SHA256")
    hasher.update(password.encode())
    key = hasher.digest()
    with open("iv.txt", "r") as ivfile:
        iv = ivfile.readline()
        iv= iv.encode()
        iv= b64decode(iv) #iv is bytes
    cipher = Cipher(algorithms.ChaCha20(key, iv), mode=None, backend=backend)
    encryptor = cipher.encryptor()
    ct = encryptor.update(message) + encryptor.finalize()
    plain = b64encode(ct).decode()
    print("Le message crypté est : ", plain)

def symdec_ChaCha20():
    """decrypts using ChaCha20"""
    backend = default_backend()
    print("Give the message you would like to decrypt:")
    message = input()
    to_use=b64decode(message.encode())
    print("Give the password you would like to use:")
    password = input()
    hasher = hashlib.new("SHA256")
    hasher.update(password.encode())
    key = hasher.digest()
    with open("iv.txt", "r") as ivfile:
        iv = ivfile.readline()
        iv= iv.encode()
        iv= b64decode(iv)
        # print("iv ", iv)
    cipher = Cipher(algorithms.ChaCha20(key, iv), mode=None, backend=backend)
    decryptor = cipher.decryptor()
    dc = decryptor.update(to_use) + decryptor.finalize()
    print("Le message en décrypté est: ", dc.decode())



def symen_TripleDES():
    """encrypts using Triple DES"""
    backend = default_backend()
    print("Give the message you would like to encrypt:")
    message = input().encode()
    print("Give the password you would like to use:")
    password = input()
    hasher = hashlib.new("MD5")
    hasher.update(password.encode())
    key = hasher.digest()
    with open("iv.txt", "r") as ivfile:
        iv = ivfile.readline()
        iv= iv.encode()
        iv= b64decode(iv)[:8] #iv is bytes
    cipher = Cipher(algorithms.TripleDES(key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()
    message = pad(message, 128)
    ct = encryptor.update(message) + encryptor.finalize()
    plain = b64encode(ct).decode()
    print("Le message crypté est : ", plain)

def symdec_TripleDES():
    """decrypts using Triple DES"""
    backend = default_backend()
    print("Give the message you would like to decrypt:")
    message = input()
    to_use=b64decode(message.encode())
    print("Give the password you would like to use:")
    password = input()
    hasher = hashlib.new("MD5")
    hasher.update(password.encode())
    key = hasher.digest()
    with open("iv.txt", "r") as ivfile:
        iv = ivfile.readline()
        iv= iv.encode()
        iv= b64decode(iv)[:8]
        # print("iv ", iv)
    cipher = Cipher(algorithms.TripleDES(key), modes.CBC(iv), backend=backend)
    decryptor = cipher.decryptor()
    dc = decryptor.update(to_use) + decryptor.finalize()
    dc = unpad(dc, 128)
    print("Le message en décrypté est: ", dc.decode())
