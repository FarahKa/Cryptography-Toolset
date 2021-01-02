import base64
from base64 import b64encode
from base64 import b64decode
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


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