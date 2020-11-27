import binascii
import os

from ecies import encrypt, decrypt
from ecies.utils import generate_eth_key


def ecies_key_generation():
    priv_key = generate_eth_key()
    priv_key_hex = priv_key.to_hex()
    pub_key_hex = priv_key.public_key.to_hex()
    return priv_key_hex, pub_key_hex


def save_keys_to_file(private_key_hex, public_key_hex, filename, enc_password):
    # encrypt key first
    with open("private_keys/ecies/" + filename, 'w') as out:
        out.write(private_key_hex)

    filename = filename.replace("eciesprivkey", "eciespubkey")
    with open("public_keys/ecies/" + filename, 'w') as out:
        out.write(public_key_hex)


def load_private_key_from_file(filename, enc_password):
    with open("private_keys/ecies/" + filename, 'r') as out:
        key = out.read()
    return key


def load_public_key_from_file(filename):
    with open("public_keys/ecies/" + filename, 'r') as out:
        key = out.read()
    return key


def encryptt(pub_key_hex, message):
    encrypted = binascii.hexlify(encrypt(pub_key_hex, bytes(message)))
    print("Encrypted:", encrypted.decode("utf-8"))


def decryptt(priv_key_hex, cipher_text):
    decrypted = decrypt(priv_key_hex, binascii.unhexlify(cipher_text))
    print("Decrypted:", decrypted)


def list_public_keys():
    files = os.listdir("public_keys/ecies")
    for f in files:
        key = load_public_key_from_file(f)
        print(f+" : "+key)


def list_private_keys():
    print("NOTE : the keys are encrypted")
    files = os.listdir("private_keys/ecies")
    for f in files:
        with open("private_keys/ecies/" + f, 'r') as out:
            key = out.read()
        print(f+" : "+key)
