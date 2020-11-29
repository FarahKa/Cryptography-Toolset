import binascii
import os

from cryptography.hazmat.primitives.asymmetric import ec
from ecies import encrypt, decrypt, hex2prv, hex2pub
from ecies.utils import generate_eth_key


def ecies_key_generation():
    private_key = ec.generate_private_key(ec.SECP384R1())
    public_key = private_key.public_key()


    priv_key = generate_eth_key()
    priv_key_hex = priv_key.to_hex()
    pub_key_hex = priv_key.public_key.to_hex()
    return priv_key_hex, pub_key_hex


def save_keys_to_file(private_key_hex, public_key_hex, filename, enc_password):
    # encrypt key first
    from security_project import sym_encrypt
    with open("private_keys/ecies/" + filename, 'wb') as out:
        out.write(sym_encrypt(private_key_hex, enc_password))

    filename = filename.replace("eciesprivkey", "eciespubkey")
    with open("public_keys/ecies/" + filename, 'w') as out:
        out.write(public_key_hex)


def load_private_key_from_file(filename, enc_password):
    try:
        with open("private_keys/ecies/" + filename, 'rb') as out:
            key = out.read()
        from security_project import sym_decrypt
        return sym_decrypt(key.decode("utf-8"), enc_password)
    except FileNotFoundError:
        print("Can't find key oops")


def load_public_key_from_file(filename):
    try:
        with open("public_keys/ecies/" + filename, 'r') as out:
            key = out.read()
        return key
    except FileNotFoundError:
        print("Can't find key oops")


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


# def prehash():
#     print("Is the message pre hashed ?(yes/no)")
#     yes = input()
#     if yes == "yes":
#         # function tprinti l hashes wl user ya5tar
#         chosen_hash = hashes.SHA256()
#         hashh = utils.Prehashed(chosen_hash)
#     if yes == "no":
#         hashh = hashes.SHA256()
#     else:
#         return
#     return hashh


def verify(public_key_hex, sig, message):
    public_key = hex2pub(public_key_hex)
    if public_key.verify(binascii.unhexlify(sig), message.encode("utf-8")):
        print('Signature matches yay')
    else:
        print("Signature does not match")


def sign(private_key_hex, message):
    # hashh = prehash()
    # if not hashh:
    #     return
    print("Message : ")
    print(message)
    print("Signature : ")
    private_key = hex2prv(private_key_hex)
    signature = private_key.sign(message.encode("utf-8"))
    print(binascii.hexlify(signature).decode("utf-8"))



