import binascii
import os

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_pem_private_key


def rsa_key_generation(key_size, public_exponent):
    # GENERATE NEW KEYPAIR
    private_key = rsa.generate_private_key(
        # 65537 or 3. 65537 recommended
        public_exponent=public_exponent,
        # 4096. for security reasons >= 2048 It must not be less than 512
        key_size=key_size,
        backend=default_backend()
    )
    return private_key


def save_keys_to_file(private_key, filename, enc_password):
    # save private key
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.BestAvailableEncryption(bytes(enc_password, 'utf-8'))
    )
    with open("private_keys/rsa/" + filename, 'wb') as pem_out:
        pem_out.write(pem)

    # save public key
    filename = filename.replace("privkey.pem", "pubkey.pem")
    pemm = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open("public_keys/rsa/" + filename, 'wb') as pem_out:
        pem_out.write(pemm)


def load_private_key_from_file(filename, enc_password):
    with open("private_keys/rsa/" + filename, 'rb') as pem_in:
        pemlines = pem_in.read()
    private_key = load_pem_private_key(pemlines, enc_password, default_backend())
    return private_key


def load_public_key_from_file(filename, ):
    with open("public_keys/rsa/" + filename, 'rb') as pem_in:
        pemlines = pem_in.read()
    public_key = load_pem_public_key(pemlines)
    return public_key


# RSA
def encryptt(public_key, message):
    ciphertext = public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    print("Encrypted : " + binascii.hexlify(ciphertext).decode("utf-8"))


# RSA
def decryptt(private_key, ciphertext):
    plaintext = private_key.decrypt(
        binascii.unhexlify(ciphertext),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    # decrypted_cipher_text = plaintext.decode('utf-8')
    print("Decrypted : " + str(plaintext))


def list_public_keys():
    files = os.listdir("public_keys/rsa")
    for f in files:
        with open("public_keys/rsa/" + f, 'rb') as pem_in:
            key = pem_in.read()
        print(f + " :")
        print(key.decode("utf-8"))


def list_private_keys():
    print("NOTE : the keys are encrypted")
    files = os.listdir("private_keys/rsa")
    for f in files:
        with open("private_keys/rsa/" + f, 'rb') as pem_in:
            key = pem_in.read()
        print(f + " :")
        print(key.decode("utf-8"))
