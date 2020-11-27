import os

from cryptography.exceptions import UnsupportedAlgorithm

import asymmetric_ecies
import asymmetric_rsa

os.makedirs("private_keys/rsa", exist_ok=True)
os.makedirs("public_keys/rsa", exist_ok=True)
os.makedirs("private_keys/ecies", exist_ok=True)
os.makedirs("public_keys/ecies", exist_ok=True)


def algorithms():
    print("Choose an algorithm :")
    print("1) RSA")
    print("2) ECIES : Elliptic Curve Integrated Encryption Scheme")
    return input()


def asymmetric_encryption(algo):
    print("Provide the message you'd like to encrypt:")
    message = input()
    message = message.encode('utf-8')
    print("Provide the public key you'd like to encrypt with:")
    print("1) Load key from file")
    print("2) Type in key")
    i = input()
    if i == "2":
        print("Go ahead then..")
        public_key = input()

    # RSA
    if algo == "1":
        if i == "1":
            print("Please provide key name")
            key_name = input()
            public_key = asymmetric_rsa.load_public_key_from_file(key_name + "_rsapubkey.pem")
        asymmetric_rsa.encryptt(public_key, message)
    # ECIES
    if algo == "2":
        if i == "1":
            print("Please provide key name")
            key_name = input()
            public_key = asymmetric_ecies.load_public_key_from_file(key_name + "_eciespubkey")
        asymmetric_ecies.encryptt(public_key, message)


def asymmetric_decryption(algo):
    print("Provide the ciphertext you'd like to decrypt:")
    ciphertext = input()
    ciphertext = ciphertext.encode('utf-8')
    print("Choose which way to load private key:")
    print("1) Load key from file")
    print("2) Type in key")
    i = input()
    if i == "2":
        print("Go ahead then..")
        private_key = input()
    # RSA
    if algo == "1":
        if i == "1":
            print("Please provide key name")
            key_name = input()
            print("Provide the encryption password")
            password = input()
            private_key = asymmetric_rsa.load_private_key_from_file(key_name + "_rsaprivkey.pem",
                                                                    password.encode('utf-8'))
        asymmetric_rsa.decryptt(private_key, ciphertext)
    # ECIES
    if algo == "2":
        if i == "1":
            print("Please provide key name")
            key_name = input()
            print("Provide the encryption password")
            password = input()
            private_key = asymmetric_ecies.load_private_key_from_file(key_name + "_eciesprivkey",
                                                                    password.encode('utf-8'))
        asymmetric_ecies.decryptt(private_key, ciphertext)


def generate_keys(algo):
    print("Name ? (no spaces)")
    name = input()
    if (' ' in name) or not name:
        print("I said no spaces")
        return
    filename = name + '_rsaprivkey.pem'
    # RSA
    if algo == "1":
        print("Key size ? (default 4096)")
        s = input()
        try:
            s = int(s)
            if s < 512:
                print("Must be over 512")
                return
        except:
            s = 4096
        print("Public exponent ? (3 or 65537)(default 65537)")
        p = input()
        try:
            p = int(p)
            if p not in [65537, 3]:
                print("Unusable public exponent")
                return
        except:
            p = 65537
        priv = asymmetric_rsa.rsa_key_generation(s, p)

        print("Please provide an encryption password : ")
        enc_password = input()
        asymmetric_rsa.save_keys_to_file(priv, filename, enc_password)
    # ECIES
    if algo == "2":
        priv, pub = asymmetric_ecies.ecies_key_generation()
        filename = name + '_eciesprivkey'
        print("Please provide an encryption password : ")
        enc_password = input()
        asymmetric_ecies.save_keys_to_file(priv, pub, filename, enc_password)


def list_public_keys(algo):
    if algo == "1":
        asymmetric_rsa.list_public_keys()
    if algo == "2":
        asymmetric_ecies.list_public_keys()


def list_private_keys(algo):
    if algo == "1":
        asymmetric_rsa.list_private_keys()
    if algo == "2":
        asymmetric_ecies.list_private_keys()


def menu_asym():
    print("Menu:")
    print("1) Generate keys")
    print("2) Asymmetrically encrypt a message")
    print("3) Asymmetrically decrypt a message")
    print("4) List saved public keys")
    print("5) List saved private keys")
    o = input()
    error_m = 'Asymmetric encryption failed'
    try:
        if o == "1":
            generate_keys(algorithms())
        if o == "2":
            asymmetric_encryption(algorithms())
        if o == "3":
            asymmetric_decryption(algorithms())
            error_m = "Asymmetric decryption failed"
        if o == "4":
            list_public_keys(algorithms())
        if o == "5":
            list_private_keys(algorithms())
    except UnsupportedAlgorithm:
        print(error_m)


menu_asym()
