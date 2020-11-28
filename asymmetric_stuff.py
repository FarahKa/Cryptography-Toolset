import os
from cryptography.exceptions import UnsupportedAlgorithm
import asymmetric_ecies
import asymmetric_rsa

os.makedirs("private_keys/rsa", exist_ok=True)
os.makedirs("public_keys/rsa", exist_ok=True)
os.makedirs("private_keys/ecies", exist_ok=True)
os.makedirs("public_keys/ecies", exist_ok=True)


def provide_encryption_password():
    enc_password = ''
    while not enc_password:
        print("Please provide encryption password : ")
        enc_password = input()
        if not enc_password:
            print("password can't be empty")
    return enc_password


def algorithms():
    i = "0"
    while i not in ["1", "2"]:
        print("Choose an algorithm :")
        print("1) RSA")
        print("2) ECIES : Elliptic Curve Integrated Encryption Scheme")
        i = input()
    return i

def provide_public_key(algo):
    print("Choose which way to load public key:")
    print("1) Load key from file")
    print("2) Type in key")
    i = input()
    if i not in ["1", "2"]:
        return
    if i == "2":
        print("Go ahead then..")
        public_key = input()
    if i == "1":
        if algo == "1":
            print("Please provide key name")
            key_name = input()
            public_key = asymmetric_rsa.load_public_key_from_file(key_name + "_rsapubkey.pem")
        if algo == "2":
            print("Please provide key name")
            key_name = input()
            public_key = asymmetric_ecies.load_public_key_from_file(key_name + "_eciespubkey")
        if not public_key:
            return
    return public_key


def asymmetric_encryption(algo):
    print("Provide the message you'd like to encrypt:")
    message = input()
    message = message.encode('utf-8')
    public_key = provide_public_key(algo)
    # RSA
    if algo == "1":
        asymmetric_rsa.encryptt(public_key, message)
    # ECIES
    if algo == "2":
        asymmetric_ecies.encryptt(public_key, message)

def provide_private_key(algo):
    print("Choose which way to load private key:")
    print("1) Load key from file")
    print("2) Type in key")
    i = input()
    if i not in ["1", "2"]:
        return
    if i == "2":
        print("Go ahead then..")
        private_key = input()
    if i == "1":
        if algo == "1":
            print("Please provide key name")
            key_name = input()
            enc_password = provide_encryption_password()
            private_key = asymmetric_rsa.load_private_key_from_file(key_name + "_rsaprivkey.pem",
                                                                    enc_password.encode('utf-8'))
        if algo == "2":
            print("Please provide key name")
            key_name = input()
            enc_password = provide_encryption_password()
            private_key = asymmetric_ecies.load_private_key_from_file(key_name + "_eciesprivkey",
                                                                      enc_password.encode('utf-8'))
        if not private_key:
            return
    return  private_key

def asymmetric_decryption(algo):
    print("Provide the ciphertext you'd like to decrypt:")
    ciphertext = input()
    ciphertext = ciphertext.encode('utf-8')
    private_key = provide_private_key(algo)
    # RSA
    if algo == "1":
        asymmetric_rsa.decryptt(private_key, ciphertext)
    # ECIES
    if algo == "2":

        asymmetric_ecies.decryptt(private_key, ciphertext)


def generate_keys(algo):
    name = ''
    while (' ' in name) or (not name):
        print("Name ? (no spaces)")
        name = input()
        if (' ' in name) or not name:
            print("I said no spaces")
        else:
            if (algo == "2" and os.path.isfile("private_keys/ecies/" + name + "_eciesprivkey")) \
                    or (algo == "1" and os.path.isfile("private_keys/rsa/" + name + "_rsaprivkey.pem")):
                print("Key name already in use")
                name = ''

    filename = name + '_rsaprivkey.pem'
    # RSA
    if algo == "1":
        s = 510
        while s < 512:
            print("Key size ? (default 4096)")
            s = input()
            try:
                s = int(s)
                if s < 512:
                    print("Must be over 512")
            except:
                s = 4096
        p = 5
        while p not in [65537, 3]:
            print("Public exponent ? (3 or 65537)(default 65537)")
            p = input()
            try:
                p = int(p)
                if p not in [65537, 3]:
                    print("Unusable public exponent")
            except:
                p = 65537
        priv = asymmetric_rsa.rsa_key_generation(s, p)
        enc_password = provide_encryption_password()
        asymmetric_rsa.save_keys_to_file(priv, filename, enc_password)
    # ECIES
    if algo == "2":
        priv, pub = asymmetric_ecies.ecies_key_generation()
        filename = name + '_eciesprivkey'
        enc_password = provide_encryption_password()
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


def sign(algo):
    print("Provide message")
    msg = input()
    private_key = provide_private_key(algo)
    if algo == "1":
        asymmetric_rsa.sign(private_key, msg)
    if algo == "2":
        asymmetric_ecies.sign()


def verify(algo):
    print("Provide message")
    msg = input()
    print("Provide signature")
    sig = input()
    public_key = provide_public_key(algo)
    if algo == "1":
        asymmetric_rsa.verify(public_key, sig, msg)
    if algo == "2":
        asymmetric_ecies.verify()


def menu_asym():
    print("Menu:")
    print("1) Generate keys")
    print("2) Asymmetrically encrypt a message")
    print("3) Asymmetrically decrypt a message")
    print("4) Sign a message")
    print("5) Verify a message")
    print("6) List saved public keys")
    print("7) List saved private keys")
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
            sign(algorithms())
        if o == "5":
            verify(algorithms())
        if o == "6":
            list_public_keys(algorithms())
        if o == "7":
            list_private_keys(algorithms())
    except UnsupportedAlgorithm:
        print(error_m)


menu_asym()
