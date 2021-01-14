import os
import encoding as encoding
import symmetric_encryption as symen
import hashing as h
import asymmetric_stuff as asymen
from cryptography.exceptions import UnsupportedAlgorithm



def menu_encode():
    print("Choose what you'd like to work on:")
    print("1) Encoding")
    print("2) Decoding")
    o = input()
    if o == "1":
        encoding.encode()
    if o == "2":
        encoding.decode()


def menu_encrypt():
    print("Menu: Choose an algorithm:")
    print("1) AES with CTR")
    print("2) AES with CBC")
    print("3) Camellia (cbc)")
    print("4) ChaCha20")
    print("5) Triple DES")
    o = input()
    if o == "1":
        symen.symen_AES_CTR()
    if o == "2":
        symen.symen_AES_CBC()
    if o == "3":
        symen.symen_Camellia()
    if o == "4":
        symen.symen_ChaCha20()
    if o == "5":
        symen.symen_TripleDES()

def menu_decrypt():
    print("Menu: Choose an algorithm:")
    print("1) AES with CTR")
    print("2) AES with CBC")
    print("3) Camellia (cbc)")
    print("4) ChaCha20")
    print("5) Triple DES")
    o = input()
    if o == "1":
        symen.symdec_AES_CTR()
    if o == "2":
        symen.symdec_AES_CBC()
    if o == "3":
        symen.symdec_Camellia()
    if o == "4":
        symen.symdec_ChaCha20()
    if o == "5":
        symen.symdec_TripleDES()

def menu_crypt():
    print("Menu:")
    print("1) Symmetrically encrypt a message")
    print("2) Symmetrically decrypt a message")
    o = input()
    if o == "1":
        menu_encrypt()
    if o == "2":
        menu_decrypt()



def menu_hash():
    print("Menu:")
    print("1) Hash a message")
    print("2) Crack a hashed message")
    print("3) Create a dictionary")
    print("4) Add words to an existing dictionary")
    print("5) Quit")
    a = input()  # to get input from the user
    if a == "1":
        h.hashing()
    if a == "2":
        menu_attack()
    if a == "3":
        h.create_dictionary()
    if a == "4":
        h.add_words_to_dictionary()
    if a == "5":
        return

def menu_attack():
    print("Menu:")
    print("1) Dictionary attack")
    print("2) Simple brute force attack")
    print("3) Identify hash algorithm")
    print("4) Quit")
    a = input()  # to get input from the user
    if a == "1":
        h.dictionary_attack()
    if a == "2":
        h.simple_brute_force_attack()
    if a == "3":
        h.identify_hash()
    if a == "4":
        return

def menu_asym():
    print("Menu:")
    print("1) Generate keys")
    print("2) Asymmetrically encrypt a message")
    print("3) Asymmetrically decrypt a message")
    print("4) Sign a message")
    print("5) Verify a message")
    print("6) List saved public keys")
    print("7) List saved private keys")
    print("8) Change a saved private key's encryption password")
    o = input()
    error_m = 'Asymmetric encryption failed'
    try:
        if o == "1":
            asymen.generate_keys(asymen.algorithms())
        if o == "2":
            asymen.asymmetric_encryption(asymen.algorithms())
        if o == "3":
            asymen.asymmetric_decryption(asymen.algorithms())
            error_m = "Asymmetric decryption failed"
        if o == "4":
            asymen.sign(asymen.algorithms())
        if o == "5":
            asymen.verify(asymen.algorithms())
        if o == "6":
            asymen.list_public_keys(asymen.algorithms())
        if o == "7":
            asymen.list_private_keys(asymen.algorithms())
        if o == "8":
            asymen.change_pwd_private_key(asymen.algorithms())
    except UnsupportedAlgorithm:
        print(error_m)


os.makedirs("dics", exist_ok=True)
print("Choose what you'd like to work on:")
print("1) Encoding and decoding")
print("2) Hashing and attacking a hashed password")
print("3) Symmetric encryption and decryption")
print("4) Asymmetric encryption and decryption")
print("5) Quit")
o = input()
if o == "1":
    menu_encode()
if o == "2":
    menu_hash()
if o == "3":
    menu_crypt()
if o == "4":
    menu_asym()
if o == "5":
    exit()