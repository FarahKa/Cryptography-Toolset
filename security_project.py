# To add a new cell, type '# %%'
# To add a new markdown cell, type '# %% [markdown]'
import os
import gc
import hashlib
import base64
from base64 import b64encode
from base64 import b64decode
from os import listdir
from os.path import isfile, join
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from asymmetric_stuff import menu_asym
from itertools import combinations_with_replacement


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


def choose_hash():
    print("Choose the hash algorithm :")
    print(hashlib.algorithms_available)  # lists all the available algorithms we can use
    algo = input()  # we'll have to check li el user input is fel algorithms_available
    if algo not in hashlib.algorithms_available:
        print("Algorithm is unavailable.")
        return
    return algo


def hashing():
    """Hashes the given message."""
    algo = choose_hash()
    if not algo:
        return
    h = hashlib.new(algo)
    print("What do you want to hash?")
    to_hash = input()
    print("The hash is:")
    h.update(
        to_hash.encode())  # update adds the stuff you want to hash, encode is because youhave to give it something binary, not a string
    print(h.hexdigest())  # hexdigest gives you the hash.yeyyyyyy done


def choose_dictionary():
    print("Choose a dictionary :")
    dics = get_dic_names()
    for index, dic in enumerate(dics):
        print(str(index) + ") " + dic.split(".txt")[0])
    i = input()
    try:
        i = int(i)
        if i >= len(dics):
            print("can't find the dictionary with the index " + str(i))
            return -1
        return dics[i]
    except:
        print(str(i)+" isnt an int")
        return -1


def dictionary_attack():
    """Attacks the password using a dictionary"""
    dic = choose_dictionary()
    if dic == -1:
        return

    algo = choose_hash()
    if not algo:
        return
    hasher = hashlib.new(algo)
    print("Write the hashed password you want to attack:")
    hpassword = input().strip()  # no trailing whitespaces
    # primary check: if the hash doesn't even have the right length ça sert à rien de continuer:
    hasher.update(b"test")
    if len(hpassword) != len(hasher.hexdigest()):
        print("The given hash does not have the right length for the given algorithm.")
        return
    with open("dics/"+dic, "r") as dictionary:  # opening the file dictionary
        for line in dictionary:  # treating it line by line
            words = line.split()  # lines contain many words so we split on whitespaces
            for word in words:
                hasher = hashlib.new(
                    algo)  # on reinitialise le hasher à chaque utilisation: il en faut un nouveau hasher car sinon la fct "update" concatène au lieu de remplacer.
                hasher.update(word.encode())
                if hpassword == hasher.hexdigest():
                    print("The password is:", word)
                    return
    print("No match found :(")
    return


def get_dic_names():
    return [f for f in listdir("dics/") if isfile(join("dics/", f))]


def create_dictionary():
    print("Dictionary name ?")
    name = input()
    if ' ' in name or not name:
        return
    name = name.split(".txt")[0]
    if name in get_dic_names():
        print("Dictionary already exists")
        return
    with open("dics/" + name, "w") as dictionary:
        print("The dictionary '"+name+"' was successfully created")




def add_words_to_dictionary():
    """adds words to a dictionary"""
    dic = choose_dictionary()
    if dic == -1:
        return
    print("Write the words you wish to add to the dictionary, separated by a white space :")
    to_add = input().strip()
    if len(to_add):
        with open("dics/"+dic, "a+") as dictionary:
            dictionary.write(to_add + "\n")
            print(
                "The words were added successfully")  # checked this with a function to see last n lines of files, will send it to you
        return
    print("There were no words")
    return


def simple_brute_force_attack():
    # get l alphabet mt3na li hia hex
    stuff = []
    for chars in range(92):
        stuff.append(chr(chars + 33))
    print(stuff)
    # get l hasher
    algo = choose_hash()
    if not algo:
        return
    print("Write the hashed password:")
    hpassword = input()
    print("Provide the maximum length of the password (keep it short please):")
    max_len = input()
    try:
        max_len = int(max_len)
    except:
        print("You haven't provided an int tf")
        return
    for i in range(max_len):
        if i == 0:
            for el in stuff:
                hasher = hashlib.new(algo)
                hasher.update(el.encode())
                if hasher.hexdigest() == hpassword:
                    print("Cracked password : " + ''.join(el))
                    return
            n = gc.collect()  # clean up
        else:
            possible_words = list(combinations_with_replacement(stuff, i + 1))
            for word in possible_words:
                hasher = hashlib.new(algo)
                for thing in word:
                    hasher.update(thing.encode())
                if hasher.hexdigest() == hpassword:
                    print("Cracked password : " + ''.join(word))
                    return
    print("Couldn't crack password with simple brute force")


def identify_hash():
    s = hashlib.algorithms_available
    print("Write the hashed message (must be hex for now):")
    hash = input()  # we'll have to check li el user input is fel algorithms_available
    size = len(hash) * 4
    print("Possible hash algorithms :")
    for algo in s:
        hasher = hashlib.new(algo)
        if (hasher.digest_size * 8) == size:
            print("     - " + algo)


def menu_attack():
    print("Menu:")
    print("1) Dictionary attack")
    print("2) Simple brute force attack")
    print("3) Identify hash algorithm")
    print("4) Quit")
    a = input()  # to get input from the user
    if a == "1":
        dictionary_attack()
    if a == "2":
        simple_brute_force_attack()
    if a == "3":
        identify_hash()
    if a == "4":
        return


def menu_hash():
    print("Menu:")
    print("1) Hash a message")
    print("2) Crack a hashed message")
    print("3) Create a dictionary")
    print("4) Add words to an existing dictionary")
    print("5) Quit")
    a = input()  # to get input from the user
    if a == "1":
        hashing()
    if a == "2":
        menu_attack()
    if a == "3":
        create_dictionary()
    if a == "4":
        add_words_to_dictionary()
    if a == "5":
        return


def menu_crypt():
    print("Menu:")
    print("1) Symmetrically encrypt a message")
    print("2) Symmetrically decrypt a message")
    o = input()
    if o == "1":
        symmetric_encryption()
    if o == "2":
        symmetric_decryption()


def gen_salt():
    """Function that was used to generate the salt in the salt file."""
    salt = os.urandom(16)
    print(salt)
    print(type(salt))
    salt = b64encode(salt).decode('ascii')
    with open("salt.txt", "a+") as saltfile:
        saltfile.write(salt)
    # exit()
    # b'(,<\xc4\x8ao\x95\xf3\xd4(\xeeA\x96{\x88%'

# test on reading the salt, also won't be run
def read_salt():
    with open("salt.txt", "r") as saltfile:
        salt = saltfile.readline()
    print(salt)
    print(b64decode(salt))

def encode():
    print("State the encoding type: (exp: base64 )")
    entype = input()
    print("State the message you would like to encode:") 
    message = input()
    encodeTypes=["utf-8", "ascii"]
    if(entype in encodeTypes ):
        print("Your encoded message is:")  
        print(message.encode(entype))
    if(entype == "base64"):
        print("Your encoded message is:")  
        print(b64encode(message.encode()))       


def decode():
    print("State the encoding type: (exp: base64 )")
    entype = input()
    print("State the message you would like to decode:") 
    message = input()
    encodeTypes=["utf-8", "ascii"]
    if(entype in encodeTypes ):
        print("Your decoded message is:")  
        print(message.decode(entype))
    if(entype == "base64"):
        print("Your decoded message is:")  
        print(b64decode(message.encode()).decode('utf-8'))       


def menu_encode():
    print("Choose what you'd like to work on:")
    print("1) Encoding")
    print("2) Decoding")
    o = input()
    if o == "1":
        encode()
    if o == "2":
        decode()


if __name__ == "__main__":
    # bch when i import this to use l encryption mayrunnich all this 3andi
    # stuff only to run when not called via 'import' here

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
