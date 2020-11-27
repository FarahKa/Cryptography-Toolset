# To add a new cell, type '# %%'
# To add a new markdown cell, type '# %% [markdown]'
# %%
#How I generated the salt and saved it, this will not be run every time.
from base64 import b64encode
import os
salt = os.urandom(16)
print(salt)
print(type(salt))
salt = b64encode(salt).decode('ascii')
with open("salt.txt", "a+") as saltfile:
    saltfile.write(salt)
exit()

#b'(,<\xc4\x8ao\x95\xf3\xd4(\xeeA\x96{\x88%'


# %%
#test on reading the salt, also won't be run
from base64 import b64decode
with open("salt.txt", "r") as saltfile:
    salt= saltfile.readline()
    print(salt)
    print(b64decode(salt))


from cryptography.fernet import Fernet
from base64 import b64decode
import hashlib
import base64
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC



def symmetric_encryption():
    """Provides functionnality for encrypting a message symmetrically"""

    with open("salt.txt", "r") as saltfile: #retreiving the salt from the salt file
        salt= b64decode(saltfile.readline())

    print("Provide the message you'd like to encrypt:")
    message= input()
    print("Provide the password you'd like to encrypt it with:")
    password= input()
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))

    fernet = Fernet(key) #loading up the key into fernet
    encrypted = fernet.encrypt(message.encode()) #encrypting the message
    print("Your symetrically encrypted message is:")
    print(encrypted.decode('ascii'))
    print("Would you like to save your encrypted message to a file? y/n")
    answer= input()
    if answer == "y":
        print("Give a filename:")
        filename = input()
        with open(filename.strip()+".txt", "w") as messageFile:
            messageFile.write(encrypted.decode('ascii'))
    input()


def symmetric_decryption():
    """Decrypts a symmetrically crypted message"""

    with open("salt.txt", "r") as saltfile: #retreiving the salt from the salt file
       salt= b64decode(saltfile.readline())

    print("Provide the message you would like to decrypt:")
    message=input()
    print("Provide the password you'd like to decrypt it with:")
    password= input()
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    fernet = Fernet(key)
    print("Your decrypted message is:")
    print(fernet.decrypt(message.encode()).decode('ascii'))



def hashing():
    """Hashes the given message."""
    print("Choose a hash algorithm:")
    print(hashlib.algorithms_available) #lists all the available algorithms we can use
    algo = input() #we'll have to check li el user input is fel algorithms_available
    if algo not in hashlib.algorithms_available:
        print("Algorithme choisi non valide")
        return
    print("What do you want to hash?")
    toHash = input()
    print("The hash is:")
    h = hashlib.new(algo) #creates an object that can hash stuff with the algorithm you give it
    h.update(toHash.encode()) #update adds the stuff you want to hash, encode is because youhave to give it something binary, not a string
    print(h.hexdigest()) #hexdigest gives you the hash.yeyyyyyy done

def dictionnary_Attack():
    """Attacks the password using a dictionnary"""
    print("Choose the hash algorithm with which the password was hashed:")
    print(hashlib.algorithms_available) #lists all the available algorithms we can use
    algo = input() #we'll have to check li el user input is fel algorithms_available
    if algo not in hashlib.algorithms_available:
        print("Algorithm is unavailable.")
        return
    hasher = hashlib.new(algo)
    print("Write the hashed password you want to attack:")
    hpassword = input().strip() #no trailing whitespaces
    #primary check: if the hash doesn't even have the right length ça sert à rien de continuer:
    hasher.update(b"test")
    if len(hpassword) != len(hasher.hexdigest()):
        print("The given hash does not have the right length for the given algorithm.")
        return
    with open("words.txt", "r") as dictionary: #opening the file dictionnary
        for line in dictionary: #treating it line by line
            words = line.split() #lines contain many words so we split on whitespaces
            for word in words:  
                hasher = hashlib.new(algo) # on reinitialise le hasher à chaque utilisation: il en faut un nouveau hasher car sinon la fct "update" concatène au lieu de remplacer.
                hasher.update(word.encode())
                if hpassword == hasher.hexdigest():
                    print("The password is:", word)
                    return
    print("No match found :(")
    return

def add_words_dico():
    """adds words to the dictionnary"""
    print("Write the words you wish to add to the dictionnary, separated by a white space :")
    toAdd = input().strip()
    if len(toAdd):
        with open("words.txt", "a+") as dictionary:
            dictionary.write(toAdd + "\n")
            print("The words were added successfully") #checked this with a function to see last n lines of files, will send it to you
        return
    print("There were no words")
    return
    
            
            
            
def menu_hash():
    print("Menu:")
    print("1) Hash something")
    print("2) Unhash something")
    print("3) Add words to dictionnary")
    print("4) Quit")
    a = input() # to get input from the user
    if(a == "1"):
        hashing()
    if(a == "2"):
        dictionnary_Attack()
    if(a == "3"):
        add_words_dico()
    if(a == "4"):
        return
        
def menu_crypt():
    print("Menu:")
    print("1) Symmetrically encrypt a message")
    print("2) Symmetrically decrypt a message")
    o= input()
    if o == "1":
        symmetric_encryption()
    if o == "2":
        symmetric_decryption()
        
        
        

print("Choose what you'd like to work on:")
print("1) Hashing, and attacking a hashed password")
print("2) Symmetric encryption and decryption")
print("3) Asymmetric encryption and decryption")
print("4) Quit")
o= input()
if o == "1":
    menu_hash()
if o == "2":
    menu_crypt()
if o == "4":
    exit()