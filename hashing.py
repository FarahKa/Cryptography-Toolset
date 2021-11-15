import hashlib
from os import listdir
from os.path import isfile, join
from itertools import combinations_with_replacement
import gc

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
    return h.hexdigest()


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