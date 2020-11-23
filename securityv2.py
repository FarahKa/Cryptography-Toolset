#!/usr/bin/env python
# coding: utf-8

# In[ ]:


import hashlib



def hashing():
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
    print("Write the words you wish to add to the dictionnary, separated by a white space:")
    toAdd = input().strip()
    if len(toAdd):
        with open("words.txt", "a+") as dictionary:
            dictionary.write(toAdd + "\n")
            print("The words were added successfully.") #checked this with a function to see last n lines of files, will send it to you
        return
    print("There were no words.")
    return
    
            
            
            
def menu_hash():
    while True:
        print("Menu:")
        print("1) Hash something.")
        print("2) Unhash Something.")
        print("3) Add words to dictionnary.")
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
        
        
while True:
    print("Choose what you'd like to work on:")
    print("1) Hashing, and attacking a hashed password.")
    print("2) Ecrypting messages...")
    print("3) Quit")
    o= input()
    if o == "1":
        menu_hash()
    if o == "2":
        menu_crypt()
    if o == "3":
        exit()
                
        


# In[ ]:





# In[ ]:




