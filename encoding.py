from base64 import b64encode
from base64 import b64decode

def encode():
    print("State the encoding type: (exp: utf-8, ascii )")
    entype = input()
    print("State the string you would like to encode:") 
    message = input()
    #encodeTypes=["utf-8", "ascii"]
    # if(entype in encodeTypes ):
    print("Your encoded string is:")  
    em= message.encode(entype)
    print(str(em))
    print("Its type is: ", type(em))
    print("Would you like to save your encoded message to a file? y/n")
    answer = input()
    if answer == "y":
        print("Give a filename:")
        filename = input()
        with open(filename.strip(), "w") as encodedFile:
            encodedFile.write(str(em))
    # if(entype == "base64"):
    #     print("Your encoded message is:")  
    #     print(b64encode(message.encode()))       


def decode():
    print("State the encoding type: (exp: ascii, utf-8 )")
    entype = input()
    print("State the name of the file containing the text you would like to decode:") 
    fileName = input()
    with open(fileName, "rb") as encodedTextFile:
        encodedText = encodedTextFile.read(1)

    print(type(encodedText))
    print(encodedText)
    # message=input()
    # print(type(message))
    # print(message)
    # print(bytes(message, encoding=entype))
    # print(type(bytes(message, encoding=entype)))
    # print(message.encode(entype))
    # print(type(message.encode(entype)))
    
    #encodeTypes=["utf-8", "ascii"]
    # if(entype in encodeTypes ):
    print("Your decoded message is:")  
    print(encodedText.decode(entype).decode(entype))
    # if(entype == "base64"):
    #     print("Your decoded message is:")  
    #     print(b64decode(message).decode("utf-8", 'ignore'))


decode()