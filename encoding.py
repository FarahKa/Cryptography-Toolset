from base64 import b64encode
from base64 import b64decode

def encode():
    print("State the encoding type: (exp: utf-8, ascii )")
    entype = input()
    print("State the string you would like to encode:") 
    message = input()
    encodeTypes=["utf-8", "ascii"]
    # if(entype in encodeTypes ):
    print("Your encoded string is:")  
    print(message.encode(entype).decode())
    # if(entype == "base64"):
    #     print("Your encoded message is:")  
    #     print(b64encode(message.encode()))       


def decode():
    print("State the encoding type: (exp: ascii, utf-8 )")
    entype = input()
    print("State the message you would like to decode:") 
    message = input().encode(entype)
    encodeTypes=["utf-8", "ascii"]
    # if(entype in encodeTypes ):
    print("Your decoded message is:")  
    print(message.decode(entype))
    # if(entype == "base64"):
    #     print("Your decoded message is:")  
    #     print(b64decode(message).decode("utf-8", 'ignore'))