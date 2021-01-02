from base64 import b64encode
from base64 import b64decode

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