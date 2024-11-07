# TP-ransomware
1- Cet algorithme permet de faire un chiffrement XOR d'où son nom, néanmoins il n'est pas robuste en raison de sa simplicité en effet un chiffrement xor est assez simple à mettre en place. Une personne ayant accès à plusieurs messages pourrait réussir à décoder la clé. De plus si on utilise une clé courte et répétée cela rend le code vulnérable.	

2 - Ici on ne dérive pas la clé directement car c'est moins robuste, en effet un simple hachage rend le cryptage plus vulnérable car plus rapide à décrypter, d'ailleurs les dérivations succesives dans PBKDF2 rend le code plus robuste.

3 - Il est préférable de verifier sa présence afin d'éviter des doublons ou remplacements accidentels.

4 - Pour vérifier la validité de la clé on doit utiliser le token et le salt chargé, en effet on va générer une clé à partir du salt et la clé de la victime et on va la comparer à la clé originelle.
