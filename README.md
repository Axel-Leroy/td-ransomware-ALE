# td-ransomware-ALE

1. Le nom de cet algorithme est le chiffrement XOR. Il n'est pas très robuste. Sa faille principale est liée à la répétition de la clé. Il est possible de deviner la clé grâce aux statistiques : la clé se répète et le message a certainement des mots fréquents devinables.

2. L'utilisation d'un HMAC rend un brute force plus long et moins efficace grâce à un grand nombre d'itérations. On évite donc de hacher directement pour limiter le brute force.

3. Il faut vérifier qu'un fichier token.bin n'existe pas afin d'éviter les doublons et d'éviter d'écraser/supprimer des données d'un autre token, duquel peuvent dépendre d'autres informations essentielles.

4. On vérifie que la clé est bonne en la dérivant avec le salt (obtenu depuis le fichier salt.bin). Cela génère un token qui sera identique au token généré par l'attanquant (se trouvant dans le fichier token.bin) uniquement si la clé est bonne. Il suffit donc de vérifier que les tokens sont égaux.