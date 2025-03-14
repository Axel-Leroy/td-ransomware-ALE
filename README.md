# td-ransomware-ALE

1. Le nom de cet algorithme est le chiffrement XOR. Il n'est pas très robuste. Sa faille principale est liée à la répétition de la clé. Il est possible de deviner la clé grâce aux statistiques : la clé se répète et le message a certainement des mots fréquents devinables.

2. L'utilisation d'un HMAC rend un brute force plus long et moins efficace grâce à un grand nombre d'itérations. On évite donc de hacher directement pour limiter le brute force.