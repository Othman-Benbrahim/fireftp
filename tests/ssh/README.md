# Tests SSH hors navigateur (Node.js 18+)

Ces scripts exécutent la bibliothèque `paramikojs` de FireFTP dans Node.js, avec une
imitation minimale des services XPCOM de Pale Moon (hachage, HMAC, conversion UTF-8).
Ils ne remplacent pas un test dans Pale Moon, mais valident la couche SSH/SFTP.

## Signatures RSA (aucun serveur requis)

    node tests/ssh/test_rsa.js

Vérifie `ssh-rsa`, `rsa-sha2-256` et `rsa-sha2-512` dans les deux sens contre OpenSSL.

## Connexion réelle à un serveur SSH

PowerShell :

    $env:SSH_HOST="exemple.org"; $env:SSH_PORT="22"; $env:SSH_USER="moi"
    $env:SSH_PASS="secret"; node tests/ssh/harness.js password
    $env:SSH_KEY="C:\chemin\id_rsa"; node tests/ssh/harness.js key

La clé doit être une clé RSA non chiffrée (format PEM ou PKCS#8).
`EXPECT=nom_de_fichier` fait échouer le test si ce fichier n'apparaît pas dans le
dossier d'accueil distant. Le script affiche l'algorithme de clé hôte négocié.
