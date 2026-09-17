# FireFTP pour Pale Moon

Fork de [FireFTP](https://github.com/mimecuvalo/fireftp) de Mime Čuvalo, maintenu pour
fonctionner avec **Pale Moon 29 à 35.x** et avec les **serveurs OpenSSH récents**.
Le développement du FireFTP d'origine s'est arrêté à la version 2.0.32.

## Correctifs de la version 2.0.33

**Connexion SFTP aux serveurs OpenSSH 8.8 et plus récents.** Le symptôme était l'erreur
`NS_ERROR_FAILURE [nsIBinaryInputStream.readBytes]` dans `ssh2.js`. La cause : FireFTP
ne proposait que `ssh-rsa` (SHA-1) et `ssh-dss` pour la clé d'hôte, deux algorithmes
qu'OpenSSH refuse par défaut. Le serveur fermait alors la connexion.
- Clé d'hôte : ajout de `rsa-sha2-512` et `rsa-sha2-256` (RFC 8332). La signature doit
  correspondre à l'algorithme négocié.
- Authentification par clé RSA : prise en charge de `server-sig-algs` (RFC 8308).
  Le client utilise `rsa-sha2-512`/`256` si le serveur les annonce, sinon `ssh-rsa`
  pour les anciens serveurs. Les clés fournies par un agent SSH suivent la même règle.
- `ssh2.js` : la lecture du flux tolère la fermeture par le serveur. Un échec de
  négociation affiche désormais un message explicite.

**Autres changements**
- `install.rdf` cible uniquement Pale Moon (29.0 à 35.*).
- Les entrées de menu sont placées correctement dans le menu Développeur web de Pale Moon.
- Plus d'onglet `fireftp.net/donate` ouvert à l'installation.
- `paramikojs` est intégré au dépôt au lieu d'un sous-module (base : commit `d2c4e7e`
  de [mimecuvalo/paramikojs](https://github.com/mimecuvalo/paramikojs), modifié ici).
- Scripts de build : `src/build.ps1` (Windows) et `src/build.sh` (bash) produisent
  `dist/fireftp-<version>-palemoon.xpi`.

**Limites connues** : les serveurs qui n'offrent *que* des clés d'hôte Ed25519 ou
ECDSA restent incompatibles. Les clés client Ed25519 ne sont pas prises en charge.

## Construire le XPI

Windows (PowerShell 5.1 ou 7) :

    cd src
    .\build.ps1                    # -> dist\fireftp-2.0.33-palemoon.xpi
    .\build.ps1 -Version 2.0.34    # autre numéro de version

Si PowerShell bloque le script : `powershell -ExecutionPolicy Bypass -File .\build.ps1`

Linux / macOS / Git Bash (nécessite `zip`) :

    cd src && bash build.sh

N'utilisez pas `Compress-Archive` pour empaqueter à la main. Sous Windows PowerShell 5.1,
il écrit des chemins avec `\`, et Pale Moon refuse le XPI.

## Installer

Dans Pale Moon : Outils → Modules complémentaires → roue dentée →
« Installer un module depuis un fichier… » → choisir le `.xpi`.
Désinstallez d'abord une éventuelle ancienne version de FireFTP.

## Tests

Voir [tests/ssh/README.md](tests/ssh/README.md) (Node.js 18+).

## Licence

MIT, voir `src/license.txt`. Copyright © 2004-présent Mime Čuvalo et contributeurs.
`paramikojs` est un portage de paramiko, sous sa propre licence (voir
`src/content/js/connection/paramikojs/license.txt`).
