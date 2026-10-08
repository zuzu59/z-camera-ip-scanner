# Scanner de caméra IP

Application web locale pour inventorier les ports TCP ouverts d’une caméra IP, distinguer les protocoles confirmés des hypothèses, et tester les services HTTP(S), RTSP, ONVIF et XM/DVRIP.

## Documentation technique

Voir [ARCHITECTURE.md](ARCHITECTURE.md) pour le fonctionnement interne, les routes API, le cycle des tâches, le scan réseau et la vérification des flux média.

## Fonctionnalités

- Scanne les ports TCP `1–65535` d’une seule adresse IP.
- Distingue les protocoles observés (avec preuve) des services seulement supposés d’après le numéro de port.
- Teste HTTP(S) sur tous les ports ouverts détectés; expose le statut HTTP, le serveur annoncé et les défis d’authentification.
- Vérifie les flux RTSP/RTSPS et les chemins de snapshot/vidéo HTTP(S); seuls les médias reconnus sont copiables.
- Vérifie ONVIF, distingue l’authentification requise et détecte le PTZ à partir des capacités, profils et réponse PTZ; l’interface affiche le port du service PTZ sans commander de mouvement.
- Sur le port XM/DVRIP courant `34567`, peut vérifier le protocole avec une seule tentative utilisant les identifiants saisis; aucune combinaison n’est devinée.
- Détecte le format et, lorsque disponibles, le codec et la résolution.
- Prend en charge l’authentification HTTP Basic et Digest.
- Fournit une interface web accessible sur le réseau local.

## Prérequis

- Python 3.10 ou plus récent, avec le module `venv`.
- Une connexion Internet lors de la première installation des dépendances (installation via `pip`).
- Aucun accès `sudo` n’est requis : l’environnement Python et ses dépendances sont installés dans le dossier local `.venv/`.

## Installation et démarrage

Le script `start.sh` prépare automatiquement l’environnement virtuel, installe ou vérifie les dépendances listées dans `requirements.txt`, puis lance le serveur en arrière-plan :

```bash
./start.sh
```

La première exécution peut prendre un peu de temps, le temps de créer `.venv/` et d’installer Flask, OpenCV (version headless) et NumPy. Les dépendances sont installées dans le projet, pas globalement sur le système. Les exécutions suivantes vérifient les dépendances et démarrent le scanner.

Le serveur écoute par défaut sur toutes les interfaces (`0.0.0.0:8092`). Le script détecte automatiquement l’adresse IP réseau de la machine et affiche l’URL à ouvrir, par exemple :

```text
URL : http://192.168.0.92:8092/
```

Ouvrez cette URL depuis un navigateur sur la machine ou un appareil du même réseau. L’adresse affichée dépend du réseau de la machine.

### Autre méthode : installation et démarrage manuels

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python scan_camera.py
```

Par défaut, `scan_camera.py` écoute aussi sur `0.0.0.0:8092`. Pour changer l’adresse d’écoute, définissez `SCAN_CAMERA_HOST`, par exemple :

```bash
SCAN_CAMERA_HOST=127.0.0.1 .venv/bin/python scan_camera.py
```

## Commandes du script

```bash
./start.sh             # démarre le scanner (commande par défaut)
./start.sh start       # démarre le scanner
./start.sh status      # affiche l’état et l’URL d’accès
./start.sh restart     # arrête puis redémarre le scanner
./start.sh stop        # arrête le scanner
./start.sh --help      # affiche l’aide détaillée
```

Les journaux sont écrits dans `scan_camera.log`. Le script conserve le PID dans `.scan_camera.pid` pour contrôler le processus. Si une autre application utilise déjà le port `8092`, le démarrage échoue : arrêtez cette application ou libérez le port avant de relancer le scanner.

## Utilisation

1. Saisissez l’adresse IP privée ou locale de la caméra. Les noms d’hôte et les sous-réseaux ne sont pas acceptés.
2. Entrez les identifiants de la caméra si nécessaire.
3. Lancez le scan des ports.
4. Cliquez sur **Tester les flux et services caméra**.
5. Copiez une URL parmi les résultats validés.

Les résultats séparent les services confirmés, les services qui réclament des identifiants et les simples hypothèses basées sur un port connu. Les chemins possibles sont testés en arrière-plan et ne sont pas copiables s’ils échouent. Le scan couvre TCP, pas l’ensemble des ports UDP ni tous les protocoles propriétaires possibles; un port inconnu est affiché comme non identifié, pas présenté comme une certitude.

## Sécurité

- Utilisez le scanner uniquement sur des caméras que vous êtes autorisé à administrer.
- L’écoute sur `0.0.0.0` rend le serveur accessible aux appareils pouvant joindre la machine sur le réseau. N’exposez pas le port `8092` sur Internet ou un réseau non fiable. Pour un usage strictement local, lancez manuellement l’application avec `SCAN_CAMERA_HOST=127.0.0.1`.
- Le navigateur transmet au serveur les URLs et identifiants nécessaires au test des médias via HTTP non chiffré. Les URLs validées peuvent afficher les identifiants en clair : utilisez uniquement un réseau de confiance.
- Les identifiants ne sont pas enregistrés dans les fichiers du projet ni conservés dans les résultats du scan. Le test XM/DVRIP n’essaie les identifiants saisis qu’une fois; un mauvais mot de passe peut déclencher le verrouillage décidé par la caméra.
- Pour réduire les risques, le scanner accepte uniquement une adresse IP privée, locale ou link-local, et ne prend pas en charge les noms d’hôte ou les sous-réseaux.

## Tests

```bash
.venv/bin/python -m unittest discover -s tests -v
```
