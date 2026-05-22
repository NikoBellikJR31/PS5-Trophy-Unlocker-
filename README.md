# Trophy Unlocker PS5 ELF
Tool PC pour envoyer une payload Trophy Unlocker sur une console PS5 compatible avec un jeu déjà lancé.

Le choix des trophées se fait depuis le PC avec le lanceur. Le projet garde l'esprit du payload de base, mais il a été fortement modifié et étendu avec un lanceur PC, plusieurs modes d'envoi, des rapports debug, une détection PS4/PS5...

## Vidéo de démonstration

[![Voir la démonstration](https://img.youtube.com/vi/amzFqTmyxbs/maxresdefault.jpg)](https://www.youtube.com/watch?v=amzFqTmyxbs)

> Projet expérimental pour développeurs/homebrew. Utilisation à vos risques.      Tester sur FW 6.02/kstuff 1.6.7 Ps5 Debug 1.05

## Base et modifications

Ce projet est basé sur le travail public de John Törnblom autour des payloads PS5 et de `ps5-payload-elfldr`.

La base d'origine a été fortement modifiée notamment pour ajouter :

- un lanceur PC en `.bat` et `.ps1` ;
- des modes `all`, `id`, `wave`, `range`, `list` ;
- un mode debug avec rapport côté PC ;
- des logs TCP sur `9022` ;
- la gestion des fichiers de configuration temporaires ;
- la détection PS4 / PS5 ;
- des tests Trophy1 / Trophy2 / UDS ;
- des vérifications et messages d'erreur plus détaillés.

## Fichiers importants

```text
PS5 Unlocker.elf              Payload normal envoyée dans le process du jeu
PS5 Unlocker DEBUG.elf        Payload debug séparée avec logs TCP
LANCER_UNLOCKER.bat           Lanceur simple en double-clic
LANCER_UNLOCKER.ps1           Menu PowerShell interactif
INSTALLER_PYTHON_DEPENDANCES.bat
_support/                     Scripts internes, Python portable et dépendances
debug_logs/                   Rapports debug créés sur le PC
```

## Prérequis console

Avant de lancer le tool :

- La console doit être allumée.
- Le jeu doit déjà être lancé.
- Le debug doit être actif sur le port `744`.
- Le FTP doit être actif sur le port `2121`.
- Le PC doit pouvoir joindre l'adresse IP de la console.
- Le payload loader doit être prêt côté console.

Ports utilisés :

```text
744     Debug PS5
2121    FTP
9021    Envoi payload / loader selon le mode utilisé
9022    Logs payload debug
```

Note : dans le lanceur PC, le port `9021` sert surtout à capturer ou gérer le retour payload quand tu lances `Debug rapport PC` / `-DebugReport`. En mode normal, les logs payload passent surtout par le mode debug et le port `9022`.

Configuration utilisée pendant les tests :

```text
Console : PS5
Firmware testé : 6.02
PC : Windows 11 / Windows 10 VM
Debug utilisé : PS5 Debug 1.05 
```

## Python / dépendances

Il y a 2 méthodes.

### Méthode 1 : portable, recommandée

Dans le zip :

```text
_support\python
```

Python portable est déjà inclus dans le pack. Tu peux lancer directement le tool sans installer Python sur le PC.

Double-clique simplement :

```text
LANCER_UNLOCKER.bat
```

### Méthode 2 : installer / réparer les dépendances

Double-clique :

```text
INSTALLER_PYTHON_DEPENDANCES.bat
```

Ou lance en PowerShell depuis le dossier du tool :

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File ".\_support\install_dependencies_core.ps1"
```

Une fois les dépendances prêtes, utilise le lanceur.

## Lancer le menu

Double-clique :

```text
LANCER_UNLOCKER.bat
```

Ou lance en PowerShell depuis le dossier :

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File ".\LANCER_UNLOCKER.ps1"
```

Le menu demande ensuite :

1. l'IP de la console ;
2. le mode à envoyer ;
3. l'ID, la plage ou la liste selon le mode choisi.

## Modes disponibles

### 1. Tout unlock

Envoie tous les trophées détectés.

Commande équivalente :

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File ".\_support\run_unlocker_core.ps1" -PS5 192.168.1.94 -Mode all
```

### 2. Un trophée précis

Exemple : envoyer l'ID `8`.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File ".\_support\run_unlocker_core.ps1" -PS5 192.168.1.94 -Mode id -Id 8
```

### 3. Vague rapide

Exemple : envoyer 10 trophées, IDs `1` à `10`.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File ".\_support\run_unlocker_core.ps1" -PS5 192.168.1.94 -Mode wave -Start 1 -Wave 10
```

Autre exemple : `-Start 5 -Wave 5` envoie `5` à `9`.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File ".\_support\run_unlocker_core.ps1" -PS5 192.168.1.94 -Mode wave -Start 5 -Wave 5
```

### 4. Plage précise

Exemple : envoyer `5` à `8`.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File ".\_support\run_unlocker_core.ps1" -PS5 192.168.1.XX -Mode range -Range 5-8
```

### 5. Liste d'IDs

Exemple : envoyer `5`, `8` et `21`.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File ".\_support\run_unlocker_core.ps1" -PS5 192.168.1.XX -Mode list -Ids "5,8,21"
```

### 6. Debug rapport PC

Le mode debug accepte une plage de 10 trophées maximum.

Tu peux taper par exemple :

```text
5       -> 1 à 5
6 9     -> 6 à 9
6-9     -> 6 à 9
6 a 9   -> 6 à 9
```

Le rapport est créé sur le PC dans :

```text
debug_logs/
```

Commande équivalente :

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File ".\_support\run_unlocker_core.ps1" -PS5 192.168.1.XX -DebugReport -Elf "PS5 Unlocker DEBUG.elf" -PayloadLogPort 9022 -Mode wave -Start 1 -Wave 5
```

Le rapport sert à vérifier :

- la détection du jeu lancé ;
- la plateforme détectée PS4/PS5 ;
- le patch PS5 FW602 appliqué ou non ;
- la configuration envoyée ;
- l'injection ELF ;
- les logs TCP du payload ;
- l'erreur exacte si une étape bloque.

## Commandes utiles

Toutes les commandes suivantes sont à lancer depuis le dossier du tool.

### Installer / réparer les dépendances

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File ".\_support\install_dependencies_core.ps1"
```

### Lancer le menu PowerShell

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File ".\LANCER_UNLOCKER.ps1"
```

### Tout unlock

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File ".\_support\run_unlocker_core.ps1" -PS5 192.168.1.94 -Mode all
```

### Un seul trophée

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File ".\_support\run_unlocker_core.ps1" -PS5 192.168.1.94 -Mode id -Id 8
```

### 10 trophées, IDs 1 à 10

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File ".\_support\run_unlocker_core.ps1" -PS5 192.168.1.94 -Mode wave -Start 1 -Wave 10
```

### Vague depuis ID 5, longueur 5

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File ".\_support\run_unlocker_core.ps1" -PS5 192.168.1.94 -Mode wave -Start 5 -Wave 5
```

### Plage précise 5 à 8

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File ".\_support\run_unlocker_core.ps1" -PS5 192.168.1.94 -Mode range -Range 5-8
```

### Liste précise

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File ".\_support\run_unlocker_core.ps1" -PS5 192.168.1.94 -Mode list -Ids "5,8,21"
```

### Vrai debug ELF 9022, exemple IDs 1 à 5

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File ".\_support\run_unlocker_core.ps1" -PS5 192.168.1.94 -DebugReport -Elf "PS5 Unlocker DEBUG.elf" -PayloadLogPort 9022 -Mode wave -Start 1 -Wave 5
```
## Fonctionnement général

Le fonctionnement est le suivant :

1. Le jeu est lancé sur la console.
2. Le PC prépare une configuration selon le mode choisi.
3. Le lanceur envoie la payload ELF vers la console.
4. La payload s'exécute dans le process du jeu.
5. Elle détecte la plateforme et le contexte disponible.
6. Elle tente d'utiliser la branche adaptée : PS4/Trophy1 ou PS5/Trophy2/UDS selon les cas.
7. En mode debug, les logs sont récupérés sur le PC et un rapport est écrit dans `debug_logs/`.

## Comportement PS4 / PS5

### PS4

- Le script détecte le jeu CUSA lancé.
- Il tente de récupérer les infos NPWR/NPSIG via FTP si disponibles.
- Il envoie ensuite le ELF dans le process du jeu.

### PS5

- Le script détecte le jeu PPSA lancé.
- Il tente le patch FW602 seulement si la signature connue correspond.
- Si la signature est différente, si les offsets ne sont pas supportés, ou si ShellCore est introuvable :
  - le script affiche un warning ;
  - le rapport debug explique la raison ;
  - l'envoi du ELF peut continuer quand même selon le cas.

## Logs et rapports

Les rapports debug sont créés sur le PC dans :

```text
debug_logs/
```

La payload debug peut aussi exposer un log TCP sur :

```text
9022
```

Le code peut également utiliser des fichiers temporaires côté console, selon le mode :

```text
/data/trophy_unlocker_log.txt
/data/trophy_unlocker_id.txt
/data/trophy_unlocker_config.txt
/data/trophy_unlocker_npcomm.txt
/data/trophy_unlocker_npsig.bin
/data/trophy_unlocker_count.txt
/data/trophy_unlocker_platform.txt
```

## Bugs connus

Ce projet est expérimental.

Il est possible de rencontrer :

- des bugs ;
- des offsets non supportés ;
- des différences selon firmware ;
- des problèmes de détection ;
- des erreurs d'injection ;
- des comportements différents selon le jeu lancé.

## Avertissement

Ce projet est fourni à titre éducatif, expérimental et homebrew

## Crédits

Base / inspiration principale :

- John Törnblom, pour ses travaux publics autour de la scène PS5 homebrew et de `ps5-payload-elfldr`.

Modifications importantes :

-Extension du code, lanceur PC, les modes de sélection, les rapports debug, la gestion PS4/PS5 et les tests expérimentaux Trophy1 / Trophy2 / UDS….

Merci également aux développeurs et testeurs de la scène PS4/PS5 homebrew qui partagent leurs recherches.

## Licence

Ce projet est un dérivé fortement modifié de travaux publics existants. Les crédits d'origine doivent être conservés.

Le projet est distribué sous licence :

```text
GPL-3.0-or-later
```


