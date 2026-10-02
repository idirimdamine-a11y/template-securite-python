# Template code Sécurité Python

## Description

Projet contenant les TP du cours de sécurité Python de 4e année de l'ESGI.

TP1 : analyse d'une capture réseau (.pcap ou en direct). L'outil compte les
protocoles, détecte les attaques (ARP spoofing, scan de ports, injection SQL)
et génère un rapport `report.json`.

## Installation

Faire un fork puis un clone du projet :

```
git clone git@github.com:<VotreNom>/template-securite-python.git
```

Installer les dépendances :

```
cd template-securite-python
poetry lock
poetry install
```

## Utilisation

Lancer le projet :

```
poetry run tp1
```

## Tests

```
poetry run pytest
```
