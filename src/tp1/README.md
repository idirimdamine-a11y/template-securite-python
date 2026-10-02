# TP1 – Analyse réseau

Outil en Python (Scapy) qui analyse une capture réseau, soit à partir d'un
fichier .pcap, soit en direct sur une interface. Il compte les protocoles
présents, détecte certaines attaques et génère un rapport `report.json`.

## Ce que l'outil détecte

Protocoles comptés : Ethernet, IP, ARP, TCP, UDP, ICMP, DNS, HTTP.

Attaques :
- **ARP spoofing** : une même IP annoncée par deux adresses MAC différentes.
- **Scan de ports** : une même IP qui envoie des SYN vers beaucoup de ports.
- **Injection SQL** : motifs suspects (`' OR 1=1`, `UNION SELECT`…) dans les
  requêtes HTTP.

Pour chaque attaque, le rapport indique l'IP et l'adresse MAC de l'attaquant.
L'outil cherche aussi le drapeau caché dans la capture.

## Installation

```bash
poetry install
pre-commit install
```

## Lancement

```bash
COMMANDE_A_COMPLETER
```

La capture en direct nécessite les droits root (`sudo`).

## Tests

```bash
poetry run pytest
```

## Limites

Le trafic HTTPS est chiffré : une injection SQL envoyée en HTTPS ne peut pas
être détectée.