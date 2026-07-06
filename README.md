# satcom-sec

Ce projet modélise, attaque et sécurise une chaîne de communication satellite simulée,
depuis une transmission volontairement vulnérable jusqu'à une communication résiliente
face au bruit et aux attaques cyber.

L'architecture est volontairement modulaire afin de :

- séparer clairement les responsabilités techniques,
- faciliter le travail collaboratif,
- permettre une évolution progressive du projet (attaques, défenses, métriques).

Chaque dossier correspond à une brique fonctionnelle précise du système.

## Niveaux de sécurité

Le projet démontre une évolution progressive de la sécurité du système :

| Niveau       | État de la communication | Mécanismes implémentés                                     |
| :----------- | :----------------------- | :--------------------------------------------------------- |
| **Niveau 0** | Vulnérable               | Transmission en clair, aucune correction d'erreur.         |
| **Niveau 1** | Robuste                  | Codes correcteurs (Reed-Solomon) contre le bruit.          |
| **Niveau 2** | Sécurisé                 | Authentification des trames (HMAC-SHA256) + détection IDS. |
| **Niveau 3** | Résilient                | Saut de fréquence (FHSS) pour contrer le brouillage actif. |

## Structure du dépôt

```
config/     Paramètres de simulation (YAML) — voir config/exemple_config.yml
data/       Images sources (input/) et reconstruites (output/)
docs/       Documentation technique, rapport, diagrammes
scripts/    Scénarios exécutables de bout en bout (run_step1/2/3, démos)
src/        Code source, découpé par brique fonctionnelle
tests/      Tests automatisés (+ tests/legacy/ : anciens brouillons conservés)
```

### Briques `src/`

| Module             | Rôle                                                            |
| :----------------- | :------------------------------------------------------------- |
| `protocol/`        | Construction des trames CCSDS (header + payload + CRC).         |
| `encoding/`        | Découpage d'une image en paquets CCSDS côté émetteur.           |
| `channel/`         | Simulation du canal : brouillage (`jamming`) et FEC (`reed_solomon`). |
| `receiver/`        | Parsing, validation (CRC) et reconstruction côté récepteur.    |
| `attacks/`         | Vecteurs d'attaque (altération de trames, injection).          |
| `detection/`       | Défenses : authentification HMAC et détection d'anomalies (IDS).|
| `dashboard/`       | Interface de supervision Streamlit.                            |

## Installation

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e .          # installe le projet et ses dépendances
```

Le mode éditable (`-e .`) rend le package `src` importable depuis n'importe où,
sans manipulation de `sys.path`.

## Utilisation

Scénarios de bout en bout (exécutables depuis la racine du dépôt) :

```bash
python scripts/run_step1_simple_communication.py   # transmission simple
python scripts/run_step2_add_spatial_noise.py      # + bruit / brouillage
python scripts/run_step3_add_reed_solomon.py       # + correction Reed-Solomon
```

Dashboard de supervision :

```bash
streamlit run src/dashboard/dashboard.py
```

## Tests

```bash
pip install -e ".[dev]"   # installe pytest
pytest
```
