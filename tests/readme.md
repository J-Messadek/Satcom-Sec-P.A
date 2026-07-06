Ce dossier regroupe les tests du projet.

Il permet de vérifier le bon fonctionnement des briques critiques
(protocole, crypto, canal, attaques) et de garantir la stabilité
du système lors des évolutions.

## Lancer les tests

Depuis la racine du dépôt :

```bash
pytest
```

## Suites actives

- `test_channel_improvements.py` : brouillage multi-mode et Reed-Solomon.
- `reception_test.py`            : chaîne de réception (parse → validate → reconstruct).
- `frame_alteration_test.py`     : Attaque 2 (altération) + Défense 2 (HMAC + IDS).

## Historique

Les anciens brouillons sont conservés dans `tests/legacy/` (non collectés par
pytest). Ne pas les effacer : ils servent d'historique du projet.
