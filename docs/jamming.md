# Module de brouillage

Ce document décrit comment intégrer le module de brouillage ajouté dans `src/channel/jamming.py`.

## Objectif

Le module fournit un brouillage autonome pour une simulation satellite-sol, sans imposer de modification au reste du pipeline.

Il couvre deux cas d'usage :

- brouiller un signal échantillonné avec `jam_signal(...)` ;
- brouiller une trame binaire avec `jam_bytes(...)`.

Le profil de brouillage est lu depuis la section `channel_simulation` du YAML.

## Paramètres de configuration

Le module lit les champs suivants dans `config/exemple_config.yml` :

```yaml
channel_simulation:
  enable_jamming: true
  default_snr: 15
  ber_threshold: 1e-5
  jamming_intensity: 0.08
  jamming:
    mode: "multi"
    modes: ["barrage", "pulse", "tone"]
    seed: 2026
    burst_probability: 0.08
    burst_length: 64
    tone_frequency_ratio: 0.12
  reed_solomon:
    ecc_symbols: 32
```

Signification :

- `enable_jamming` active ou coupe entièrement le brouillage ;
- `default_snr` définit le bruit de base du canal ;
- `ber_threshold` sert de seuil d'alerte pour juger si le canal est trop dégradé ;
- `jamming_intensity` règle la puissance relative du brouilleur entre 0 et 1 ;
  pour une démo corrigeable avec Reed-Solomon, une plage de `0.05` à `0.15` est recommandée ;
- `mode` choisit le profil de brouillage :
  - `barrage` : bruit large bande continu ;
  - `pulse` : brouillage par rafales ;
  - `tone` : brouillage sinusoïdal périodique ;
  - `multi` : combine plusieurs profils en même temps ;
- `modes` permet de sélectionner les profils à combiner quand `mode: "multi"` ;
- `seed` permet de rejouer exactement le même scénario ;
- `burst_probability` et `burst_length` pilotent le mode `pulse` ;
- `tone_frequency_ratio` pilote la fréquence normalisée du mode `tone`.

## API disponible

Le module expose trois objets :

- `JammingConfig` : structure de configuration ;
- `JammingReport` : métriques produites après un brouillage ;
- `SatelliteJammer` : moteur principal.

Exemple d'initialisation depuis le YAML :

```python
from src.channel.jamming import SatelliteJammer

jammer = SatelliteJammer.from_yaml("config/exemple_config.yml")
```

## Intégration côté signal

Si votre chaîne manipule un signal échantillonné, le point d'insertion le plus propre est après la modulation et avant la réception/démodulation.

Exemple :

```python
samples = [0.92, 0.85, -0.88, -0.91, 0.87]

jammer = SatelliteJammer.from_yaml("config/exemple_config.yml")
jammed_samples, report = jammer.jam_signal(samples)

print(report.effective_snr_db)
print(report.estimated_ber)
```

`jam_signal(...)` retourne :

- la séquence brouillée ;
- un `JammingReport` avec le SNR effectif, le BER estimé et le dépassement éventuel du seuil.

## Intégration côté trame

Si votre chaîne manipule uniquement des octets, le point d'insertion le plus simple est juste après la création de la trame et avant le décodage/correction côté réception.

Exemple :

```python
frame = b"SATCOM_FRAME"

jammer = SatelliteJammer.from_yaml("config/exemple_config.yml")
jammed_frame, report = jammer.jam_bytes(frame)

print(report.flipped_bits)
print(report.estimated_ber)
```

`jam_bytes(...)` retourne :

- la trame potentiellement corrompue ;
- un `JammingReport` avec le nombre de bits inversés et le BER observé.

## Recommandation d'insertion dans votre pipeline

Choisissez un seul point d'insertion pour éviter de compter deux fois la dégradation du canal.

Cas recommandés :

1. si vous avez une couche physique simulée : appelez `jam_signal(...)` entre l'émetteur et le récepteur ;
2. si vous êtes encore au niveau trame uniquement : appelez `jam_bytes(...)` entre la création de trame et la réception ;
3. si vous ajoutez plus tard du FEC ou de la détection d'attaque : utilisez `report.threshold_exceeded` pour tracer les scénarios critiques.

## Notes de conception

Le module a été conçu pour rester indépendant :

- aucune modification du pipeline existant n'est requise ;
- la config actuelle reste compatible grâce à `enable_jamming`, `default_snr`, `ber_threshold` et `jamming_intensity` ;
- la sous-section `jamming` ajoute uniquement le profil fin du brouillage.