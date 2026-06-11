"""Configuration pytest.

Ajoute la racine du dépôt au `sys.path` afin que `import src...` fonctionne
même sans installation éditable (`pip install -e .`).
"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
