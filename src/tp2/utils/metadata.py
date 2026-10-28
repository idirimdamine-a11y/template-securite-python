import hashlib
import math
from collections import Counter

import magic

from tp2.utils.config import logger


def get_file_metadata(data: bytes) -> dict:
    """Calcule les empreintes, la taille, le type et l'entropie d'un fichier."""
    logger.debug(f"Calcul des métadonnées ({len(data)} octets)")
    return {
        "sha256": hashlib.sha256(data).hexdigest(),
        "md5": hashlib.md5(data).hexdigest(),
        "size": len(data),
        "file_type": magic.from_buffer(data),
        "entropy": compute_entropy(data),
    }


def compute_entropy(data: bytes) -> float:
    """Entropie de Shannon des octets, entre 0 et 8."""
    if not data:
        return 0.0
    total = 0.0
    for count in Counter(data).values():
        p = count / len(data)
        total -= p * math.log2(p)
    return round(total, 2)