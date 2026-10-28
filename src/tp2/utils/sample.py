import hashlib
import math
from collections import Counter

import magic

from tp2.utils.config import logger


class Sample:
    """Fichier suspect à analyser."""

    def __init__(self, path: str) -> None:
        self.path = path
        with open(path, "rb") as f:
            self.data = f.read()

    def get_file_metadata(self) -> dict:
        """sha256, md5, taille, type de fichier, entropie de Shannon."""
        logger.debug(f"Métadonnées de {self.path}")
        return {
            "sha256": hashlib.sha256(self.data).hexdigest(),
            "md5": hashlib.md5(self.data).hexdigest(),
            "size": len(self.data),
            "file_type": magic.from_buffer(self.data),
            "entropy": round(self.shannon_entropy(), 2),
        }

    def shannon_entropy(self) -> float:
        """Entropie de Shannon des octets, entre 0 et 8."""
        if not self.data:
            return 0.0
        freq = Counter(self.data)
        n = len(self.data)
        return -sum((c / n) * math.log2(c / n) for c in freq.values())

    def extract_iocs(self) -> dict:
        """domaines, ips, urls, mutex, registry (regex sur les strings)."""
        raise NotImplementedError

    def parse_binary(self) -> dict:
        """imports / sections via lief (si PE/ELF)."""
        raise NotImplementedError