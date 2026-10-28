import hashlib
import math
import re
from collections import Counter
from urllib.parse import urlparse

import lief
import magic

from tp2.utils.config import logger

lief.logging.disable()

ASCII_STR_RE = re.compile(rb"[\x20-\x7e]{6,}")
UTF16_STR_RE = re.compile(rb"(?:[\x20-\x7e]\x00){6,}")
DOMAIN_RE = re.compile(r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}", re.I)
IP_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
URL_RE = re.compile(r"\bhttps?://[^\s\"'<>]+", re.I)
MUTEX_RE = re.compile(r"\b(?:Global|Local)\\[\w.-]+")
REGISTRY_RE = re.compile(r"\b(?:HKEY_[A-Z_]+|HKLM|HKCU|HKCR|HKU)\\[^\s\"']+", re.I)
FLAG_RE = re.compile(r"FLAG=(ESGI\{[0-9A-Za-z_]+\})")
FILE_EXTENSIONS = (".dll", ".exe", ".sys", ".so", ".bat", ".ps1", ".php", ".txt", ".py", ".js", ".html")
VALID_TLDS = {
    "com", "net", "org", "info", "biz", "io", "co", "me", "xyz", "top", "site", "online",
    "club", "cc", "tk", "ml", "ga", "cf", "gq", "pw", "su", "ru", "cn", "de", "fr", "uk",
    "us", "eu", "nl", "br", "in", "onion", "test", "example", "invalid", "local",
}


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
        """domaines, ips, urls, mutex, registry (chaînes de l'overlay s'il existe)."""
        binary = lief.parse(self.path)
        overlay = bytes(binary.overlay) if binary is not None else b""
        data = overlay or self.data

        strings = [s.decode("ascii") for s in ASCII_STR_RE.findall(data)]
        strings += [s.decode("utf-16le") for s in UTF16_STR_RE.findall(data)]
        text = "\n".join(strings)

        urls = set(URL_RE.findall(text))
        domains = {urlparse(u).hostname for u in urls if urlparse(u).hostname}
        domains |= {s.strip().lower() for s in strings if DOMAIN_RE.fullmatch(s.strip())}
        domains = {
            d for d in domains
            if not d.endswith(FILE_EXTENSIONS) and d.rsplit(".", 1)[-1] in VALID_TLDS
        }

        logger.debug(f"{len(urls)} URL(s), {len(domains)} domaine(s) trouvés")
        return {
            "domains": sorted(domains),
            "ips": sorted(set(IP_RE.findall(text))),
            "urls": sorted(urls),
            "mutex": sorted(set(MUTEX_RE.findall(text))),
            "registry": sorted(set(REGISTRY_RE.findall(text))),
        }

    def extract_flag(self) -> str | None:
        """Drapeau annoncé par FLAG= ; les ESGI{...} cités ailleurs sont ignorés."""
        match = FLAG_RE.search(self.data.decode("latin-1"))
        return match.group(1) if match else None

    def parse_binary(self) -> dict:
        """imports, exports et sections via lief (listes vides si pas PE/ELF)."""
        binary = lief.parse(self.path)
        if binary is None:
            logger.debug(f"{self.path} n'est pas un binaire PE/ELF")
            return {"imports": [], "exports": [], "sections": []}
        return {
            "imports": sorted({f.name for f in binary.imported_functions if f.name}),
            "exports": sorted({f.name for f in binary.exported_functions if f.name}),
            "sections": [s.name for s in binary.sections if s.name],
        }