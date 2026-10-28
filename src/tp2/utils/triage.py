import json

from tp2.utils.config import logger
from tp2.utils.llm import LLMTriage
from tp2.utils.sample import Sample
from tp2.utils.scanner import YaraScanner


class Triage:
    """Enchaîne l'analyse d'un échantillon : features, YARA, LLM, score final."""

    def __init__(self, path: str, backend: str, scanner: YaraScanner | None = None) -> None:
        self.path = path
        self.backend = backend
        self.scanner = scanner or YaraScanner()
        self.llm = LLMTriage(backend)

    def run(self) -> dict:
        """Analyse complète d'un échantillon, au format JSON de la correction."""
        sample = Sample(self.path)
        logger.info(f"Triage de {self.path} ({len(sample.data)} octets)")

        meta = sample.get_file_metadata()
        iocs = sample.extract_iocs()
        bininfo = sample.parse_binary()
        matches = self.scanner.scan(sample.data)
        summary = json.dumps({
            "meta": meta,
            "iocs": iocs,
            "yara": matches,
            "imports": bininfo["imports"][:50],
            "sections": bininfo["sections"],
        })
        verdict = json.loads(self.llm.triage(summary))

        base = self.rule_score(meta, iocs, matches)
        if verdict.get("source") == "fallback":
            score = base
        else:
            score = max(base, round((base + verdict["score_0_10"]) / 2))

        return {
            "sha256": meta["sha256"],
            "md5": meta["md5"],
            "size": meta["size"],
            "entropy": meta["entropy"],
            "file_type": meta["file_type"],
            "iocs": iocs,
            "imports": bininfo["imports"],
            "yara_matches": matches,
            "family_guess": verdict["famille"],
            "mitre_attack": sorted(set(verdict["mitre_attack"]) | set(self.rule_mitre(iocs))),
            "llm_summary": verdict["resume"],
            "score": score,
            "flag": sample.extract_flag(),
        }

    @staticmethod
    def rule_score(meta: dict, iocs: dict, matches: list[str]) -> int:
        """Score 0-10 calculé sans LLM, à partir des IOC, de YARA et de l'entropie."""
        score = 0
        if iocs["urls"] or iocs["domains"]:
            score += 3
        if iocs["ips"]:
            score += 1
        if iocs["mutex"]:
            score += 1
        if iocs["registry"]:
            score += 2
        score += min(len(matches), 3)
        if meta["entropy"] > 7.2:
            score += 1
        return min(score, 10)

    @staticmethod
    def rule_mitre(iocs: dict) -> list[str]:
        """Techniques MITRE ATT&CK déduites des IOC, sans LLM."""
        techniques = []
        if iocs["urls"] or iocs["domains"] or iocs["ips"]:
            techniques.append("T1071")
        if iocs["registry"]:
            techniques.append("T1547")
        return techniques