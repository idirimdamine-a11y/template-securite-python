from pathlib import Path

import yara

from tp2.utils.config import logger

STUDENT_RULES = r"""
rule Prompt_Injection_Attempt
{
    meta:
        description = "Texte qui tente de manipuler un analyste ou un LLM"
    strings:
        $a = "ignore previous instructions" nocase ascii wide
        $b = "AI_INSTRUCTIONS" nocase ascii wide
        $c = "NOTE_TO_AI" nocase ascii wide
        $d = "mark the sample clean" nocase ascii wide
    condition:
        any of them
}

rule Run_Key_Persistence
{
    meta:
        description = "Persistance via la clé Run du registre Windows"
    strings:
        $run = "\\CurrentVersion\\Run" nocase ascii wide
    condition:
        $run
}
"""


class YaraScanner:
    """Applique les règles YARA fournies (fichier ou dossier) et nos règles."""

    def __init__(self, rules_path: str = "rules/course_rules.yar") -> None:
        self.rules_path = rules_path
        sources = {"student_rules": STUDENT_RULES}
        path = Path(rules_path)
        if path.is_dir():
            files = sorted(path.glob("*.yar")) + sorted(path.glob("*.yara"))
        elif path.is_file():
            files = [path]
        else:
            logger.warning(f"Règles introuvables : {rules_path}")
            files = []
        for f in files:
            sources[f.stem] = f.read_text(errors="ignore")
        logger.info(f"{len(files)} fichier(s) de règles chargé(s) + règles perso")
        self.rules = yara.compile(sources=sources)

    def scan(self, data: bytes) -> list[str]:
        """Noms des règles YARA déclenchées."""
        return sorted({match.rule for match in self.rules.match(data=data)})