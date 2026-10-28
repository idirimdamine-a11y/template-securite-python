import json
from pathlib import Path

from fpdf import FPDF
from fpdf.enums import XPos, YPos

from tp2.utils.config import logger


class Report:
    """Écrit le résultat d'un triage en JSON (machine) et en PDF (humain)."""

    def __init__(self, result: dict) -> None:
        self.result = result

    def generate_pdf(self, out_pdf: str) -> None:
        """Rapport PDF lisible (fpdf2)."""
        r = self.result
        sections = [
            ("Identité", [
                f"SHA-256 : {r['sha256']}",
                f"MD5 : {r['md5']}",
                f"Taille : {r['size']} octets",
                f"Type : {r['file_type']}",
                f"Entropie : {r['entropy']}",
            ]),
            ("Verdict", [
                f"Score : {r['score']}/10",
                f"Famille : {r['family_guess']}",
                f"MITRE ATT&CK : {', '.join(r['mitre_attack']) or '-'}",
                f"Drapeau : {r['flag'] or '-'}",
            ]),
            ("Indicateurs de compromission", [
                f"{nom} : {', '.join(valeurs) or '-'}" for nom, valeurs in r["iocs"].items()
            ]),
            ("Règles YARA", r["yara_matches"] or ["Aucune"]),
            ("Résumé du LLM", [r["llm_summary"]]),
            ("Imports", [f"{len(r['imports'])} fonction(s) : {', '.join(r['imports'][:30])}"]),
        ]

        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("Helvetica", "B", 16)
        pdf.cell(0, 10, "Rapport de triage malware", new_x=XPos.LMARGIN, new_y=YPos.NEXT, align="C")
        for titre, lignes in sections:
            pdf.set_font("Helvetica", "B", 12)
            pdf.cell(0, 8, titre, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            pdf.set_font("Helvetica", size=9)
            for ligne in lignes:
                propre = ligne.encode("latin-1", "replace").decode("latin-1")
                pdf.multi_cell(0, 5, propre, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            pdf.ln(3)

        Path(out_pdf).parent.mkdir(parents=True, exist_ok=True)
        pdf.output(out_pdf)
        logger.info(f"PDF écrit : {out_pdf}")

    def generate_json(self, out_json: str) -> None:
        """Fichier JSON lisible."""
        Path(out_json).parent.mkdir(parents=True, exist_ok=True)
        with open(out_json, "w", encoding="utf-8") as f:
            json.dump(self.result, f, indent=2, ensure_ascii=False)
        logger.info(f"JSON écrit : {out_json}")