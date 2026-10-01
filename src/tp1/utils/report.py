import json

from tp1.utils.capture import Capture
from tp1.utils.config import logger


class Report:
    def __init__(self, capture: Capture, filename: str, summary: str):
        self.capture = capture
        self.filename = filename
        self.title = "Rapport d'analyse réseau - TP1"
        self.summary = summary
        self.array = ""
        self.graph = ""

    def save_json(self, output_file: str) -> dict:
        """
        Écrit le report.json au format imposé :
        protocols, attacks, flag.
        """
        report = {
            "protocols": self.capture.get_all_protocols(),
            "attacks": self.capture.alerts,
            "flag": self.capture.flag,
        }
        with open(output_file, "w") as f:
            json.dump(report, f, indent=2)
        logger.info(f"Rapport JSON écrit dans {output_file}")
        return report

    def concat_report(self) -> str:
        """
        Concatène toutes les données du rapport en texte.
        """
        content = ""
        content += self.title
        content += self.summary
        content += self.array
        content += self.graph
        return content

    def save(self, filename: str) -> None:
        """
        Sauvegarde le rapport texte dans un fichier.
        """
        final_content = self.concat_report()
        with open(self.filename, "w") as report:
            report.write(final_content)

    def generate(self, param: str) -> None:
        """
        Génère le graphe ou le tableau (PDF - à venir).
        """
        if param == "graph":
            # TODO: génération du graphe
            self.graph = ""
        elif param == "array":
            # TODO: génération du tableau
            self.array = ""