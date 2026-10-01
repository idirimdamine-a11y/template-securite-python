import json

import matplotlib

matplotlib.use("Agg")  # backend sans écran (bac à sable sans affichage)
import matplotlib.pyplot as plt
from fpdf import FPDF

from tp1.utils.capture import Capture
from tp1.utils.config import logger


class Report:
    def __init__(self, capture: Capture, filename: str, summary: str):
        self.capture = capture
        self.filename = filename
        self.title = "Rapport d'analyse reseau - TP1"
        self.summary = summary
        self.array = ""
        self.graph = ""
        self.graph_file = "graph.png"

    def save_json(self, output_file: str) -> dict:
        """
        Écrit le report.json au format imposé : protocols, attacks, flag.
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

    def generate(self, param: str) -> None:
        """
        Génère le graphe (image PNG) ou le tableau (texte).
        """
        if param == "graph":
            protocols = self.capture.get_all_protocols()
            plt.figure(figsize=(6, 4))
            plt.bar(list(protocols.keys()), list(protocols.values()), color="steelblue")
            plt.title("Volume de paquets par protocole")
            plt.xlabel("Protocole")
            plt.ylabel("Nombre de paquets")
            plt.tight_layout()
            plt.savefig(self.graph_file)
            plt.close()
            self.graph = self.graph_file
            logger.info(f"Graphe généré : {self.graph_file}")

        elif param == "array":
            lines = ["Protocoles :"]
            for proto, count in self.capture.get_all_protocols().items():
                lines.append(f"  {proto} : {count} paquets")
            lines.append("")
            lines.append("Attaques detectees :")
            if self.capture.alerts:
                for alert in self.capture.alerts:
                    lines.append(f"  {alert['type']} - attaquant : {alert['attacker']}")
            else:
                lines.append("  Aucune attaque detectee")
            lines.append("")
            lines.append(f"Flag : {self.capture.flag}")
            self.array = "\n".join(lines)
            logger.info("Tableau généré")

    def concat_report(self) -> str:
        """
        Concatène toutes les données du rapport en texte.
        """
        content = ""
        content += self.title + "\n\n"
        content += self.summary + "\n"
        content += self.array + "\n"
        return content

    def save(self, filename: str) -> None:
        """
        Sauvegarde le rapport en PDF : titre, tableau, attaques, flag, graphe.
        """
        pdf = FPDF()
        pdf.add_page()

        # Titre
        pdf.set_font("Helvetica", "B", 16)
        pdf.cell(0, 10, self.title, ln=True, align="C")
        pdf.ln(5)

        # Contenu texte (tableau des protocoles, attaques, flag)
        pdf.set_font("Helvetica", "", 11)
        for line in self.array.split("\n"):
            pdf.cell(0, 8, line, ln=True)
        pdf.ln(5)

        # Graphe
        if self.graph:
            pdf.image(self.graph, w=150)

        pdf.output(filename)
        logger.info(f"Rapport PDF écrit dans {filename}")