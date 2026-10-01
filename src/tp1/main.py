import argparse

from tp1.utils.capture import Capture
from tp1.utils.config import logger
from tp1.utils.report import Report


def main():
    parser = argparse.ArgumentParser(description="IDS/IPS maison - analyse PCAP")
    parser.add_argument("--pcap", help="Fichier PCAP à analyser")
    parser.add_argument("--iface", help="Interface réseau (mode live, dev)")
    parser.add_argument("--out", default="report.json", help="Fichier JSON de sortie")
    args = parser.parse_args()

    logger.info("Starting TP1")

    # Mode PCAP (correction) ou live (dev)
    capture = Capture(pcap_file=args.pcap)
    capture.capture_traffic()
    capture.analyse()
    summary = capture.get_summary()

    # Rapport JSON (format imposé)
    report = Report(capture, "report.pdf", summary)
    report.save_json(args.out)

    # Rapport PDF (à venir)
    report.generate("graph")
    report.generate("array")
    report.save("report.pdf")

    logger.info("Analyse terminée")


if __name__ == "__main__":
    main()