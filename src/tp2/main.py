import argparse
from pathlib import Path

from tp2.utils.config import logger
from tp2.utils.report import Report
from tp2.utils.scanner import YaraScanner
from tp2.utils.triage import Triage


def main(argv: list[str] | None = None) -> None:
    """Point d'entrée : poetry run tp2 --samples DOSSIER --rules DOSSIER --out DOSSIER."""
    ap = argparse.ArgumentParser(description="Triage automatisé de malware")
    ap.add_argument("--samples", required=True, help="dossier des échantillons")
    ap.add_argument("--rules", default="rules", help="dossier des règles YARA")
    ap.add_argument("--out", required=True, help="dossier de sortie")
    ap.add_argument("--llm", choices=["openrouter", "ollama"], default="openrouter")
    args = ap.parse_args(argv)

    logger.info("Starting TP2")
    scanner = YaraScanner(args.rules)
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    samples = sorted(p for p in Path(args.samples).iterdir() if p.is_file())
    logger.info(f"{len(samples)} échantillon(s) à analyser")

    for path in samples:
        try:
            result = Triage(str(path), args.llm, scanner).run()
            report = Report(result)
            report.generate_json(str(out_dir / f"{path.name}.triage.json"))
            report.generate_json(str(out_dir / f"{result['sha256']}.json"))
            report.generate_pdf(str(out_dir / f"{path.name}.triage.pdf"))
        except Exception as e:  # noqa: BLE001 - un échantillon défectueux ne doit pas bloquer les autres
            logger.error(f"Échec sur {path} : {e}")


if __name__ == "__main__":
    main()