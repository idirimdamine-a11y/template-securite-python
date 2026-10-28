import json

from tp2.utils.report import Report

RESULT = {
    "sha256": "a" * 64,
    "md5": "b" * 32,
    "size": 10,
    "entropy": 4.5,
    "file_type": "ELF 64-bit",
    "iocs": {"domains": ["c2.evil.test"], "ips": [], "urls": [], "mutex": [], "registry": []},
    "imports": ["malloc"],
    "yara_matches": ["Run_Key_Persistence"],
    "family_guess": "dropper",
    "mitre_attack": ["T1071"],
    "llm_summary": "Résumé avec l’apostrophe et un emoji 🚨",
    "score": 8,
    "flag": "ESGI{test}",
}


def test_generate_json(tmp_path):
    sortie = tmp_path / "out" / "result.json"
    Report(RESULT).generate_json(str(sortie))
    assert json.loads(sortie.read_text(encoding="utf-8")) == RESULT


def test_generate_pdf(tmp_path):
    sortie = tmp_path / "out" / "result.pdf"
    Report(RESULT).generate_pdf(str(sortie))
    assert sortie.read_bytes().startswith(b"%PDF")