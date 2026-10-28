from unittest.mock import MagicMock

from src.tp1.utils.report import Report


def _make_report():
    capture = MagicMock()
    capture.get_all_protocols.return_value = {"TCP": 5, "ARP": 2}
    capture.alerts = [{"type": "port_scan", "attacker": "10.0.0.9"}]
    capture.flag = "ESGI{test}"
    return Report(capture, "test.pdf", "Resume test")


def test_report_init():
    capture = MagicMock()
    report = Report(capture, "test.pdf", "Test summary")
    assert report.capture == capture
    assert report.filename == "test.pdf"
    assert report.summary == "Test summary"


def test_save_json(tmp_path):
    report = _make_report()
    output = tmp_path / "report.json"
    result = report.save_json(str(output))
    assert result["protocols"] == {"TCP": 5, "ARP": 2}
    assert result["flag"] == "ESGI{test}"
    assert output.exists()


def test_generate_array():
    report = _make_report()
    report.generate("array")
    assert "TCP" in report.array
    assert "port_scan" in report.array


def test_generate_graph(tmp_path):
    report = _make_report()
    report.graph_file = str(tmp_path / "graph.png")
    report.generate("graph")
    assert report.graph == report.graph_file

def test_concat_report():
    report = _make_report()
    report.title = "Titre"
    report.array = "Contenu"
    result = report.concat_report()
    assert "Titre" in result
    assert "Contenu" in result

def test_generate_invalid_param():
    report = _make_report()
    report.generate("invalid")
    assert report.array == ""
    assert report.graph == ""


def test_save_creates_pdf(tmp_path):
    report = _make_report()
    report.generate("array")
    report.generate("graph")
    output = tmp_path / "report.pdf"
    report.save(str(output))
    assert output.exists()