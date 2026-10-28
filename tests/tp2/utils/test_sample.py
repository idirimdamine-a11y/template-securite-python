from tp2.utils.sample import Sample


def test_get_file_metadata(tmp_path):
    fichier = tmp_path / "test.bin"
    fichier.write_bytes(b"aaaa")
    meta = Sample(str(fichier)).get_file_metadata()
    assert meta["size"] == 4
    assert meta["entropy"] == 0.0
    assert meta["md5"] == "74b87337454200d4d33f80c4663dc5e5"


def test_shannon_entropy(tmp_path):
    fichier = tmp_path / "test.bin"
    fichier.write_bytes(bytes(range(256)))
    assert Sample(str(fichier)).shannon_entropy() == 8.0