import json

import pytest
from cryptography.exceptions import InvalidTag

from crypto_search.engine import SearchStore


KEY = bytes(range(32))


def test_indexed_search_decrypts_only_matching_record(tmp_path):
    path = tmp_path / "store.json"
    store = SearchStore(path, KEY)
    store.add_record("r1", "rotate keys weekly")
    store.add_record("r2", "backup the audit log")

    assert store.search("rotation") == []
    assert store.search("rotate") == [("r1", "rotate keys weekly")]
    raw = json.loads(path.read_text())
    assert "rotate keys weekly" not in json.dumps(raw)
    assert "ciphertext" in raw["records"]["r1"]


def test_ciphertext_tampering_is_rejected(tmp_path):
    path = tmp_path / "store.json"
    store = SearchStore(path, KEY)
    store.add_record("r1", "rotate keys weekly")
    raw = json.loads(path.read_text())
    encoded = raw["records"]["r1"]["ciphertext"]
    raw["records"]["r1"]["ciphertext"] = encoded[:-2] + ("AA" if encoded[-2:] != "AA" else "BB")
    path.write_text(json.dumps(raw))

    with pytest.raises(InvalidTag):
        SearchStore.load(path, KEY).search("rotate")


def test_wrong_key_cannot_open_record(tmp_path):
    path = tmp_path / "store.json"
    SearchStore(path, KEY).add_record("r1", "rotate keys weekly")
    with pytest.raises(InvalidTag):
        SearchStore.load(path, bytes([1] * 32)).search("rotate")
