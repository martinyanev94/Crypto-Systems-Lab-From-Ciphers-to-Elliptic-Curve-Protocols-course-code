from __future__ import annotations

import base64
import hashlib
import json
import re
import secrets
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def normalize(value: str) -> str:
    return value.casefold()


def b64(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def unb64(value: str) -> bytes:
    return base64.b64decode(value.encode("ascii"))


def token_digest(token: str) -> str:
    return hashlib.sha256(normalize(token).encode("utf-8")).hexdigest()


class SearchStore:
    def __init__(self, path: str | Path, key: bytes, data: dict | None = None):
        if len(key) != 32:
            raise ValueError("key must contain exactly 32 bytes")
        self.path = Path(path)
        self.key = key
        self.index = data["index"] if data else {}
        self.records = data["records"] if data else {}

    @classmethod
    def load(cls, path: str | Path, key: bytes) -> "SearchStore":
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        return cls(path, key, data)

    def save(self) -> None:
        data = {"index": self.index, "records": self.records}
        self.path.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")

    def add_record(self, record_id: str, text: str) -> None:
        if not record_id or record_id in self.records:
            raise ValueError("record ID must be non-empty and unused")
        tokens = sorted(set(re.findall(r"[\\w']+", normalize(text))))
        for token in tokens:
            digest = token_digest(token)
            self.index.setdefault(digest, []).append(record_id)
        nonce = secrets.token_bytes(12)
        ciphertext = AESGCM(self.key).encrypt(nonce, text.encode("utf-8"), record_id.encode())
        self.records[record_id] = {"nonce": b64(nonce), "ciphertext": b64(ciphertext)}
        self.save()

    def search(self, query: str) -> list[tuple[str, str]]:
        ids = self.index.get(token_digest(query), [])
        results = []
        for record_id in ids:
            item = self.records[record_id]
            plaintext = AESGCM(self.key).decrypt(
                unb64(item["nonce"]), unb64(item["ciphertext"]), record_id.encode()
            ).decode("utf-8")
            results.append((record_id, plaintext))
        return results

    def decrypt_record(self, record_id: str) -> str:
        item = self.records[record_id]
        return AESGCM(self.key).decrypt(
            unb64(item["nonce"]), unb64(item["ciphertext"]), record_id.encode()
        ).decode("utf-8")


__all__ = ["InvalidTag", "SearchStore", "normalize", "token_digest"]
