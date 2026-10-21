from __future__ import annotations

import argparse
import json
from pathlib import Path

from .engine import SearchStore


def key_from_hex(value: str) -> bytes:
    try:
        key = bytes.fromhex(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("key must be hexadecimal") from exc
    if len(key) != 32:
        raise argparse.ArgumentTypeError("key must encode 32 bytes")
    return key


def main() -> None:
    parser = argparse.ArgumentParser(description="Search encrypted records by hashed tokens")
    parser.add_argument("command", choices=["init", "add", "search"])
    parser.add_argument("store")
    parser.add_argument("key", type=key_from_hex)
    parser.add_argument("args", nargs="*")
    ns = parser.parse_args()
    path = Path(ns.store)
    if ns.command == "init":
        SearchStore(path, ns.key).save()
        return
    store = SearchStore.load(path, ns.key)
    if ns.command == "add":
        if len(ns.args) != 2:
            parser.error("add requires RECORD_ID TEXT")
        store.add_record(ns.args[0], ns.args[1])
    else:
        if len(ns.args) != 1:
            parser.error("search requires QUERY")
        print(json.dumps([{"id": i, "text": t} for i, t in store.search(ns.args[0])]))


if __name__ == "__main__":
    main()
