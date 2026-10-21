from dataclasses import dataclass
from typing import Iterable


@dataclass(frozen=True)
class Finding:
    area: str
    priority: str
    evidence: str
    action: str


def review_signatures(signatures: Iterable[tuple[int, int]]) -> list[Finding]:
    """Detect the repeated-r signal associated with nonce reuse.

    This is a review aid, not a complete ECDSA verifier.
    """
    seen_r: set[int] = set()
    findings: list[Finding] = []
    for r, _ in signatures:
        if r in seen_r:
            findings.append(
                Finding(
                    "nonce",
                    "critical",
                    "repeated r",
                    "stop signing and rotate the key",
                )
            )
        seen_r.add(r)
    return findings


def checklist() -> list[Finding]:
    return [
        Finding(
            "curve",
            "critical",
            "public-point validation required",
            "validate encoding, field range, curve membership, and subgroup",
        ),
        Finding(
            "nonce",
            "critical",
            "nonce generation is security-sensitive",
            "use a sound fresh or correctly deterministic nonce design",
        ),
        Finding(
            "encoding",
            "high",
            "signed bytes must be canonical",
            "canonicalize before hashing and exclude the signature field",
        ),
        Finding(
            "identity",
            "high",
            "valid math does not identify a signer",
            "bind the claimed signer to a trusted verification key",
        ),
        Finding(
            "lifecycle",
            "strategic",
            "future algorithm migration is required",
            "keep algorithm and key representation replaceable",
        ),
    ]
