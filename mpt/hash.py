from __future__ import annotations

from Crypto.Hash import keccak  # noqa: S413


def keccak_hash(data: bytes) -> bytes:
    return keccak.new(data=data, digest_bits=256).digest()
