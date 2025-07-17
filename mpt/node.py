from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Sequence
from typing import TYPE_CHECKING, Final

from .hash import keccak_hash
from .nibble_path import NibblePath

if TYPE_CHECKING:
    # WOrk around untyped rlp package
    from typing_extensions import TypeAlias

    _Encodable: TypeAlias = 'bytes | bytearray | Sequence[_Encodable]'

    class _Rlp:
        def encode(self, value: _Encodable) -> bytes: ...
        def decode(self, value: bytes) -> _Encodable: ...

    rlp = _Rlp()
else:
    import rlp

NODE_REF_LENGTH: Final = 32


def _prepare_reference_for_usage(ref: _Encodable) -> bytes:
    """Encodes reference into RLP so stored references will appear as bytes."""
    if not isinstance(ref, bytes):
        return rlp.encode(ref)

    return ref


def _prepare_reference_for_encoding(ref: bytes) -> _Encodable:
    """Decodes RLP-encoded reference so the full node will be encoded correctly."""
    if 0 < len(ref) < NODE_REF_LENGTH:
        return rlp.decode(ref)

    return ref


class AnyNode(ABC):
    @abstractmethod
    def encode(self) -> bytes:
        raise NotImplementedError

    @abstractmethod
    def raw(self) -> list[bytes]:
        raise NotImplementedError


class Leaf(AnyNode):
    path: NibblePath
    data: bytes

    def __init__(self, path: NibblePath, data: bytes) -> None:
        self.path = path
        self.data = data

    def encode(self) -> bytes:
        return rlp.encode([self.path.encode(True), self.data])

    def raw(self) -> list[bytes]:
        return [self.path.encode(True), self.data]


class Extension(AnyNode):
    path: NibblePath
    next_ref: bytes

    def __init__(self, path: NibblePath, next_ref: bytes) -> None:
        self.path = path
        self.next_ref = next_ref

    def encode(self) -> bytes:
        next_ref = _prepare_reference_for_encoding(self.next_ref)
        return rlp.encode([self.path.encode(False), next_ref])

    def raw(self) -> list[bytes]:
        return [self.path.encode(False), self.next_ref]


class Branch(AnyNode):
    branches: list[bytes]
    data: bytes

    def __init__(self, branches: list[bytes], data: bytes) -> None:
        self.branches = branches
        self.data = data

    def encode(self) -> bytes:
        branches = list(map(_prepare_reference_for_encoding, self.branches))
        return rlp.encode([*branches, self.data])

    def raw(self) -> list[bytes]:
        return [*self.branches, self.data]


class Node:
    EMPTY_HASH: Final = keccak_hash(rlp.encode(b''))

    AnyNode: TypeAlias = AnyNode
    Leaf: TypeAlias = Leaf
    Extension: TypeAlias = Extension
    Branch: TypeAlias = Branch

    @classmethod
    def decode(cls, encoded_data: bytes) -> AnyNode:
        """Decodes node from RLP."""
        data = rlp.decode(encoded_data)

        if not isinstance(data, list) or len(data) not in {17, 2}:
            raise ValueError('Unknown data format.')

        if len(data) == 17:  # noqa: PLR2004
            branches = list(map(_prepare_reference_for_usage, data[:16]))
            node_data = data[16]
            assert isinstance(node_data, bytes)
            return Node.Branch(branches, node_data)

        type_, ref_or_data = data
        assert isinstance(type_, bytes)
        assert isinstance(ref_or_data, bytes)
        path, is_leaf = NibblePath.decode_with_type(type_)
        if is_leaf:
            return Node.Leaf(path, ref_or_data)
        ref = _prepare_reference_for_usage(ref_or_data)
        return Node.Extension(path, ref)

    @classmethod
    def into_reference(cls, node: AnyNode) -> bytes:
        """Returns reference to the given node.

        If length of encoded node is less than 32 bytes, the reference is encoded node
        itself (In-place reference).
        Otherwise reference is keccak hash of encoded node.
        """
        encoded_node = node.encode()
        if len(encoded_node) < NODE_REF_LENGTH:
            return encoded_node
        return keccak_hash(encoded_node)
