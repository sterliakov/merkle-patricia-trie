from __future__ import annotations

from collections.abc import Sequence, Sized
from typing import Protocol

from typing_extensions import Self


class _NibblePathLike(Protocol, Sized):
    def at(self, idx: int, /) -> int: ...


class _ChainedPath:
    """Class that chains two paths."""

    def __init__(self, first: _NibblePathLike, second: _NibblePathLike) -> None:
        self.first = first
        self.second = second

    def __len__(self) -> int:
        return len(self.first) + len(self.second)

    def at(self, idx: int) -> int:
        if idx < len(self.first):
            return self.first.at(idx)
        return self.second.at(idx - len(self.first))


class NibblePath:
    ODD_FLAG = 0x10
    LEAF_FLAG = 0x20

    _Chained = _ChainedPath  # For backwards compat

    def __init__(self, data: Sequence[int], offset: int = 0) -> None:
        self._data = data
        self._offset = offset

    def __len__(self) -> int:
        return len(self._data) * 2 - self._offset

    def __repr__(self) -> str:
        return f'<NibblePath: Data: 0x{bytes(self._data).hex()}, Offset: {self._offset}>'

    def __str__(self) -> str:
        return f'<Hex 0x{bytes(self._data).hex()} | Raw {self._data}>'

    def __eq__(self, other):
        if not isinstance(other, NibblePath):
            return NotImplemented

        if len(self) != len(other):
            return False

        return all(self.at(i) == other.at(i) for i in range(len(self)))

    def __getitem__(self, idx: int) -> int:
        return self.at(idx)

    def __hash__(self) -> int:
        return hash((self._data, self._offset))

    def next(self) -> int:
        first = self[0]
        self.consume(1)
        return first

    @classmethod
    def decode_with_type(cls, data: Sequence[int]) -> tuple[Self, bool]:
        """Decodes NibblePath and its type from raw bytes."""
        is_odd_len = data[0] & cls.ODD_FLAG == cls.ODD_FLAG
        is_leaf = data[0] & cls.LEAF_FLAG == cls.LEAF_FLAG

        offset = 1 if is_odd_len else 2

        return cls(data, offset), is_leaf

    @classmethod
    def decode(cls, data: Sequence[int]) -> Self:
        """Decodes NibblePath without its type from raw bytes."""
        return cls.decode_with_type(data)[0]

    def starts_with(self, other: _NibblePathLike) -> bool:
        """Checks if `other` is prefix of `self`."""
        if len(other) > len(self):
            return False

        return all(self.at(i) == other.at(i) for i in range(len(other)))

    def at(self, idx: int) -> int:
        """Returns nibble at the certain position."""
        idx += self._offset

        byte_idx = idx // 2
        nibble_idx = idx % 2

        byte = self._data[byte_idx]
        return byte >> 4 if nibble_idx == 0 else byte & 0x0F

    def consume(self, amount: int) -> Self:
        """Cuts off nibbles at the beginning of the path."""
        self._offset += amount
        return self

    @classmethod
    def _create_new(cls, path: _NibblePathLike, length: int) -> Self:
        """Creates a new NibblePath from a given object with a certain length."""
        is_odd_len = length % 2 == 1
        pos, data = 0, []

        if is_odd_len:
            data.append(path.at(pos))
            pos += 1

        while pos < length:
            data.append(path.at(pos) * 16 + path.at(pos + 1))
            pos += 2

        offset = 1 if is_odd_len else 0

        return cls(data, offset)

    def common_prefix(self, other: _NibblePathLike) -> NibblePath:
        """Returns common part at the beginning of both paths."""
        least_len = min(len(self), len(other))
        common_len = next(
            (i for i in range(least_len) if self.at(i) != other.at(i)), least_len
        )

        return NibblePath._create_new(self, common_len)

    def encode(self, is_leaf: bool) -> bytes:
        """Encode NibblePath into bytes.

        Encoded path contains prefix with flags of type and length and also may contain
        a padding nibble so the length of encoded path is always even.
        """
        nibbles_len = len(self)
        is_odd = nibbles_len % 2 == 1

        prefix = (
            0x00
            + (self.ODD_FLAG + self.at(0) if is_odd else 0x00)
            + (self.LEAF_FLAG if is_leaf else 0x00)
        )
        output = [prefix]

        pos = nibbles_len % 2
        while pos < nibbles_len:
            byte = self.at(pos) * 16 + self.at(pos + 1)
            output.append(byte)
            pos += 2

        return bytes(output)

    def combine(self, other: _NibblePathLike) -> NibblePath:
        """Merges two paths into one."""
        chained = NibblePath._Chained(self, other)
        return NibblePath._create_new(chained, len(chained))
