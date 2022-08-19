[![PyPi Version](https://img.shields.io/pypi/v/merkle-patricia-trie.svg)](https://pypi.python.org/pypi/merkle-patricia-trie/)
[![Python Versions](https://img.shields.io/pypi/pyversions/merkle-patricia-trie.svg)](https://pypi.python.org/pypi/merkle-patricia-trie/)
[![pre-commit](https://img.shields.io/badge/pre--commit-enabled-brightgreen?logo=pre-commit&logoColor=white)](https://github.com/pre-commit/pre-commit)
[![Code style: black](https://img.shields.io/badge/code%20style-blue-blue.svg)](https://blue.readthedocs.io/)


# Credits

This is a fork of [eth_mpt](https://github.com/popzxc/merkle-patricia-trie) package with minor improvements.

# Modified Merkle Paticia Trie

MPT is the data structure used in [Ethereum](https://www.ethereum.org/) as a cryptographically authenticated key-value data storage.

This library is a Python implementation of Modified Merkle Patrica Trie with a very simple interface.

## Example

```python
storage = {}
trie = MerklePatriciaTrie(storage)

trie.update(b'do', b'verb')
trie.update(b'dog', b'puppy')
trie.update(b'doge', b'coin')
trie.update(b'horse', b'stallion')

old_root = trie.root()
old_root_hash = trie.root_hash()

print("Root hash is {}".format(old_root_hash.hex()))

trie.delete(b'doge')

print("New root hash is {}".format(trie.root_hash().hex()))

trie_from_old_hash = MerklePatriciaTrie(storage, root=old_root)

print(trie_from_old_hash.get(b'doge'))

try:
    print(trie.get(b'doge'))
except KeyError:
    print('Not accessible in a new trie.')
```

## Installing

Install and update using [pip](https://pip.pypa.io/en/stable/quickstart/):

```
pip install -U mercle_patricia_trie
```
