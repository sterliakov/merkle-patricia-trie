import sha3  # pysha3


def keccak_hash(data):
    hasher = sha3.keccak_256()
    hasher.update(data)
    return hasher.digest()
