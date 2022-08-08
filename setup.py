import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="eth_mpt",
    version="0.2.0",
    author="Igor Aleksanov",
    author_email="popzxc@yandex.com",
    description="A simlpe Merkle Patricia Trie implementation",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/popzxc/merkle-patricia-trie",
    packages=setuptools.find_packages(),
    install_requires=[
        'cytoolz ~= 0.12.0',
        'eth-hash ~= 0.5.0',
        'eth-typing ~= 3.1.0',
        'eth-utils ~= 1.10.0',
        'pycryptodome ~= 3.15.0',
        'rlp ~= 2.0.1',
        'toolz ~= 0.12.0',
    ],
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Security :: Cryptography",
    ],
)
