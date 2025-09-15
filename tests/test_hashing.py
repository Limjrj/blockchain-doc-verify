import hashlib
import pytest
from src.hashing import sha256_stream,  to_onchain_doc_hash, file_to_doc_hash

EMPTY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
ABC_SHA256 = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"

def _write(tmp_path, name: str, data: bytes):
    p = tmp_path / name
    p.write_bytes(data)
    return p 

def test_sha256_empty(tmp_path):
    p = _write(tmp_path, "empty", b"")
    d = sha256_stream(str(p))
    assert d.hex() == EMPTY_SHA256 and len(d) == 32

def test_sha256_abc(tmp_path):
    p = _write(tmp_path, "abc.txt", b"abc")
    d = sha256_stream(str(p))
    assert d.hex() == ABC_SHA256

def test_streaming_large(tmp_path):
    data = b"A" * (5*1024*1024 +123) # ~5MiB + a bit
    p = _write(tmp_path, "big.bin", data)
    assert sha256_stream(str(p)) == hashlib.sha256(data).digest()

def test_chunk_size_validation(tmp_path):
    p = _write(tmp_path, "x.bin", b"x")
    with pytest.raises(ValueError): sha256_stream(str(p), 0)
    with pytest.raises(ValueError): sha256_stream(str(p), -1)

def test_missing_file_raises():
    with pytest.raises(FileNotFoundError):
        sha256_stream("no/such/file")

def test_file_to_doc_hash(tmp_path):
    p = _write(tmp_path, "abc.txt", b"abc")
    sha, leaf = file_to_doc_hash(str(p))
    assert sha.hex() == ABC_SHA256
    assert len(leaf) == 32 and leaf != sha # keccak(sha256(file)) differs from sha256(file)