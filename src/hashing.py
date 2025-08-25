import hashlib
from eth_utils import keccak

def sha256_stream(path: str, chunk_size: int = 1024*1024) -> bytes:
    if chunk_size<=0:
        raise ValueError("chunk_size must be greater than 0")
    
    h = hashlib.sha256()

    with open(path, "rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            h.update(chunk)
    return h.digest() # raw 32 bytes

def to_onchain_doc_hash(file_sha256: bytes) -> bytes:
    if not isinstance(file_sha256, (bytes, bytearray)):
        raise TypeError("file_sha256 must be  bytes or bytearray")
    if len(file_sha256)!=32:
        raise ValueError("file_sha256 must be a 32-byte digest")
    return keccak(file_sha256)

def file_to_doc_hash(path: str) -> tuple[bytes, bytes]:
    file_sha = sha256_stream(path)
    return file_sha, to_onchain_doc_hash(file_sha)

if __name__ == "__main__":
    import argparse, os

    parser = argparse.ArgumentParser(description="Hash a file for on-chain doc verification.")
    parser.add_argument("path", help="Path to the file to hash")
    parser.add_argument("--chunk", type=int, default=1024 * 1024, help="Chunk size in bytes (default: 1MiB)")
    args = parser.parse_args()

    if not os.path.exists(args.path):
        raise FileNotFoundError(f"No such file: {args.path}")

    sha, leaf = file_to_doc_hash(args.path)
    print("SHA-256:", sha.hex())
    print("DocHash (keccak(sha256(file))):", leaf.hex())