import hashlib


def compute_sha256(file_path: str) -> str:
    """
    Compute the SHA256 hash of a file
    :param file_path: Path to the file you want to compute the SHA256 hash for.
    :return: SHA256 hash of the file.
    """
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()