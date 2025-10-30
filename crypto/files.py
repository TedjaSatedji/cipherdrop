from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from os import urandom
from auth.keys import derive_key_from_password  # <-- use your KDF

MAGIC = b"AGC2"  # new magic for salted format (was AGCM)

def aesgcm_encrypt_file_with_passphrase(passphrase: str, in_path: str, out_path: str):
    """Encrypt a file with AES-GCM. Header = MAGIC(4) + SALT(16) + NONCE(12) + CT."""
    dk = derive_key_from_password(passphrase)  # fresh random salt
    aes = AESGCM(dk.key)
    nonce = urandom(12)
    with open(in_path, "rb") as f:
        pt = f.read()
    ct = aes.encrypt(nonce, pt, b"file")
    with open(out_path, "wb") as f:
        f.write(MAGIC + dk.salt + nonce + ct)

def aesgcm_decrypt_bytes_with_passphrase(passphrase: str, blob: bytes) -> bytes:
    """Decrypt bytes produced by the function above."""
    if not blob.startswith(MAGIC):
        raise ValueError("Unsupported file format or magic header")
    salt = blob[4:20]
    nonce = blob[20:32]
    ct = blob[32:]
    dk = derive_key_from_password(passphrase, salt)
    aes = AESGCM(dk.key)
    return aes.decrypt(nonce, ct, b"file")
