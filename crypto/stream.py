from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from os import urandom
def stream_encrypt(key: bytes, plaintext: bytes, aad: bytes=b""):
    nonce = urandom(12)
    ct = ChaCha20Poly1305(key).encrypt(nonce, plaintext, aad)
    return nonce, ct
def stream_decrypt(key: bytes, nonce: bytes, ct: bytes, aad: bytes=b""):
    return ChaCha20Poly1305(key).decrypt(nonce, ct, aad)
