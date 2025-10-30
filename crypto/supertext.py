import base64
from .vigenere import enc_vigenere, dec_vigenere
from .stream import stream_encrypt, stream_decrypt

def super_encrypt_text(text: str, vkey: str, key32: bytes) -> dict:
    v = enc_vigenere(text, vkey)
    nonce, ct = stream_encrypt(key32, v.encode())
    return {"ver":1,"algo":"VIG+CHACHA20P1305",
            "nonce_b64":base64.b64encode(nonce).decode(),
            "ct_b64":base64.b64encode(ct).decode()}

def super_decrypt_text(blob: dict, vkey: str, key32: bytes) -> str:
    nonce = base64.b64decode(blob["nonce_b64"])
    ct    = base64.b64decode(blob["ct_b64"])
    v = stream_decrypt(key32, nonce, ct).decode()
    return dec_vigenere(v, vkey)
