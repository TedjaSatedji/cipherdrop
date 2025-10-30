from argon2.low_level import Type, hash_secret_raw
from os import urandom
from dataclasses import dataclass

ARGON_PARAMS = dict(time_cost=3, memory_cost=64_000, parallelism=2,
                    hash_len=32, type=Type.ID)

@dataclass
class DerivedKey:
    key: bytes
    salt: bytes

def derive_key_from_password(password: str, salt: bytes | None = None) -> DerivedKey:
    if salt is None:
        salt = urandom(16)
    key = hash_secret_raw(password.encode(), salt, **ARGON_PARAMS)
    return DerivedKey(key=key, salt=salt)
