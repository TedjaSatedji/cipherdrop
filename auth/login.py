from argon2 import PasswordHasher
ph = PasswordHasher()
def make_login_hash(password: str) -> str: return ph.hash(password)
def verify_login_hash(password: str, stored: str) -> bool: return ph.verify(stored, password)
