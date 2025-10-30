ALPH = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
def _norm(s: str) -> str: return ''.join(c for c in s.upper() if c.isalpha())
def enc_vigenere(plaintext: str, key: str) -> str:
    P, K = _norm(plaintext), _norm(key); out=[]
    for i,ch in enumerate(P):
        shift = ALPH.index(K[i%len(K)])
        out.append(ALPH[(ALPH.index(ch)+shift)%26])
    return ''.join(out)
def dec_vigenere(ciphertext: str, key: str) -> str:
    C, K = _norm(ciphertext), _norm(key); out=[]
    for i,ch in enumerate(C):
        shift = ALPH.index(K[i%len(K)])
        out.append(ALPH[(ALPH.index(ch)-shift)%26])
    return ''.join(out)
