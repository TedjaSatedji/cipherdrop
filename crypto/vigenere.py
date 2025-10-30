# All 95 printable ASCII chars from space ( ) to tilde (~)
ALPH = (' !"#$%&\'()*+,-./0123456789:;<=>?@'
        'ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`'
        'abcdefghijklmnopqrstuvwxyz{|}~')

ALPH_LEN = len(ALPH)  # This is 95
# A fast lookup map to get the index of a character
ALPH_MAP = {char: i for i, char in enumerate(ALPH)}

def _clean_key(key: str) -> str:
    """Filters the key to only contain valid alphabet characters."""
    cleaned = ''.join(c for c in key if c in ALPH_MAP)
    # If the key is empty or has no valid chars, default to 'a'
    # to prevent errors.
    return cleaned if cleaned else "a"

def enc_vigenere(plaintext: str, key: str) -> str:
    K = _clean_key(key)
    K_LEN = len(K)
    out = []
    key_idx = 0  # We use a separate index for the key

    for ch in plaintext:
        if ch in ALPH_MAP:
            # This character is in our alphabet, so we shift it.
            shift = ALPH_MAP[K[key_idx % K_LEN]]
            new_idx = (ALPH_MAP[ch] + shift) % ALPH_LEN
            out.append(ALPH[new_idx])
            key_idx += 1  # Only advance the key index when we use it
        else:
            # This char (e.g., newline) isn't in our alphabet.
            # Pass it through unchanged.
            out.append(ch)
            
    return ''.join(out)

def dec_vigenere(ciphertext: str, key: str) -> str:
    K = _clean_key(key)
    K_LEN = len(K)
    out = []
    key_idx = 0

    for ch in ciphertext:
        if ch in ALPH_MAP:
            # This character is in our alphabet, so we un-shift it.
            shift = ALPH_MAP[K[key_idx % K_LEN]]
            new_idx = (ALPH_MAP[ch] - shift) % ALPH_LEN
            out.append(ALPH[new_idx])
            key_idx += 1
        else:
            # This char isn't in our alphabet.
            # Pass it through unchanged.
            out.append(ch)
            
    return ''.join(out)