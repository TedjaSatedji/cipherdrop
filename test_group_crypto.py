"""
Group Messaging Test Script

This script tests the group messaging cryptographic functions.
Run this to verify the encryption/decryption logic works correctly.

Usage:
    python test_group_crypto.py
"""

import base64
import json
import secrets
import sys
import os

# Add the project root to the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import the crypto functions from cipherapp
try:
    from auth.keys import derive_key_from_password, ARGON_PARAMS
    from crypto.supertext import super_encrypt_text, super_decrypt_text
except ImportError:
    print("❌ Could not import crypto modules. Make sure you're running from the project root.")
    sys.exit(1)

# Import the group functions
def generate_group_key():
    """Generate a random 32-byte group key for AES-256."""
    return secrets.token_bytes(32)

def encrypt_group_key_for_user(group_key, user_passphrase):
    """Encrypt a group key with a user's passphrase."""
    dk = derive_key_from_password(user_passphrase)
    group_key_hex = group_key.hex()
    env = super_encrypt_text(group_key_hex, "GROUPKEY", dk.key)
    env["kdf"] = {
        "type": "argon2id",
        "salt_b64": base64.b64encode(dk.salt).decode(),
        "t": ARGON_PARAMS["time_cost"],
        "m": ARGON_PARAMS["memory_cost"],
        "p": ARGON_PARAMS["parallelism"],
    }
    return base64.b64encode(json.dumps(env).encode()).decode()

def decrypt_group_key_for_user(encrypted_group_key_b64, user_passphrase):
    """Decrypt a group key using a user's passphrase."""
    env = json.loads(base64.b64decode(encrypted_group_key_b64))
    salt = base64.b64decode(env["kdf"]["salt_b64"])
    dk = derive_key_from_password(user_passphrase, salt)
    group_key_hex = super_decrypt_text(env, "GROUPKEY", dk.key)
    return bytes.fromhex(group_key_hex)

def encrypt_group_message(message, group_key):
    """Encrypt a message with a group key."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    aesgcm = AESGCM(group_key)
    nonce = secrets.token_bytes(12)
    ciphertext = aesgcm.encrypt(nonce, message.encode('utf-8'), None)
    blob = nonce + ciphertext
    return base64.b64encode(blob).decode()

def decrypt_group_message(encrypted_blob_b64, group_key):
    """Decrypt a message with a group key."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    blob = base64.b64decode(encrypted_blob_b64)
    nonce = blob[:12]
    ciphertext = blob[12:]
    aesgcm = AESGCM(group_key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    return plaintext.decode('utf-8')

def run_tests():
    """Run all tests."""
    print("=" * 60)
    print("GROUP MESSAGING CRYPTOGRAPHY TESTS")
    print("=" * 60)
    print()
    
    # Test 1: Generate Group Key
    print("Test 1: Generate Group Key")
    print("-" * 60)
    group_key = generate_group_key()
    print(f"✓ Generated group key: {len(group_key)} bytes")
    print(f"  Key (hex): {group_key.hex()[:32]}...")
    print()
    
    # Test 2: Encrypt Group Key for User A
    print("Test 2: Encrypt Group Key for User A")
    print("-" * 60)
    passphrase_a = "alice_secret_123"
    encrypted_key_a = encrypt_group_key_for_user(group_key, passphrase_a)
    print(f"✓ Encrypted for User A")
    print(f"  Passphrase: {passphrase_a}")
    print(f"  Encrypted: {encrypted_key_a[:50]}...")
    print()
    
    # Test 3: Encrypt Group Key for User B
    print("Test 3: Encrypt Group Key for User B")
    print("-" * 60)
    passphrase_b = "bob_secret_456"
    encrypted_key_b = encrypt_group_key_for_user(group_key, passphrase_b)
    print(f"✓ Encrypted for User B")
    print(f"  Passphrase: {passphrase_b}")
    print(f"  Encrypted: {encrypted_key_b[:50]}...")
    print()
    
    # Test 4: Decrypt Group Key as User A
    print("Test 4: Decrypt Group Key as User A")
    print("-" * 60)
    decrypted_key_a = decrypt_group_key_for_user(encrypted_key_a, passphrase_a)
    if decrypted_key_a == group_key:
        print(f"✓ User A successfully decrypted group key")
        print(f"  Original:  {group_key.hex()}")
        print(f"  Decrypted: {decrypted_key_a.hex()}")
    else:
        print(f"❌ User A failed to decrypt group key")
        return False
    print()
    
    # Test 5: Decrypt Group Key as User B
    print("Test 5: Decrypt Group Key as User B")
    print("-" * 60)
    decrypted_key_b = decrypt_group_key_for_user(encrypted_key_b, passphrase_b)
    if decrypted_key_b == group_key:
        print(f"✓ User B successfully decrypted group key")
        print(f"  Original:  {group_key.hex()}")
        print(f"  Decrypted: {decrypted_key_b.hex()}")
    else:
        print(f"❌ User B failed to decrypt group key")
        return False
    print()
    
    # Test 6: Wrong Passphrase Should Fail
    print("Test 6: Wrong Passphrase Should Fail")
    print("-" * 60)
    try:
        decrypt_group_key_for_user(encrypted_key_a, "wrong_password")
        print(f"❌ Decryption with wrong password should have failed!")
        return False
    except Exception as e:
        print(f"✓ Correctly rejected wrong passphrase")
        print(f"  Error: {str(e)[:50]}...")
    print()
    
    # Test 7: Encrypt a Message
    print("Test 7: Encrypt a Message")
    print("-" * 60)
    message = "Hello, this is a secret group message! 🔒"
    encrypted_message = encrypt_group_message(message, group_key)
    print(f"✓ Encrypted message")
    print(f"  Original: {message}")
    print(f"  Encrypted: {encrypted_message[:50]}...")
    print()
    
    # Test 8: Decrypt Message as User A
    print("Test 8: Decrypt Message as User A")
    print("-" * 60)
    decrypted_message_a = decrypt_group_message(encrypted_message, decrypted_key_a)
    if decrypted_message_a == message:
        print(f"✓ User A successfully decrypted message")
        print(f"  Original:  {message}")
        print(f"  Decrypted: {decrypted_message_a}")
    else:
        print(f"❌ User A failed to decrypt message")
        return False
    print()
    
    # Test 9: Decrypt Message as User B
    print("Test 9: Decrypt Message as User B")
    print("-" * 60)
    decrypted_message_b = decrypt_group_message(encrypted_message, decrypted_key_b)
    if decrypted_message_b == message:
        print(f"✓ User B successfully decrypted message")
        print(f"  Original:  {message}")
        print(f"  Decrypted: {decrypted_message_b}")
    else:
        print(f"❌ User B failed to decrypt message")
        return False
    print()
    
    # Test 10: Multiple Messages
    print("Test 10: Multiple Messages")
    print("-" * 60)
    messages = [
        "First message",
        "Second message with emoji 😊",
        "Third message with special chars: !@#$%^&*()",
    ]
    encrypted_messages = []
    for msg in messages:
        enc = encrypt_group_message(msg, group_key)
        encrypted_messages.append(enc)
        print(f"  ✓ Encrypted: {msg[:30]}...")
    
    print()
    print("  Decrypting all messages...")
    for i, enc in enumerate(encrypted_messages):
        dec = decrypt_group_message(enc, group_key)
        if dec == messages[i]:
            print(f"  ✓ Message {i+1} decrypted correctly")
        else:
            print(f"  ❌ Message {i+1} decryption failed")
            return False
    print()
    
    # Test 11: Large Message
    print("Test 11: Large Message")
    print("-" * 60)
    large_message = "A" * 10000 + " This is a large message test"
    encrypted_large = encrypt_group_message(large_message, group_key)
    decrypted_large = decrypt_group_message(encrypted_large, group_key)
    if decrypted_large == large_message:
        print(f"✓ Large message ({len(large_message)} chars) encrypted/decrypted successfully")
    else:
        print(f"❌ Large message encryption/decryption failed")
        return False
    print()
    
    # Test 12: Unicode and Special Characters
    print("Test 12: Unicode and Special Characters")
    print("-" * 60)
    unicode_message = "Hello 世界 🌍 Привет مرحبا"
    encrypted_unicode = encrypt_group_message(unicode_message, group_key)
    decrypted_unicode = decrypt_group_message(encrypted_unicode, group_key)
    if decrypted_unicode == unicode_message:
        print(f"✓ Unicode message encrypted/decrypted successfully")
        print(f"  Original:  {unicode_message}")
        print(f"  Decrypted: {decrypted_unicode}")
    else:
        print(f"❌ Unicode message encryption/decryption failed")
        return False
    print()
    
    return True

if __name__ == "__main__":
    print()
    success = run_tests()
    print("=" * 60)
    if success:
        print("✅ ALL TESTS PASSED!")
        print("=" * 60)
        print()
        print("The group messaging cryptography is working correctly.")
        print("You can now proceed to test the full application.")
        print()
        sys.exit(0)
    else:
        print("❌ SOME TESTS FAILED!")
        print("=" * 60)
        print()
        print("Please check the errors above and fix the implementation.")
        print()
        sys.exit(1)
