#!/usr/bin/env python3
"""
Decrypt all bilgi fields from codes.txt to recover the encrypted password.

The encryption algorithm was reverse-engineered from program.exe.hex, the hex
dump of the Delphi binary.  The cipher works as follows:

  1. A key string is base64-encoded to form the initial keystream seed.
  2. A custom TMD5 object is created.  Its ``HashAsBytes`` is **destructive**:
     it applies MD5 padding/length directly to the live state, so every call
     permanently alters the running hash context (non-resetting behaviour).
  3. Data (UTF-16LE of an MD5 hex-digest) is processed in 16-byte blocks:
       • MD5.Update(current_key_bytes)  then  hash = MD5.HashAsBytes()
       • For each byte in the block two bit-manipulation transforms are
         applied (selected by the upper/lower hex digit of the corresponding
         MD5 hash byte), followed by XOR with that hash byte.
       • The uppercase hex representation of the 16 hash bytes becomes the
         key fed to the next MD5.Update call.

Three different keys are used for the three bilgi fields:
  - bilgi1: key "Aymm+bd0813"  → stores MD5(base64(school_info))
  - bilgi2: key "MBD+MOAE+AY81" → stores MD5(base64(password))
  - bilgi3: key "mfl86+mfl86"  → stores MD5(md5_password + md5_school)

This script implements the full algorithm (NonResettingMD5 + transforms)
derived from program.exe.hex, so it can decrypt any ciphertext without
needing example substitution tables.
"""

import base64
import hashlib
import math
import struct
import sys


# ---------------------------------------------------------------------------
# Non-resetting MD5 (matches the TMD5 class in the Delphi binary)
# ---------------------------------------------------------------------------

_T = [int(abs(math.sin(i + 1)) * (2**32)) & 0xFFFFFFFF for i in range(64)]
_S = (
    [7, 12, 17, 22] * 4
    + [5, 9, 14, 20] * 4
    + [4, 11, 16, 23] * 4
    + [6, 10, 15, 21] * 4
)


def _left_rotate(n, b):
    return ((n << b) | (n >> (32 - b))) & 0xFFFFFFFF


class _NonResettingMD5:
    """MD5 whose ``hash_as_bytes`` permanently modifies the internal state."""

    def __init__(self):
        self.a0 = 0x67452301
        self.b0 = 0xEFCDAB89
        self.c0 = 0x98BADCFE
        self.d0 = 0x10325476
        self._buffer = b""
        self._count_lo = 0
        self._count_hi = 0

    # -- internals ----------------------------------------------------------

    def _process_block(self, block):
        M = struct.unpack("<16I", block)
        a, b, c, d = self.a0, self.b0, self.c0, self.d0
        for i in range(64):
            if i < 16:
                f, g = (b & c) | (~b & d), i
            elif i < 32:
                f, g = (d & b) | (~d & c), (5 * i + 1) % 16
            elif i < 48:
                f, g = b ^ c ^ d, (3 * i + 5) % 16
            else:
                f, g = c ^ (b | ~d), (7 * i) % 16
            f = (f + a + _T[i] + M[g]) & 0xFFFFFFFF
            a, d, c = d, c, b
            b = (b + _left_rotate(f, _S[i])) & 0xFFFFFFFF
        self.a0 = (self.a0 + a) & 0xFFFFFFFF
        self.b0 = (self.b0 + b) & 0xFFFFFFFF
        self.c0 = (self.c0 + c) & 0xFFFFFFFF
        self.d0 = (self.d0 + d) & 0xFFFFFFFF

    # -- public API ---------------------------------------------------------

    def update(self, data):
        """Feed *data* into the running hash (same semantics as hashlib)."""
        data_bits = len(data) * 8
        new_lo = (self._count_lo + data_bits) & 0xFFFFFFFF
        if new_lo < self._count_lo:
            self._count_hi = (self._count_hi + 1) & 0xFFFFFFFF
        self._count_lo = new_lo
        self._count_hi = (self._count_hi + (len(data) >> 29)) & 0xFFFFFFFF

        self._buffer += data
        while len(self._buffer) >= 64:
            self._process_block(self._buffer[:64])
            self._buffer = self._buffer[64:]

    def hash_as_bytes(self):
        """Return the 16-byte digest **and** permanently alter state.

        This mirrors the Delphi TMD5.HashAsBytes which applies MD5 padding
        and length directly to the live context without resetting afterwards.
        """
        saved_bits = struct.pack("<II", self._count_lo, self._count_hi)
        pos = len(self._buffer)
        # Pad to 56 bytes (mod 64) so the 8-byte length fits in one block
        pad_len = (56 - pos) if pos < 56 else (64 + 56 - pos)
        self.update(b"\x80" + b"\x00" * (pad_len - 1))
        self.update(saved_bits)
        return struct.pack("<IIII", self.a0, self.b0, self.c0, self.d0)


# ---------------------------------------------------------------------------
# Byte-level transforms (from sifreleme_icin_degistir in the binary)
# ---------------------------------------------------------------------------

_XOR_MASKS = {
    0x0: 0xF0, 0x1: 0x0F, 0x2: 0x3C, 0x3: 0xC3,
    0x4: 0xC0, 0x5: 0x03, 0x6: 0x18, 0x7: 0xE0,
    0x8: 0x07, 0x9: 0x70, 0xA: 0x0E, 0xB: 0xE7,
}


def _rol8(v, n):
    n %= 8
    return ((v << n) | (v >> (8 - n))) & 0xFF


def _ror8(v, n):
    n %= 8
    return ((v >> n) | (v << (8 - n))) & 0xFF


def _swap_bits_partial(b):
    """Swap bits 0↔7 and 1↔6; keep bits 2-5 unchanged."""
    return ((b & 1) << 7) | ((b >> 7) & 1) | \
           ((b & 2) << 5) | ((b >> 5) & 2) | \
           (b & 0x3C)  # preserve bits 2-5


def _swap_bits_full(b):
    """Swap bits 0↔7, 1↔6, and 2↔5; keep bits 3-4 unchanged."""
    return ((b & 1) << 7) | ((b >> 7) & 1) | \
           ((b & 2) << 5) | ((b >> 5) & 2) | \
           ((b & 4) << 3) | ((b >> 3) & 4) | \
           (b & 0x18)  # preserve bits 3-4


def _transform1(byte_val, lo_digit):
    """First transform, selected by the lower hex digit of the MD5 byte."""
    if lo_digit in _XOR_MASKS:
        return byte_val ^ _XOR_MASKS[lo_digit]
    if lo_digit == 0xC:
        return (byte_val & 0xE7) | (((byte_val >> 3) & 1) << 4) | \
               (((byte_val >> 4) & 1) << 3)
    if lo_digit == 0xD:
        return ((byte_val & 0x30) >> 2) | ((byte_val & 0x0C) << 2) | \
               (byte_val & 0xC3)
    if lo_digit == 0xE:
        return ((byte_val & 0x70) >> 3) | ((byte_val & 0x0E) << 3) | \
               (byte_val & 0x81)
    # 0xF
    return ((byte_val >> 4) & 0x0F) | ((byte_val & 0x0F) << 4)


def _transform2(byte_val, hi_digit):
    """Second transform, selected by the upper hex digit of the MD5 byte."""
    if hi_digit <= 6:
        return _rol8(byte_val, hi_digit + 1)
    rmap = {7: 1, 8: 2, 9: 3, 0xA: 5, 0xB: 6, 0xC: 7}
    if hi_digit in rmap:
        return _ror8(byte_val, rmap[hi_digit])
    if hi_digit == 0xD:
        return (~byte_val) & 0xFF
    if hi_digit == 0xE:
        return _swap_bits_partial(byte_val)
    # 0xF
    return _swap_bits_full(byte_val)


def _inv_transform2(byte_val, hi_digit):
    """Inverse of _transform2."""
    if hi_digit <= 6:
        return _ror8(byte_val, hi_digit + 1)
    rmap = {7: 1, 8: 2, 9: 3, 0xA: 5, 0xB: 6, 0xC: 7}
    if hi_digit in rmap:
        return _rol8(byte_val, rmap[hi_digit])
    if hi_digit == 0xD:
        return (~byte_val) & 0xFF
    if hi_digit == 0xE:
        return _swap_bits_partial(byte_val)
    # 0xF
    return _swap_bits_full(byte_val)


def _encrypt_byte(plain_byte, hash_byte):
    hi, lo = hash_byte >> 4, hash_byte & 0xF
    return _transform2(_transform1(plain_byte, lo), hi) ^ hash_byte


def _decrypt_byte(cipher_byte, hash_byte):
    hi, lo = hash_byte >> 4, hash_byte & 0xF
    return _transform1(_inv_transform2(cipher_byte ^ hash_byte, hi), lo)


# ---------------------------------------------------------------------------
# High-level encrypt / decrypt
# ---------------------------------------------------------------------------

BILGI1_KEY = "Aymm+bd0813"
BILGI2_KEY = "MBD+MOAE+AY81"
BILGI3_KEY = "mfl86+mfl86"
ENCRYPTION_KEY = BILGI2_KEY  # default for backward compatibility


def encrypt(plaintext_bytes, key=ENCRYPTION_KEY):
    """Encrypt *plaintext_bytes* using the algorithm from the binary."""
    b64key = base64.b64encode(key.encode("ascii")).decode("ascii")
    data = bytearray(plaintext_bytes)
    n = len(data)
    md5 = _NonResettingMD5()
    current_key = b64key
    pos = 0
    while pos < n:
        md5.update(current_key.encode("ascii"))
        hb = md5.hash_as_bytes()
        current_key = ""
        for bi in range(16):
            if pos >= n:
                break
            data[pos] = _encrypt_byte(data[pos], hb[bi])
            current_key += f"{hb[bi]:02X}"
            pos += 1
    return bytes(data)


def decrypt(ciphertext_bytes, key=ENCRYPTION_KEY):
    """Decrypt *ciphertext_bytes* using the algorithm from the binary."""
    b64key = base64.b64encode(key.encode("ascii")).decode("ascii")
    data = bytearray(ciphertext_bytes)
    n = len(data)
    md5 = _NonResettingMD5()
    current_key = b64key
    pos = 0
    while pos < n:
        md5.update(current_key.encode("ascii"))
        hb = md5.hash_as_bytes()
        current_key = ""
        for bi in range(16):
            if pos >= n:
                break
            data[pos] = _decrypt_byte(data[pos], hb[bi])
            current_key += f"{hb[bi]:02X}"
            pos += 1
    return bytes(data)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def parse_examples(path="examples.txt"):
    """Parse password/bilgi2/bilgi3 triplets from examples.txt."""
    examples = []
    with open(path) as f:
        lines = f.readlines()
    i = 0
    while i < len(lines):
        line = lines[i].strip()
        if line.startswith('"') and line.endswith('"'):
            pwd = line[1:-1]
            b2 = lines[i + 1].strip().split("=", 1)[1]
            b3 = lines[i + 2].strip().split("=", 1)[1]
            examples.append((pwd, b2, b3))
            i += 3
        else:
            i += 1
    return examples


def get_b64(pwd):
    """Base64-encode a password (UTF-8 for ASCII, cp1254 for Turkish chars)."""
    try:
        pwd.encode("ascii")
        return base64.b64encode(pwd.encode("utf-8")).decode()
    except UnicodeEncodeError:
        return base64.b64encode(pwd.encode("cp1254")).decode()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    examples = parse_examples()
    print(f"Loaded {len(examples)} examples from examples.txt")

    # Validate the algorithm against every known example
    print("\nValidation (algorithm derived from program.exe.hex):")
    all_ok = True
    for pwd, b2, _ in examples:
        b64 = get_b64(pwd)
        expected_hash = hashlib.md5(b64.encode()).hexdigest()
        expected_pt = expected_hash.encode("utf-16-le")
        ct = base64.b64decode(b2)

        # Round-trip check: encrypt then compare
        encrypted = encrypt(expected_pt)
        enc_ok = encrypted == ct

        # Decrypt and recover the MD5 hex digest
        decrypted = decrypt(ct)
        recovered = decrypted.decode("utf-16-le")
        dec_ok = recovered == expected_hash

        ok = enc_ok and dec_ok
        print(f"  {'✓' if ok else '✗'} '{pwd}': {recovered}")
        if not ok:
            all_ok = False

    if not all_ok:
        print("\nWARNING: Some examples failed validation!")
        sys.exit(1)

    # Validate bilgi3 cross-check for all examples
    school_info = "İSTANBUL BEYKOZ NUN OKULLARI"
    school_b64 = base64.b64encode(school_info.encode("cp1254")).decode()
    school_hash = hashlib.md5(school_b64.encode()).hexdigest()

    print(f"\nBilgi3 cross-validation:")
    for pwd, b2, b3 in examples:
        b64_pwd = get_b64(pwd)
        pwd_hash = hashlib.md5(b64_pwd.encode()).hexdigest()
        expected_b3 = hashlib.md5(
            (pwd_hash + school_hash).encode()
        ).hexdigest()
        ct_b3 = base64.b64decode(b3)
        actual_b3 = decrypt(ct_b3, BILGI3_KEY).decode("utf-16-le")
        ok = actual_b3 == expected_b3
        print(f"  {'✓' if ok else '✗'} '{pwd}': bilgi3 = {actual_b3}")
        if not ok:
            all_ok = False

    if not all_ok:
        print("\nWARNING: bilgi3 cross-validation failed!")
        sys.exit(1)

    # -----------------------------------------------------------------------
    # Decrypt all three bilgi fields from codes.txt
    # -----------------------------------------------------------------------
    codes_bilgi = {}
    with open("codes.txt") as f:
        for line in f:
            stripped = line.strip()
            for tag in ("bilgi1", "bilgi2", "bilgi3"):
                if stripped.startswith(f"{tag}="):
                    codes_bilgi[tag] = stripped.split("=", 1)[1]

    print(f"\n{'='*60}")
    print("Decrypting codes.txt")
    print(f"{'='*60}")

    # bilgi1: school info hash
    ct1 = base64.b64decode(codes_bilgi["bilgi1"])
    pt1 = decrypt(ct1, BILGI1_KEY).decode("utf-16-le")
    print(f"\nbilgi1 (key: {BILGI1_KEY}):")
    print(f"  Decrypted: {pt1}")
    print(f"  This is MD5(base64(\"{school_info}\", cp1254))")
    verify1 = pt1 == school_hash
    print(f"  Verified: {'✓' if verify1 else '✗'} (expected {school_hash})")

    # bilgi2: password hash
    ct2 = base64.b64decode(codes_bilgi["bilgi2"])
    pt2 = decrypt(ct2, BILGI2_KEY).decode("utf-16-le")
    print(f"\nbilgi2 (key: {BILGI2_KEY}):")
    print(f"  Decrypted: {pt2}")
    print(f"  This is MD5(base64(password))")
    print(f"  *** This is the encrypted password hash ***")

    # bilgi3: cross-check hash
    ct3 = base64.b64decode(codes_bilgi["bilgi3"])
    pt3 = decrypt(ct3, BILGI3_KEY).decode("utf-16-le")
    expected_b3 = hashlib.md5((pt2 + pt1).encode()).hexdigest()
    verify3 = pt3 == expected_b3
    print(f"\nbilgi3 (key: {BILGI3_KEY}):")
    print(f"  Decrypted: {pt3}")
    print(f"  This is MD5(md5_password + md5_school)")
    print(
        f"  Verified: {'✓' if verify3 else '✗'} "
        f"(MD5(\"{pt2}\" + \"{pt1}\") = {expected_b3})"
    )

    # Summary
    print(f"\n{'='*60}")
    print("SUMMARY")
    print(f"{'='*60}")
    print(f"School info: {school_info}")
    print(f"bilgi1 = MD5(base64(school_info)) = {pt1}")
    print(f"bilgi2 = MD5(base64(password))    = {pt2}")
    print(f"bilgi3 = MD5(bilgi2 + bilgi1)     = {pt3}")
    print(f"\nEncrypted password (MD5 hash): {pt2}")
    print(f"All cross-checks passed: {'✓' if verify1 and verify3 else '✗'}")


if __name__ == "__main__":
    main()
