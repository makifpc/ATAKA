#!/usr/bin/env python3
"""
Decrypt bilgi2 from codes.txt to recover the password hash.

The encryption algorithm was reverse-engineered from program.exe.hex, the hex
dump of the Delphi binary.  The cipher works as follows:

  1. Key "MBD+MOAE+AY81" is base64-encoded → "TUJEK01PQUUrQVk4MQ=="
  2. A custom TMD5 object is created.  Its ``HashAsBytes`` is **destructive**:
     it applies MD5 padding/length directly to the live state, so every call
     permanently alters the running hash context (non-resetting behaviour).
  3. Data (UTF-16LE of the MD5 hex-digest of base64(password)) is processed
     in 16-byte blocks:
       • MD5.Update(current_key_bytes)  then  hash = MD5.HashAsBytes()
       • For each byte in the block two bit-manipulation transforms are
         applied (selected by the upper/lower hex digit of the corresponding
         MD5 hash byte), followed by XOR with that hash byte.
       • The uppercase hex representation of the 16 hash bytes becomes the
         key fed to the next MD5.Update call.

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

ENCRYPTION_KEY = "MBD+MOAE+AY81"


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

    # Decrypt codes.txt bilgi2
    codes_b2 = None
    with open("codes.txt") as f:
        for line in f:
            if line.strip().startswith("bilgi2="):
                codes_b2 = line.strip().split("=", 1)[1]

    if not codes_b2:
        print("ERROR: bilgi2 not found in codes.txt")
        sys.exit(1)

    ct = base64.b64decode(codes_b2)
    decrypted = decrypt(ct)
    md5_hash = decrypted.decode("utf-16-le")

    print(f"\n{'='*60}")
    print(f"Decrypted bilgi2 from codes.txt:")
    print(f"  MD5(base64(password)) = {md5_hash}")
    print(f"\nTo find the password, crack this MD5 hash where the")
    print(f"input is the base64 encoding of the password string.")
    print(f"{'='*60}")


if __name__ == "__main__":
    main()
