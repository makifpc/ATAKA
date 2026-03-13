#!/usr/bin/env python3
"""
Decrypt bilgi2 from codes.txt to recover the password hash.

The encryption algorithm in sifre_cozu.exe uses:
  1. Key "MBD+MOAE+AY81" (base64-encoded before use)
  2. MD5-based key stream with non-resetting THashMD5 state
  3. Per-byte: two bit-manipulation transforms selected by MD5 byte hex digits, then XOR
  4. 64-byte output = MD5(base64(password)) in UTF-16LE encoding

This script builds byte-level substitution tables from examples.txt (known
plaintext/ciphertext pairs) and applies them to decrypt codes.txt.
"""

import base64
import hashlib
import sys


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


def build_substitution_tables(examples):
    """Build forward (pt→ct) and reverse (ct→pt) tables from known pairs."""
    fwd = [{} for _ in range(64)]  # pt_byte → ct_byte per position
    rev = [{} for _ in range(64)]  # ct_byte → pt_byte per position

    for pwd, b2, _ in examples:
        b64 = get_b64(pwd)
        md5hex = hashlib.md5(b64.encode()).hexdigest()
        pt = md5hex.encode("utf-16-le")
        ct = base64.b64decode(b2)

        for j in range(64):
            fwd[j][pt[j]] = ct[j]
            rev[j][ct[j]] = pt[j]

    return fwd, rev


def decrypt_bilgi2(codes_b2, rev_tables):
    """Decrypt bilgi2 ciphertext using reverse substitution tables."""
    ct = base64.b64decode(codes_b2)
    result = []
    for j in range(64):
        if ct[j] in rev_tables[j]:
            result.append(rev_tables[j][ct[j]])
        else:
            result.append(None)
    return result


def bytes_to_hex_string(decrypted):
    """Convert decrypted UTF-16LE bytes to hex string (even positions only)."""
    chars = []
    for j in range(0, 64, 2):
        if decrypted[j] is not None:
            chars.append(chr(decrypted[j]))
        else:
            chars.append("?")
    return "".join(chars)


def fill_gaps_with_bit_analysis(partial_hash, fwd_tables, codes_ct):
    """
    Fill missing positions using constraint analysis.
    
    At even positions (hex chars), valid values are 0x30-0x39 (0-9) and
    0x61-0x66 (a-f). At odd positions, values should be 0x00 (UTF-16LE).
    Try all valid hex char values and check for unique solutions.
    """
    hex_chars = [ord(c) for c in "0123456789abcdef"]
    filled = list(partial_hash)
    
    for char_pos in range(32):
        if filled[char_pos] != "?":
            continue
        byte_pos = char_pos * 2  # even byte position in UTF-16LE
        ct_byte = codes_ct[byte_pos]
        
        candidates = []
        for hc in hex_chars:
            # Check if this hex char's ciphertext matches
            if hc in fwd_tables[byte_pos] and fwd_tables[byte_pos][hc] == ct_byte:
                candidates.append(chr(hc))
        
        if len(candidates) == 1:
            filled[char_pos] = candidates[0]
        elif len(candidates) > 1:
            # Filter to only valid MD5 hex chars
            valid = [c for c in candidates if c in "0123456789abcdef"]
            if len(valid) == 1:
                filled[char_pos] = valid[0]
            else:
                filled[char_pos] = f"[{'|'.join(candidates)}]"
    
    return "".join(filled)


def main():
    examples = parse_examples()
    print(f"Loaded {len(examples)} examples from examples.txt")
    
    # Build tables
    fwd, rev = build_substitution_tables(examples)
    
    # Validate against all examples
    print("\nValidation:")
    all_ok = True
    for pwd, b2, _ in examples:
        b64 = get_b64(pwd)
        expected = hashlib.md5(b64.encode()).hexdigest()
        decrypted = decrypt_bilgi2(b2, rev)
        result = bytes_to_hex_string(decrypted)
        ok = result == expected
        print(f"  {'✓' if ok else '✗'} '{pwd}': {result}")
        if not ok:
            all_ok = False
    
    if not all_ok:
        print("\nWARNING: Some examples failed validation!")
        sys.exit(1)
    
    # Decrypt codes.txt
    codes_b2 = None
    with open("codes.txt") as f:
        for line in f:
            if line.strip().startswith("bilgi2="):
                codes_b2 = line.strip().split("=", 1)[1]
    
    if not codes_b2:
        print("ERROR: bilgi2 not found in codes.txt")
        sys.exit(1)
    
    codes_ct = base64.b64decode(codes_b2)
    decrypted = decrypt_bilgi2(codes_b2, rev)
    partial_hash = bytes_to_hex_string(decrypted)
    
    # Fill gaps using forward tables
    full_hash = fill_gaps_with_bit_analysis(partial_hash, fwd, codes_ct)
    
    print(f"\n{'='*60}")
    print(f"Decrypted bilgi2 from codes.txt:")
    print(f"  Partial (substitution only): {partial_hash}")
    print(f"  Full (with gap filling):     {full_hash}")
    print(f"\nThis value = MD5(base64(password))")
    print(f"To find the password, crack this MD5 hash where the")
    print(f"input is the base64 encoding of the password string.")
    print(f"{'='*60}")


if __name__ == "__main__":
    main()
