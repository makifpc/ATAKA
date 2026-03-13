# ATAKA Binary Analysis - Findings

## Overview

The repository contains a hex-encoded Windows PE binary (`program.exe.hex`) and encrypted data files (`codes.txt`, `examples.txt`). The binary implements a custom encryption scheme used by a Turkish school management application.

## Encryption Algorithm (Reverse Engineered from program.exe.hex)

The encryption function `yazi_sifrele` was reverse-engineered by disassembling the Delphi binary reconstructed from `program.exe.hex`. It works as follows:

1. **Key preparation**: The encryption key is base64-encoded to form the initial keystream seed.
2. **Non-resetting MD5**: The binary contains a custom `TMD5` class whose `HashAsBytes` method is **destructive** — it applies MD5 padding and length data directly to the live hash state, permanently altering it. This means each `HashAsBytes` call changes the context for subsequent `Update`/`HashAsBytes` calls.
3. **Block processing**: Data is processed in 16-byte blocks:
   - `MD5.Update(current_key_bytes)` then `hash = MD5.HashAsBytes()`
   - Each byte undergoes two bit-manipulation transforms (selected by the upper and lower hex digits of the corresponding MD5 hash byte) followed by XOR with that hash byte
   - The uppercase hex representation of the 16 hash bytes becomes the key for the next block
4. **Bit manipulations**: 16 XOR/swap operations (selected by lower hex digit) + 16 ROL/ROR/NOT/bit-swap operations (selected by upper hex digit)

## Three Encryption Keys

Each bilgi field uses a different encryption key (discovered from the binary's string table):

| Field  | Encryption Key    | Purpose                              |
|--------|-------------------|--------------------------------------|
| bilgi1 | `Aymm+bd0813`    | MD5(base64(school_info))             |
| bilgi2 | `MBD+MOAE+AY81`  | MD5(base64(password))                |
| bilgi3 | `mfl86+mfl86`    | MD5(md5_password + md5_school)       |

## Decrypted Data from codes.txt

### AYARLAR (Settings)

| Key     | Base64 Value            | Decoded (cp1254)        |
|---------|-------------------------|-------------------------|
| il      | `3VNUQU5CVUw=`          | İSTANBUL                |
| ilce    | `QkVZS09a`              | BEYKOZ                  |
| okuladi | `TlVOIE9LVUxMQVJJ`     | NUN OKULLARI            |
| sinif   | `R2lyaW5peg==`          | Giriniz                 |
| kurulum | `SEFZSVI=`              | HAYIR                   |
| vbs     | 240                     | 240                     |

### BILGI Section (Fully Decrypted)

**bilgi1** (school info verification):
- Encrypted: `J54RF4l6xZD9xvq0CcOqbMs9V+EIFOZsVM4T1nFeUCrlvF1tUEVHLCS8KY4O9g6STcVa1u66LiSGrWzu1o4UiA==`
- Decrypted: `0205d217e6f563551457b59cb45ad56a`
- Equals: `MD5(base64("İSTANBUL BEYKOZ NUN OKULLARI", cp1254))` ✓

**bilgi2** (encrypted password):
- Encrypted: `xCyc658XRSNRIQxnX8Y+DKOk9c5wrLZE8OZKIjKMQl2urieCjq3PjbZMIb8aalX9CjHV2b07Lbf/8MTbFQSuIQ==`
- Decrypted: `a9a5e5ab9b5b9ec84b8f05527a4b6cd6`
- Equals: `MD5(base64(password))` — the MD5 hash of the base64-encoded password

**bilgi3** (cross-check):
- Encrypted: `63xMbz1FJwz3T9nafDQCks1vdL+DjbiXkyyk5kPD8jY4zLBILdmiyNxcqe5NfD4iM6AHlfLhYEj45mwpTA/KGA==`
- Decrypted: `ae345105e28ff6c1aad7f944167b8537`
- Equals: `MD5("a9a5e5ab9b5b9ec84b8f05527a4b6cd6" + "0205d217e6f563551457b59cb45ad56a")` ✓

## Encrypted Password

The encrypted password recovered from `codes.txt` bilgi2 is:

```
a9a5e5ab9b5b9ec84b8f05527a4b6cd6
```

This is `MD5(base64(password))` — the MD5 hash of the base64-encoded password string (9–16 characters). All three bilgi fields cross-validate, confirming the decryption is correct.

## Recovered Password

The plaintext password is:

```
qaz123wsx
```

Verification chain:
- `base64("qaz123wsx")` = `cWF6MTIzd3N4`
- `MD5("cWF6MTIzd3N4")` = `a9a5e5ab9b5b9ec84b8f05527a4b6cd6` ✓

The password `qaz123wsx` is a common keyboard pattern: columns **q-a-z**, **1-2-3**, **w-s-x** on a QWERTY keyboard.

## Validation

The complete algorithm was implemented in `decrypt.py` using the non-resetting MD5 and bit transforms extracted from the hex file. It was verified against all 12 examples in `examples.txt` for:
- bilgi2 encryption and decryption (round-trip)
- bilgi3 cross-validation (`MD5(md5_password + md5_school)`)
- bilgi1 school info verification
