# ATAKA Binary Analysis - Findings

## Overview

The repository contains a hex-encoded Windows PE binary (`program.exe.hex`) and encrypted data files (`codes.txt`, `examples.txt`). The binary implements a custom encryption scheme used by a Turkish school management application.

## Encryption Algorithm (Reverse Engineered from program.exe.hex)

The encryption function `yazi_sifrele` was reverse-engineered by disassembling the Delphi binary reconstructed from `program.exe.hex`. It works as follows:

1. **Key preparation**: The encryption key (`MBD+MOAE+AY81`) is base64-encoded → `TUJEK01PQUUrQVk4MQ==`
2. **Non-resetting MD5**: The binary contains a custom `TMD5` class whose `HashAsBytes` method is **destructive** — it applies MD5 padding and length data directly to the live hash state, permanently altering it. This means each `HashAsBytes` call changes the context for subsequent `Update`/`HashAsBytes` calls.
3. **Block processing**: Data is processed in 16-byte blocks:
   - `MD5.Update(current_key_bytes)` then `hash = MD5.HashAsBytes()`
   - Each byte undergoes two bit-manipulation transforms (selected by the upper and lower hex digits of the corresponding MD5 hash byte) followed by XOR with that hash byte
   - The uppercase hex representation of the 16 hash bytes becomes the key for the next block
4. **Bit manipulations**: 16 XOR/swap operations (selected by lower hex digit) + 16 ROL/ROR/NOT/bit-swap operations (selected by upper hex digit)

## Decrypted Data from codes.txt

- **AYARLAR** (Settings):
  - il (province) = İSTANBUL
  - ilce (district) = BEYKOZ
  - okuladi (school) = NUN OKULLARI
  - sinif (class) = Giriniz
  - kurulum (setup) = HAYIR
  - vbs = 240

- **bilgi2** (Password field): Encrypted with key `MBD+MOAE+AY81`
  - Decrypted content: `a9a5e5ab9b5b9ec84b8f05527a4b6cd6`
  - This is **MD5(base64(password))** — the MD5 hash of the base64-encoded password

## Password Hash

The password hash recovered from `codes.txt` bilgi2 is:

```
a9a5e5ab9b5b9ec84b8f05527a4b6cd6
```

This equals `MD5(base64_encode(password))`.

The full algorithm was implemented in `decrypt.py` using the non-resetting MD5 and bit transforms extracted from the hex file, and verified against all 12 examples in `examples.txt`.
