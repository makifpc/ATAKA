# ATAKA Binary Analysis - Findings

## Overview

The repository contains a hex-encoded Windows PE binary (`program.hex`) and encrypted data files (`codes.txt`, `examples.txt`). The binary implements a custom encryption scheme used by a Turkish school management application.

## Encryption Algorithm (Reverse Engineered)

The encryption function `yazi_sifrele` works as follows:

1. **Key preparation**: The encryption key is base64-encoded
2. **MD5 hashing**: A custom MD5 implementation with **non-resetting** `HashAsBytes` (each call modifies internal state permanently)
3. **Block processing**: Data is processed in 16-byte blocks:
   - For each block, the current key is fed to MD5.Update(), then HashAsBytes() is called
   - Each byte undergoes two bit-manipulation transforms (selected by hex digits of the MD5 byte) then XOR with the MD5 byte
   - The hex representation of MD5 bytes becomes the key for the next block
4. **Bit manipulations**: 16 XOR/swap operations + 16 ROL/ROR/NOT/swap operations selected by MD5 byte hex digits

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

## Password

The password hash recovered from `codes.txt` bilgi2 is:

```
a9a5e5ab9b5b9ec84b8f05527a4b6cd6
```

This equals `MD5(base64_encode(password))`.

Verified against all 12 examples in `examples.txt` — the algorithm correctly decrypts every one.
