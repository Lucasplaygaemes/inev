# Inev - The Chameleon Steganography & Mapping Tool

Inev is a high-performance mapping tool designed to "hide" secret files by reconstructing them using patterns found in other files (carriers). Unlike traditional encryption, Inev creates a "map" that points to coordinates in files you already have, making your data nearly invisible and deniable.

## How it works?
Inev uses a **Hybrid Greedy Search** powered by a **Suffix Tree** to find the longest possible matches between your secret and your carrier files.

1.  **Mapping:** It identifies sequences in carriers that match your secret.
2.  **Chameleon System:** Hide multiple secrets in one map. Each instruction is tagged to a specific file.
3.  **Zero-Knowledge (Strict Mode):** With the `-x` flag, the map contains **zero** bytes of your original data—only coordinates.
4.  **Global Compression:** The map is compressed with Zlib before encryption.
5.  **Hardened Security:** AES-256-CBC encryption with PBKDF2-HMAC-SHA256 derivation (**600,000 iterations**).

## Ethics
Read the [**ETHICAL_LICENSE.md**](./ETHICAL_LICENSE.md). For questions: lucasplaygaemes@gmail.com

---

## Installation & Compilation

### Dependencies
- OpenSSL (libssl-dev)
- Zlib (zlib1g-dev)

### Compiling
```bash
make
```

---

## How to Use

### 1. Encoding (Creating a Map)
The encoder uses flags for secrets (`-s`) and carriers (`-c`).

**Syntax:**
```bash
./encoder -s <secret1> [-s <secret2>] -c <carrier1> [-c <carrier2>] [-x]
```

**Flags:**
*   `-s`: Path to a secret file.
*   `-c`: Path to a carrier file.
*   `-x`: **Strict Mode**. The process fails if a match shorter than 16 bytes is found. This ensures the map contains **no literal data**, only pointers.

**Example (Advanced Chameleon):**
```bash
./encoder -s passwords.txt -s backup.zip -c movie.mp4 -c family_photo.jpg -x
```

### 2. Decoding (Recovering Files)
The decoder generates `recovered_0.bin`, `recovered_1.bin`, etc.

**Syntax:**
```bash
./decoder -m <map_file> -c <carrier1> [-c <carrier2>] ...
```

---

## Advanced Features

### Deniable Encryption & Selective Recovery
The Chameleon System allows for "Partial Recovery". If you create a map using two carriers (A and B) for two different secrets:
- Providing **Carrier A** to the decoder will recover **Secret A** perfectly.
- **Secret B** will be corrupted or empty because its "pieces" (stored in Carrier B) are missing.

This allows you to reveal only what you want, depending on which carriers you provide.

### Strict Mode (-x) for Maximum Privacy
Without `-x`, Inev saves "literal bytes" for patterns it can't find in carriers. While these are encrypted, they still exist in the map. **With `-x`**, Inev is forced to find everything in the carriers. If it can't, it fails. This guarantees that your map is purely a set of coordinates, containing no traces of your original file's content.

### Performance Tip
Use large, high-entropy files as carriers (Video files, ISOs, or Game assets) to increase the chance of long matches and smaller maps.
