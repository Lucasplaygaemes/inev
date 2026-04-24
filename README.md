# Inev

**Inev** is not just an encryption tool; it is a **data reconstruction engine**. It allows you to "hide" files by deconstructing them into a series of mathematical coordinates that point to data already existing in other files on your system (Videos, ISOs, Games, etc.).

The result is a **Map File** that contains zero bytes of your original secret, making it technically impossible to recover without both the **Map** AND the original **Carrier Files**.

---

### 1. High-Performance Mapping (Suffix Tree)
Inev uses a **Suffix Tree** algorithm (Ukkonen's based) to index carrier files in $O(N)$ time. 
*   **Greedy Match Logic:** For every byte of your secret, Inev finds the longest possible sequence present in your carriers.
*   **Data Pointer System:** Instead of storing your data, the map stores: `[Carrier_ID, Offset, Length]`.

### 2. Chameleon Multi-Secret System
You can map **multiple secrets** (e.g., a PDF, a ZIP, and a Key) into a **single map file**. 
*   **Selective Recovery:** If you only provide some of the carriers to the decoder, only the secrets that "belong" to those carriers will be reconstructed. The others remain invisible/corrupted.

### 3. Security Architecture
*   **Encryption:** AES-256-CBC.
*   **Key Derivation:** PBKDF2-HMAC-SHA256 with **600,000 iterations** and a unique salt.
*   **Compression:** The entire map is Zlib-compressed before encryption to minimize size and eliminate data patterns.
*   **Integrity:** The map stores SHA256 hashes of every carrier used, ensuring you never reconstruct using the wrong file version.

### 4. Robust Steganography Suite
Inev can hide its maps inside other files using two advanced methods:
*   **Append (Overlay):** Stealthily attaches the map to the end of any file (works for images, videos, executables).
*   **Robust Randomized LSB:** Hides data inside the Least Significant Bits of BMP images.
    *   **Xorshift32 PRNG:** Bits are not stored in order; they are scattered across the image based on a pseudo-random sequence generated from your **password**.
    *   **Tail-Noise Resistance:** A dedicated `Size Field` in the header prevents extraction errors caused by file-end garbage.

---

#Advanced Features & Flags

| Flag | Name | Description |
| :--- | :--- | :--- |
| `-s` | **Secret** | Path to the file you want to hide (supports multiple). |
| `-c` | **Carrier** | Path to the "source of patterns" (supports multiple). |
| `-x` | **Strict Mode** | **No-Literal Guarantee**. The process fails if it can't find matches for every byte. The map will contain 0% of your original data. |
| `-a` | **Analyze** | Compatibility check. Shows what % of your secret can be covered by the chosen carriers before you commit to a map. |
| `-H` | **Hunter** | **Multicore Search**. Scans a directory and ranks files by how well they match your secret (ordered by coverage %). |
| `-e` | **Append** | Embeds the map as a hidden overlay in a host file. |
| `-l` | **Robust LSB**| Scatters the map bits invisibly inside a BMP image using password-seeded randomization. |

---

## Practical Examples

### Scenario A: The Ghost Map (Strict Mode)
You want to hide a password list using a game ISO as a carrier. You want to ensure NO part of the passwords exists in the map file.
```bash
./encoder -s passwords.txt -c game_data.iso -x
```

### Scenario B: The Invisible Image (Robust LSB)
You want to hide a secret archive inside a family photo, scattered so well that even statistical analysis can't find it.
```bash
./encoder -s backup.zip -c movie.mp4 -l photo.bmp
```
*Inev will ask for a password. This password will both encrypt the data and decide the "scattering pattern" of the bits.*

### Scenario C: Finding the Best Carrier
You have a 1GB secret and don't know which file to use as a carrier.
```bash
./encoder -s big_secret.bin -H /home/user/Downloads/
```

---

## Installation

### Dependencies
- **OpenSSL** (`libssl-dev`)
- **Zlib** (`zlib1g-dev`)
- **GCC** & **Make**

### Compilation
```bash
make clean && make
```

---

## ⚖ Ethics & License
This tool was created for educational purposes regarding data reconstruction and steganography. Please refer to [**ETHICAL_LICENSE.md**](./ETHICAL_LICENSE.md) for usage terms.

**Author:** Lucas (lucasplaygaemes@gmail.com)
