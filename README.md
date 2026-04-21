# Inev - The Chameleon Steganography & Mapping Tool

Inev is a high-performance mapping tool designed to "hide" secret files by reconstructing them using patterns found in other files (carriers). Instead of traditional encryption that results in high-entropy random data, Inev creates a "map" that points to offsets in common files you already have.

## How it works?
Inev uses a **Hybrid Greedy Search** powered by a **Suffix Tree** to find the longest possible matches between your secret file and your "carrier" files (images, videos, ISOs, etc.). 

1. **Mapping:** It identifies sequences in the carriers that match your secret.
2. **Chameleon System:** You can hide multiple secrets in a single map. Each instruction is tagged with a Secret ID.
3. **Global Compression:** The resulting map is compressed using Zlib before encryption, making it extremely compact.
4. **Security:** The map is encrypted with AES-256-CBC, and the key is derived using PBKDF2-HMAC-SHA256 with **600,000 iterations**, making it highly resistant to brute-force attacks.

## Ethics
Read the [**ETHICAL_LICENSE.md**](./ETHICAL_LICENSE.md) to see the Ethical License of Inev. For questions, contact: lucasplaygaemes@gmail.com

---

## Installation & Compilation

### Dependencies
You need OpenSSL and Zlib installed on your system.
- Ubuntu/Debian: `sudo apt install libssl-dev zlib1g-dev`
- Fedora: `sudo dnf install openssl-devel zlib-devel`

### Compiling
Use the provided Makefile for the easiest setup:
```bash
make
```
To clean build files:
```bash
make clean
```

---

## How to Use

### 1. Encoding (Creating a Map)
The encoder now uses flags for maximum flexibility. You can specify multiple secrets and multiple carriers.

**Syntax:**
```bash
./encoder -s <secret_file1> [-s <secret_file2>] -c <carrier1> [-c <carrier2>] ...
```

**Example (Single Secret, Single Carrier):**
```bash
./encoder -s my_passwords.txt -c movie.mp4
```

**Example (Chameleon Mode - Multiple Secrets):**
```bash
./encoder -s secret1.pdf -s secret2.jpg -c backup_iso.iso -c family_video.mkv
```

### 2. Decoding (Recovering Files)
The decoder reads the map and uses the provided carriers to reconstruct the original files. It automatically generates files named `recovered_0.bin`, `recovered_1.bin`, etc.

**Syntax:**
```bash
./decoder -m <map_file> -c <carrier1> [-c <carrier2>] ...
```

**Example:**
```bash
./decoder -m map.txt -c movie.mp4
```

---

## Advanced Features

### Deniable Encryption (Chameleon)
Since the map is globally compressed and encrypted, an attacker cannot know how many secrets are hidden inside the map without the correct password and the specific carriers used for each secret.

### Performance Tip
For best results (smaller maps), use large carriers that might contain varied data, such as video files, compiled binaries, or system logs. The higher the similarity between carriers and secrets, the smaller your encrypted map will be.
