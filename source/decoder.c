#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <unistd.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <zlib.h>
#include "format.h"
#ifdef _WIN32
#include <conio.h>
#else
#include <unistd.h>
#endif
/* ---------------- PRNG ---------------- */
uint32_t xorshift32(uint32_t *state) {
    uint32_t x = *state;
    x ^= x << 13; x ^= x >> 17; x ^= x << 5;
    if (x == 0) x = 1;
    return (*state = x);
}
/* ---------------- SHA-256 ---------------- */
int calculate_sha256_raw(const char *f, unsigned char *h) {
    FILE *fp = fopen(f, "rb");
    if (!fp) return -1;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) { fclose(fp); return -1; }
    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) {
        EVP_MD_CTX_free(ctx); fclose(fp); return -1;
    }
    unsigned char b[4096];
    size_t n;
    while ((n = fread(b, 1, sizeof b, fp)) > 0) EVP_DigestUpdate(ctx, b, n);
    EVP_DigestFinal_ex(ctx, h, NULL);
    EVP_MD_CTX_free(ctx);
    fclose(fp);
    return 0;
}
/* ---------------- getpass Windows ---------------- */
#ifdef _WIN32
char *getpass(const char *prompt) {
    static char password[128];
    int i = 0, ch;
    fprintf(stderr, "%s", prompt);
    while ((ch = _getch()) != '\r') {
        if (ch == '\b') { if (i > 0) i--; }
        else if (i < 127) password[i++] = (char)ch;
    }
    password[i] = '\0';
    fprintf(stderr, "\n");
    return password;
}
#endif
/* ---------------- Extração LSB ---------------- */
unsigned char* extract_lsb_robust(const char* path, const char* pass, size_t* out_sz) {
    struct stat st;
    if (stat(path, &st) != 0) return NULL;
    if (st.st_size < 54) return NULL;
    FILE* f = fopen(path, "rb");
    if (!f) return NULL;
    unsigned char* h = (unsigned char*)malloc((size_t)st.st_size);
    if (!h) { fclose(f); return NULL; }
    if (fread(h, 1, (size_t)st.st_size, f) != (size_t)st.st_size) {
        free(h); fclose(f); return NULL;
    }
    fclose(f);
    uint32_t off = (h[0]=='B' && h[1]=='M') ? get_u32le(h + 10) : 0;
    if ((size_t)off >= (size_t)st.st_size) { free(h); return NULL; }
    size_t avail = (size_t)st.st_size - off;
    if (avail < 100) { free(h); return NULL; }
    uint32_t seed = 0;
    unsigned char hash[32];
    if (PKCS5_PBKDF2_HMAC(pass, (int)strlen(pass),
                          (unsigned char*)"INEV_SEED", 9,
                          INEV_SEED_ITERS, EVP_sha256(), 32, hash) != 1) {
        free(h); return NULL;
    }
    seed = get_u32le(hash);
    if (seed == 0) seed = 1;
    uint32_t *idx = (uint32_t*)malloc(avail * sizeof(uint32_t));
    if (!idx) { free(h); return NULL; }
    for (uint32_t i = 0; i < avail; i++) idx[i] = i;
    for (uint32_t i = (uint32_t)avail - 1; i > 0; i--) {
        uint32_t j = xorshift32(&seed) % (i + 1);
        uint32_t tmp = idx[i]; idx[i] = idx[j]; idx[j] = tmp;
    }
    size_t m_sz = avail / 8;
    unsigned char* m = (unsigned char*)malloc(m_sz ? m_sz : 1);
    if (!m) { free(h); free(idx); return NULL; }
    for (size_t i = 0; i < m_sz; i++) {
        m[i] = 0;
        for (int b = 0; b < 8; b++)
            m[i] |= (unsigned char)((h[off + idx[i*8 + b]] & 0x01) << (7 - b));
    }
    free(h); free(idx);
    *out_sz = m_sz;
    return m;
}
/* ---------------- Decifração (AES-256-GCM) ---------------- */
/* Retorna mapa em claro (malloc'd) ou NULL. Nunca distingue o motivo
 * da falha para não vazar oracle. */
unsigned char* process_decryption(const unsigned char* data, size_t sz,
                                  const char* pass, long* out_map_size) {
    if (!data || sz < INEV_ENC_MAGIC_LEN + 4) return NULL;
    const unsigned char *ptr = data;
    const unsigned char *end = data + sz;
    /* Procura magic */
    while ((size_t)(end - ptr) >= INEV_ENC_MAGIC_LEN) {
        if (memcmp(ptr, INEV_ENC_MAGIC, INEV_ENC_MAGIC_LEN) == 0) break;
        ptr++;
    }
    if ((size_t)(end - ptr) < INEV_ENC_MAGIC_LEN + 4) return NULL;
    ptr += INEV_ENC_MAGIC_LEN;
    uint32_t enc_size = get_u32le(ptr);
    ptr += 4;
    if (enc_size < INEV_MIN_ENC_OVERHEAD) return NULL;
    if ((size_t)(end - ptr) < (size_t)enc_size) return NULL;
    const unsigned char* salt = ptr; ptr += INEV_SALT_SIZE;
    const unsigned char* nonce = ptr; ptr += INEV_NONCE_SIZE;
    size_t ct_len = (size_t)enc_size - INEV_SALT_SIZE - INEV_NONCE_SIZE - INEV_TAG_SIZE;
    const unsigned char* ct = ptr;
    const unsigned char* tag = ptr + ct_len;
    unsigned char d[INEV_KEY_SIZE + INEV_IV_SIZE];
    if (PKCS5_PBKDF2_HMAC(pass, (int)strlen(pass), salt, INEV_SALT_SIZE,
                          INEV_PBKDF2_ITERS, EVP_sha256(), sizeof d, d) != 1) {
        return NULL;
    }
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) { inev_secure_zero(d, sizeof d); return NULL; }
    unsigned char* pt = (unsigned char*)malloc(ct_len + 32);
    if (!pt) { EVP_CIPHER_CTX_free(ctx); inev_secure_zero(d, sizeof d); return NULL; }
    int len = 0, total_pt = 0, ok = 1;
    ok &= EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    ok &= EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, INEV_NONCE_SIZE, NULL);
    ok &= EVP_DecryptInit_ex(ctx, NULL, NULL, d, nonce);
    ok &= EVP_DecryptUpdate(ctx, pt, &len, ct, (int)ct_len);
    total_pt = len;
    ok &= EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, INEV_TAG_SIZE, (void*)tag);
    ok &= EVP_DecryptFinal_ex(ctx, pt + total_pt, &len);
    EVP_CIPHER_CTX_free(ctx);
    inev_secure_zero(d, sizeof d);
    if (!ok) { free(pt); return NULL; }
    total_pt += len;
    if (total_pt < 4) { free(pt); return NULL; }
    uint32_t orig_sz = get_u32le(pt);
    if (orig_sz == 0 || (uint64_t)orig_sz > INEV_MAX_MAP_SIZE) { free(pt); return NULL; }
    unsigned char* final = (unsigned char*)malloc(orig_sz);
    if (!final) { free(pt); return NULL; }
    uLongf d_len = orig_sz;
    if (uncompress(final, &d_len, pt + 4, (uLong)(total_pt - 4)) != Z_OK || d_len != orig_sz) {
        free(final); free(pt); return NULL;
    }
    free(pt);
    *out_map_size = (long)orig_sz;
    return final;
}
/* ---------------- main ---------------- */
int main(int argc, char* argv[]) {
    const char* map_filename = NULL;
    const char* carrier_names[INEV_MAX_CARRIERS] = {0};
    int num_c = 0, opt;
    while ((opt = getopt(argc, argv, "m:c:")) != -1) {
        switch (opt) {
            case 'm': map_filename = optarg; break;
            case 'c':
                if (num_c < INEV_MAX_CARRIERS)
                    carrier_names[num_c++] = optarg;
                break;
        }
    }
    if (!map_filename) {
        fprintf(stderr, "Usage: %s -m <map_file> -c <carrier1>...\n", argv[0]);
        return 1;
    }
    char *pass = getpass("Enter password: ");
    if (!pass || strlen(pass) == 0) return 1;
    struct stat st;
    if (stat(map_filename, &st) != 0 || st.st_size <= 0) {
        perror("Stat failed");
        return 1;
    }
    FILE *f = fopen(map_filename, "rb");
    if (!f) { perror("fopen"); return 1; }
    unsigned char *raw = (unsigned char*)malloc((size_t)st.st_size);
    if (!raw) { fclose(f); return 1; }
    if (fread(raw, 1, (size_t)st.st_size, f) != (size_t)st.st_size) {
        free(raw); fclose(f); return 1;
    }
    fclose(f);
    long m_sz = 0;
    unsigned char* map_data = process_decryption(raw, (size_t)st.st_size, pass, &m_sz);
    free(raw);
    if (!map_data) {
        size_t l_sz = 0;
        unsigned char* lsb = extract_lsb_robust(map_filename, pass, &l_sz);
        if (lsb) {
            map_data = process_decryption(lsb, l_sz, pass, &m_sz);
            free(lsb);
        }
    }
    if (!map_data) {
        fprintf(stderr, "Error: Map decryption failed.\n");
        return 1;
    }
    /* --- Parse do mapa --- */
    const unsigned char *ptr = map_data;
    const unsigned char *end = map_data + m_sz;
    if ((size_t)(end - ptr) < INEV_MAP_MAGIC_LEN + 4) {
        fprintf(stderr, "Error: Invalid map.\n");
        free(map_data); return 1;
    }
    if (memcmp(ptr, INEV_MAP_MAGIC, INEV_MAP_MAGIC_LEN) != 0) {
        fprintf(stderr, "Error: Invalid map.\n");
        free(map_data); return 1;
    }
    ptr += INEV_MAP_MAGIC_LEN;
    uint16_t ver = get_u16le(ptr); ptr += 2;
    if (ver != INEV_MAP_VERSION) {
        fprintf(stderr, "Error: Unsupported map version %u (expected %u).\n",
                ver, INEV_MAP_VERSION);
        free(map_data); return 1;
    }
    uint16_t n_c = get_u16le(ptr); ptr += 2;
    uint16_t n_s = 0;
    /* Verifica se há espaço para os hashes + n_s */
    if ((size_t)(end - ptr) < (size_t)n_c * 32 + 2) {
        fprintf(stderr, "Error: Truncated map.\n");
        free(map_data); return 1;
    }
    FILE** c_f = (FILE**)calloc(n_c ? n_c : 1, sizeof(FILE*));
    if (!c_f) { free(map_data); return 1; }
    for (int i = 0; i < n_c; i++) {
        unsigned char expected_hash[32];
        memcpy(expected_hash, ptr, 32);
        ptr += 32;
        if (i < num_c) {
            unsigned char actual_hash[32];
            if (calculate_sha256_raw(carrier_names[i], actual_hash) == 0) {
                if (memcmp(expected_hash, actual_hash, 32) != 0) {
                    fprintf(stderr,
                            "[Warning] Carrier SHA-256 mismatch for '%s'! "
                            "Reconstructed file may be corrupted.\n",
                            carrier_names[i]);
                } else {
                    printf("[Carrier %d] SHA-256 verified: %s\n", i, carrier_names[i]);
                }
            }
            c_f[i] = fopen(carrier_names[i], "rb");
        } else {
            fprintf(stderr, "Error: Carrier %d missing from command line arguments.\n", i);
            c_f[i] = NULL;
        }
    }
    n_s = get_u16le(ptr); ptr += 2;
    FILE** o_f = (FILE**)calloc(n_s ? n_s : 1, sizeof(FILE*));
    if (!o_f) {
        for (int i = 0; i < n_c; i++) if (c_f[i]) fclose(c_f[i]);
        free(c_f); free(map_data);
        return 1;
    }
    for (int i = 0; i < n_s; i++) {
        char name[64];
        snprintf(name, sizeof name, "recovered_%d.bin", i);
        o_f[i] = fopen(name, "wb");
    }
    printf("--- Reconstructing... ---\n");
    while (ptr < end) {
        if ((size_t)(end - ptr) < 3) { fprintf(stderr, "Error: Truncated record.\n"); break; }
        uint16_t sid = get_u16le(ptr); ptr += 2;
        uint8_t ctrl = *ptr++;
        FILE* out = (sid < n_s) ? o_f[sid] : NULL;
        if (ctrl & 0x80) {
            if ((size_t)(end - ptr) < 8) { fprintf(stderr, "Error: Truncated match.\n"); break; }
            uint16_t ci  = get_u16le(ptr); ptr += 2;
            uint32_t off = get_u32le(ptr); ptr += 4;
            uint16_t len = get_u16le(ptr); ptr += 2;
            if (out && ci < n_c && c_f[ci] && len > 0) {
                unsigned char* b = (unsigned char*)malloc(len);
                if (b) {
                    if (fseek(c_f[ci], (long)off, SEEK_SET) == 0 &&
                        fread(b, 1, len, c_f[ci]) == len) {
                        fwrite(b, 1, len, out);
                    }
                    free(b);
                }
            }
        } else {
            if ((size_t)(end - ptr) < ctrl) { fprintf(stderr, "Error: Truncated literal.\n"); break; }
            if (out && ctrl > 0) fwrite(ptr, 1, ctrl, out);
            ptr += ctrl;
        }
    }
    printf("--- Done ---\n");
    for (int i = 0; i < n_s; i++) if (o_f[i]) fclose(o_f[i]);
    for (int i = 0; i < n_c; i++) if (c_f[i]) fclose(c_f[i]);
    free(o_f); free(c_f);
    free(map_data);
    return 0;
}

