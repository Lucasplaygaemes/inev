#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdbool.h> 
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <zlib.h>

#ifdef _WIN32
#include <conio.h>
#else
#include <unistd.h>
#endif

#define SALT_SIZE 16
#define KEY_SIZE 32 
#define IV_SIZE 16  
#define MAP_VERSION 3

uint32_t xorshift32(uint32_t *state) {
    uint32_t x = *state;
    x ^= x << 13; x ^= x >> 17; x ^= x << 5;
    if (x == 0) x = 1;
    return (*state = x);
}

#ifdef _WIN32
char *getpass(const char *prompt) {
    static char password[128];
    int i = 0, ch;
    fprintf(stderr, "%s", prompt);
    while ((ch = _getch()) != '\r') {
        if (ch == '\b') { if (i > 0) i--; }
        else if (i < 127) password[i++] = (char)ch;
    }
    password[i] = '\0'; fprintf(stderr, "\n");
    return password;
}
#endif

unsigned char* extract_lsb_robust(const char* path, const char* pass, size_t* out_sz) {
    struct stat st; if (stat(path, &st) != 0) return NULL;
    FILE* f = fopen(path, "rb"); if (!f) return NULL;
    unsigned char* h = malloc(st.st_size); fread(h, 1, st.st_size, f); fclose(f);
    uint32_t off = (st.st_size > 54 && h[0]=='B' && h[1]=='M') ? *(uint32_t*)(h+10) : 0;
    size_t avail = st.st_size - off;
    if (avail < 100) { free(h); return NULL; }
    uint32_t seed = 0; unsigned char hash[32];
    PKCS5_PBKDF2_HMAC(pass, strlen(pass), (unsigned char*)"INEV_SEED", 9, 1000, EVP_sha256(), 32, hash);
    memcpy(&seed, hash, 4); if (seed == 0) seed = 1;
    uint32_t *idx = malloc(avail * sizeof(uint32_t));
    for (uint32_t i = 0; i < avail; i++) idx[i] = i;
    for (uint32_t i = avail - 1; i > 0; i--) {
        uint32_t j = xorshift32(&seed) % (i + 1);
        uint32_t tmp = idx[i]; idx[i] = idx[j]; idx[j] = tmp;
    }
    size_t m_sz = avail / 8;
    unsigned char* m = malloc(m_sz);
    for (size_t i = 0; i < m_sz; i++) {
        m[i] = 0;
        for (int b = 0; b < 8; b++) m[i] |= (h[off + idx[i*8 + b]] & 0x01) << (7-b);
    }
    free(h); free(idx); *out_sz = m_sz; return m;
}

unsigned char* process_decryption(unsigned char* data, size_t sz, const char* pass, long* out_map_size) {
    unsigned char *ptr = data, *end = data + sz;
    while (ptr <= (end - 12)) { if (memcmp(ptr, "LIDECENC", 8) == 0) break; ptr++; }
    if (ptr > end - 12) return NULL;
    ptr += 8;
    uint32_t encrypted_part_size; memcpy(&encrypted_part_size, ptr, 4); ptr += 4;
    
    unsigned char salt[SALT_SIZE]; memcpy(salt, ptr, SALT_SIZE); ptr += SALT_SIZE;
    unsigned char key[32], iv[16], derived[48];
    PKCS5_PBKDF2_HMAC(pass, strlen(pass), salt, SALT_SIZE, 600000, EVP_sha256(), 48, derived);
    memcpy(key, derived, 32); memcpy(iv, derived + 32, 16);
    
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
    int ct_len = encrypted_part_size - SALT_SIZE;
    unsigned char* pt = malloc(ct_len + 32);
    int len, total_pt = 0;
    if (EVP_DecryptUpdate(ctx, pt, &len, ptr, ct_len) != 1) { EVP_CIPHER_CTX_free(ctx); free(pt); return NULL; }
    total_pt = len;
    if (EVP_DecryptFinal_ex(ctx, pt + len, &len) != 1) { EVP_CIPHER_CTX_free(ctx); free(pt); return NULL; }
    total_pt += len;
    EVP_CIPHER_CTX_free(ctx);
    
    uint32_t orig_sz; memcpy(&orig_sz, pt, 4);
    unsigned char* final = malloc(orig_sz); uLongf d_len = orig_sz;
    if (uncompress(final, &d_len, pt + 4, total_pt - 4) != Z_OK) { free(final); free(pt); return NULL; }
    free(pt); *out_map_size = (long)orig_sz; return final;
}

int main(int argc, char* argv[]) {
    const char* map_filename = NULL; const char* carrier_names[100];
    int num_c = 0, opt;
    while ((opt = getopt(argc, argv, "m:c:")) != -1) {
        switch (opt) {
            case 'm': map_filename = optarg; break;
            case 'c': if (num_c < 100) carrier_names[num_c++] = optarg; break;
        }
    }
    if (!map_filename) { fprintf(stderr, "Usage: %s -m <map_file> -c <carrier1>...\n", argv[0]); return 1; }
    char *pass = getpass("Enter password: ");
    if (!pass || strlen(pass) == 0) return 1;
    struct stat st; if (stat(map_filename, &st) != 0) { perror("Stat failed"); return 1; }
    FILE *f = fopen(map_filename, "rb"); unsigned char *raw = malloc(st.st_size); fread(raw, 1, st.st_size, f); fclose(f);
    long m_sz; unsigned char* map_data = process_decryption(raw, st.st_size, pass, &m_sz);
    if (!map_data) {
        size_t l_sz; unsigned char* lsb = extract_lsb_robust(map_filename, pass, &l_sz);
        if (lsb) { map_data = process_decryption(lsb, l_sz, pass, &m_sz); free(lsb); }
    }
    free(raw);
    if (!map_data) { fprintf(stderr, "Error: Map decryption failed.\n"); return 1; }
    unsigned char *ptr = map_data;
    if (strncmp((char*)ptr, "LIDECMAP", 8) != 0) { fprintf(stderr, "Error: Invalid map.\n"); return 1; }
    ptr += 8;
    uint16_t ver, n_c, n_s;
    memcpy(&ver, ptr, 2); ptr += 2; memcpy(&n_c, ptr, 2); ptr += 2;
    FILE** c_f = malloc(n_c * sizeof(FILE*));
    for (int i = 0; i < n_c; i++) { ptr += 32; c_f[i] = (i < num_c) ? fopen(carrier_names[i], "rb") : NULL; }
    memcpy(&n_s, ptr, 2); ptr += 2;
    FILE** o_f = malloc(n_s * sizeof(FILE*));
    for (int i = 0; i < n_s; i++) { char n[64]; sprintf(n, "recovered_%d.bin", i); o_f[i] = fopen(n, "wb"); }
    printf("--- Reconstructing... ---\n");
    while (ptr < map_data + m_sz) {
        uint16_t sid; uint8_t ctrl; memcpy(&sid, ptr, 2); ptr += 2; ctrl = *ptr++;
        FILE* out = (sid < n_s) ? o_f[sid] : NULL;
        if (ctrl & 0x80) {
            uint16_t ci, len; uint32_t off; memcpy(&ci, ptr, 2); ptr += 2; memcpy(&off, ptr, 4); ptr += 4; memcpy(&len, ptr, 2); ptr += 2;
            if (out && ci < n_c && c_f[ci]) {
                unsigned char* b = malloc(len); fseek(c_f[ci], off, SEEK_SET);
                if (fread(b, 1, len, c_f[ci]) == len) fwrite(b, 1, len, out);
                free(b);
            }
        } else { if (out) fwrite(ptr, 1, ctrl, out); ptr += ctrl; }
    }
    printf("--- Done ---\n");
    free(map_data);
    for (int i = 0; i < n_s; i++) if (o_f[i]) fclose(o_f[i]);
    for (int i = 0; i < n_c; i++) if (c_f[i]) fclose(c_f[i]);
    return 0;
}
