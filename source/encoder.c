#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>
#include <stdint.h>
#include <sys/stat.h>
#include <stdbool.h>
#include <unistd.h>
#include "suffix_tree.h"
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#define MIN_MATCH_LEN 16
#define SALT_SIZE 16
#define KEY_SIZE 32 // AES-256
#define IV_SIZE 16  // AES block size
#define MAP_VERSION 3

enum EngineType {
    ENGINE_SUFFIX_TREE,
    ENGINE_SAFE_SEARCH
};

struct Carrier {
    const char* filename;
    char* data;
    size_t size;
    enum EngineType engine;
    union {
        SuffixTree* tree;
    } index;
};

typedef struct {
    char *data;
    size_t size;
    const char *filename;
} Secret;

#ifdef _WIN32
#include <conio.h>
char *getpass(const char *prompt) {
    static char password[128];
    int i = 0;
    int ch;
    fprintf(stderr, "%s", prompt);
    while ((ch = _getch()) != '\r') {
        if (ch == '\b') {
            if (i > 0) i--;
        } else if (i < (int)sizeof(password) - 1) {
            password[i++] = (char)ch;
        }
    }
    password[i] = '\0';
    fprintf(stderr, "\n");
    return password;
}
#endif

int encrypt_file(const char* filepath) {
    char *password = getpass("Insert the password to encrypt the map file. ");
    if (!password || strlen(password) == 0) { fprintf(stderr, "\nEmpty password. Encrypting failed.\n"); return -1; }
    
    FILE* in_file = fopen(filepath, "rb");
    if (!in_file) { perror("Was not possible to re-open the map file."); return -1; }
    fseek(in_file, 0, SEEK_END);
    long raw_len = ftell(in_file);
    fseek(in_file, 0, SEEK_SET);
    
    unsigned char* raw_data = malloc(raw_len);
    if (!raw_data) { perror("Error allocating memory."); fclose(in_file); return -1; }
    fread(raw_data, 1, raw_len, in_file);
    fclose(in_file);
    
    uLongf compressed_len = compressBound(raw_len);
    unsigned char * compressed_data = malloc(compressed_len);
    if (compress(compressed_data, &compressed_len, raw_data, raw_len) != Z_OK) {
        free(raw_data); free(compressed_data); return -1;
    }
    
    int plaintext_len = (int)compressed_len + sizeof(uint32_t);
    unsigned char *plaintext = malloc(plaintext_len);
    uint32_t u32_raw_len = (uint32_t)raw_len;
    memcpy(plaintext, &u32_raw_len, sizeof(uint32_t));
    memcpy(plaintext + sizeof(uint32_t), compressed_data, compressed_len);
    
    unsigned char salt[SALT_SIZE];
    RAND_bytes(salt, sizeof(salt));
    unsigned char key[KEY_SIZE], iv[IV_SIZE], derived_byte[KEY_SIZE + IV_SIZE];
    
    PKCS5_PBKDF2_HMAC(password, strlen(password), salt, sizeof(salt), 600000, EVP_sha256(), sizeof(derived_byte), derived_byte);
    memcpy(key, derived_byte, sizeof(key));
    memcpy(iv, derived_byte + sizeof(key), sizeof(iv));
    
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
    
    unsigned char *ciphertext = malloc(plaintext_len + IV_SIZE);
    int len, ciphertext_len = 0;
    EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len);
    ciphertext_len = len;
    EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);
    ciphertext_len += len;
    
    FILE *out_file = fopen(filepath, "wb");
    fwrite("LIDECENC", 1, 8, out_file);
    fwrite(salt, 1, sizeof(salt), out_file);
    fwrite(ciphertext, 1, ciphertext_len, out_file);
    fclose(out_file);
    
    free(raw_data); free(compressed_data); free(plaintext); free(ciphertext);
    EVP_CIPHER_CTX_free(ctx);
    printf("\nMap file '%s' successfully encrypted.\n", filepath);
    return 0;
}

char* read_file_to_buffer(const char* filename, size_t* out_size) {
    struct stat statbuf;
    if (stat(filename, &statbuf) != 0 || !S_ISREG(statbuf.st_mode)) return NULL;
    *out_size = statbuf.st_size;
    FILE* file = fopen(filename, "rb");
    if (!file) return NULL;
    char* buffer = (char*)malloc(*out_size);
    if (!buffer) { fclose(file); return NULL; }
    if (fread(buffer, 1, *out_size, file) != *out_size) {
        free(buffer); fclose(file); return NULL;
    }
    fclose(file);
    return buffer;
}

const char* find_pattern(const char* text, size_t text_len, const char* pattern, size_t pattern_len) {
    if (pattern_len == 0 || pattern_len > text_len) return NULL;
    for (size_t i = 0; i <= text_len - pattern_len; i++) {
        if (memcmp(text + i, pattern, pattern_len) == 0) return text + i;
    }
    return NULL;
}

int calculate_sha256_raw(const char *filepath, unsigned char *output_hash) {
    struct stat statbuf;
    if (stat(filepath, &statbuf) != 0 || !S_ISREG(statbuf.st_mode)) return -1;
    FILE *file = fopen(filepath, "rb");
    if (!file) return -1;
    
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    const EVP_MD *md = EVP_sha256();
    EVP_DigestInit_ex(mdctx, md, NULL);
    
    const int bufSize = 4096;
    unsigned char buffer[bufSize];
    size_t bytesRead = 0;
    while ((bytesRead = fread(buffer, 1, bufSize, file))) {
        EVP_DigestUpdate(mdctx, buffer, bytesRead);
    }
    unsigned int md_len;
    EVP_DigestFinal_ex(mdctx, output_hash, &md_len);
    EVP_MD_CTX_free(mdctx);
    fclose(file);
    return 0;
}

void flush_literal_buffer(FILE* map_file, unsigned char* buffer, int* count, uint16_t secret_id) {
    if (*count > 0) {
        int remaining = *count;
        unsigned char *ptr = buffer;
        while (remaining > 0) {
            int chunk = (remaining > 127) ? 127 : remaining;
            uint8_t control_byte = (uint8_t)chunk;
            uint16_t sid = secret_id;
            fwrite(&sid, sizeof(uint16_t), 1, map_file);
            fwrite(&control_byte, 1, 1, map_file);
            fwrite(ptr, 1, chunk, map_file);
            ptr += chunk;
            remaining -= chunk;
        }
        *count = 0;
    }
}

int main(int argc, char* argv[]) {
    Secret secrets[100];
    int num_secrets = 0;
    const char *carrier_names[100];
    int num_carriers = 0;
    bool strict_mode = false;
    int opt;
    
    while ((opt = getopt(argc, argv, "s:c:x")) != -1) {
        switch (opt) {
            case 's':
                if (num_secrets < 100) {
                    size_t sz;
                    char *d = read_file_to_buffer(optarg, &sz);
                    if (d) {
                        secrets[num_secrets].data = d;
                        secrets[num_secrets].size = sz;
                        secrets[num_secrets].filename = optarg;
                        num_secrets++;
                    }
                }
                break;
            case 'c':
                if (num_carriers < 100) {
                    carrier_names[num_carriers++] = optarg;
                }
                break;
            case 'x':
                strict_mode = true;
                break;
        }
    }

    if (num_secrets == 0 || num_carriers == 0) {
        fprintf(stderr, "Use: %s -s <secret1> [-s <secret2>] -c <carrier1> [-c <carrier2>] [-x]\n", argv[0]);
        fprintf(stderr, "Flags:\n  -s: Secret file\n  -c: Carrier file\n  -x: Strict mode (fails if no match found)\n");
        return 1;
    }

    if (strict_mode) printf("--- Running in STRICT mode ---\n");

    struct Carrier* carriers = malloc(num_carriers * sizeof(struct Carrier));
    for (int i = 0; i < num_carriers; i++) {
        carriers[i].filename = carrier_names[i];
        carriers[i].data = read_file_to_buffer(carriers[i].filename, &carriers[i].size);
        if (!carriers[i].data) {
            fprintf(stderr, "Warning: Failed to read carrier %s\n", carriers[i].filename);
            carriers[i].index.tree = NULL;
            continue;
        }
        carriers[i].engine = ENGINE_SUFFIX_TREE;
        carriers[i].index.tree = st_create(carriers[i].data, carriers[i].size);
    }
    
    const char *map_filename = "map.txt";
    FILE* map_file = fopen(map_filename, "wb");
    
    uint16_t version = MAP_VERSION;
    fwrite("LIDECMAP", 1, 8, map_file);
    fwrite(&version, sizeof(uint16_t), 1, map_file);
    
    uint16_t n_c16 = (uint16_t)num_carriers;
    fwrite(&n_c16, sizeof(uint16_t), 1, map_file);
    for (int i = 0; i < num_carriers; i++) {
        unsigned char hash[SHA256_DIGEST_LENGTH];
        calculate_sha256_raw(carriers[i].filename, hash);
        fwrite(hash, 1, SHA256_DIGEST_LENGTH, map_file);
    }
    
    uint16_t n_s16 = (uint16_t)num_secrets;
    fwrite(&n_s16, sizeof(uint16_t), 1, map_file);
    
    unsigned char literal_buffer[16384];
    int literal_count = 0;

    for (int s = 0; s < num_secrets; s++) {
        printf("Processing Secret [%d]: %s\n", s, secrets[s].filename);
        for (size_t i = 0; i < secrets[s].size; ) {
            const char* remaining_secret = secrets[s].data + i;
            size_t remaining_len = secrets[s].size - i;
            int best_match_len = 0;
            int best_carrier_index = -1;

            for (int j = 0; j < num_carriers; j++) {
                if (!carriers[j].data || !carriers[j].index.tree) continue;
                int current_match_len = st_find_longest_match(carriers[j].index.tree, remaining_secret, remaining_len);
                if (current_match_len > best_match_len) { 
                    best_match_len = current_match_len; 
                    best_carrier_index = j; 
                }
            }

            if (best_match_len >= MIN_MATCH_LEN) {
                flush_literal_buffer(map_file, literal_buffer, &literal_count, (uint16_t)s);
                const char* found_ptr = find_pattern(carriers[best_carrier_index].data, carriers[best_carrier_index].size, remaining_secret, best_match_len);
                uint32_t offset = (uint32_t)(found_ptr - carriers[best_carrier_index].data);
                
                uint16_t sid = (uint16_t)s;
                uint8_t control = 0x80;
                uint16_t c_idx = (uint16_t)best_carrier_index;
                uint16_t length16 = (uint16_t)best_match_len;

                fwrite(&sid, sizeof(uint16_t), 1, map_file);
                fwrite(&control, 1, 1, map_file);
                fwrite(&c_idx, sizeof(uint16_t), 1, map_file);
                fwrite(&offset, sizeof(uint32_t), 1, map_file);
                fwrite(&length16, sizeof(uint16_t), 1, map_file);
                i += best_match_len;
            } else {
                if (strict_mode) {
                    fprintf(stderr, "\nSTRICT MODE ERROR: No match for byte at position %zu in secret %d.\n", i, s);
                    fclose(map_file);
                    remove(map_filename);
                    return 1;
                }
                literal_buffer[literal_count++] = remaining_secret[0];
                i++;
                if (literal_count == 16384) flush_literal_buffer(map_file, literal_buffer, &literal_count, (uint16_t)s);
            }
            if (i % 1024 == 0 || i == secrets[s].size) {
                printf("\rProgress: %.2f%%", (double)i / secrets[s].size * 100.0);
                fflush(stdout);
            }
        }
        flush_literal_buffer(map_file, literal_buffer, &literal_count, (uint16_t)s);
    }

    fclose(map_file);
    printf("\n--- Mapping Process Finished ---\n");
    encrypt_file(map_filename);

    for (int i = 0; i < num_secrets; i++) free(secrets[i].data);
    for (int i = 0; i < num_carriers; i++) {
        if(carriers[i].data) { 
            free(carriers[i].data); 
            if(carriers[i].index.tree) st_free(carriers[i].index.tree); 
        }
    }
    free(carriers);
    return 0;
}
