#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/stat.h>
#include <stdbool.h>
#include "suffix_tree.h"
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <unistd.h> // Para getpass

#define MIN_MATCH_LEN 8
#define SALT_SIZE 16
#define KEY_SIZE 32 // AES-256
#define IV_SIZE 16  // AES block size
#define MAP_VERSION 2

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

int encrypt_file(const char* filepath) {
    char *password = getpass("Insert the password to encrypt the map file. ");
    if (!password || strlen(password) == 0) { fprintf(stderr, "\nEmpty password. Encripyting failed.\n"); return -1; }
    FILE* in_file = fopen(filepath, "rb");
    if (!in_file) { perror("Was not possible to re-open the map file."); return -1; }
    fseek(in_file, 0, SEEK_END);
    long plaintext_len = ftell(in_file);
    fseek(in_file, 0, SEEK_SET);
    unsigned char* plaintext = malloc(plaintext_len);
    if (!plaintext) { perror("Error allocating memory."); fclose(in_file); return -1; }
    fread(plaintext, 1, plaintext_len, in_file);
    fclose(in_file);
    unsigned char salt[SALT_SIZE];
    if (RAND_bytes(salt, sizeof(salt)) != 1) { free(plaintext); return -1; }
    unsigned char key[KEY_SIZE], iv[IV_SIZE], derived_bytes[KEY_SIZE + IV_SIZE];
    if (PKCS5_PBKDF2_HMAC(password, strlen(password), salt, sizeof(salt), 4096, EVP_sha256(), sizeof(derived_bytes), derived_bytes) == 0) { free(plaintext); return -1; }
    memcpy(key, derived_bytes, sizeof(key));
    memcpy(iv, derived_bytes + sizeof(key), sizeof(iv));
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
    int ciphertext_len;
    unsigned char* ciphertext = malloc(plaintext_len + IV_SIZE);
    int len;
    EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len);
    ciphertext_len = len;
    EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);
    ciphertext_len += len;
    EVP_CIPHER_CTX_free(ctx);
    free(plaintext);
    FILE* out_file = fopen(filepath, "wb");
    if (!out_file) { free(ciphertext); return -1; }
    fwrite("LIDECENC", 1, 8, out_file);
    fwrite(salt, 1, sizeof(salt), out_file);
    fwrite(ciphertext, 1, ciphertext_len, out_file);
    fclose(out_file);
    free(ciphertext);
    printf("\nMap file '%s' sucessfully encrpyted.\n", filepath);
    return 0;
}

char* read_file_to_buffer(const char* filename, size_t* out_size) {
    struct stat statbuf;
    if (stat(filename, &statbuf) != 0 || !S_ISREG(statbuf.st_mode)) {
        return NULL; // isn't a regular file or stat fail
    }
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

int safe_find_longest_prefix_match(const char* carrier_data, size_t carrier_size, const char* secret_prefix, size_t max_len) {
    for (int len = max_len; len >= MIN_MATCH_LEN; len--) {
        if (find_pattern(carrier_data, carrier_size, secret_prefix, len) != NULL) return len;
    }
    return 0;
}

int calculate_sha256_raw(const char *filepath, unsigned char *output_hash) {
    struct stat statbuf;
    if (stat(filepath, &statbuf) != 0 || !S_ISREG(statbuf.st_mode)) return -1;
    FILE *file = fopen(filepath, "rb");
    if (!file) return -1;
    SHA256_CTX sha256_context;
    SHA256_Init(&sha256_context);
    const int bufSize = 4096;
    unsigned char buffer[bufSize];
    size_t bytesRead = 0;
    while ((bytesRead = fread(buffer, 1, bufSize, file))) {
        SHA256_Update(&sha256_context, buffer, bytesRead);
    }
    SHA256_Final(output_hash, &sha256_context);
    fclose(file);
    return 0;
}

void flush_literal_buffer(FILE* map_file, unsigned char* buffer, int* count) {
    if (*count > 0) {
        uint8_t control_byte = (uint8_t)(*count);
        fwrite(&control_byte, 1, 1, map_file);
        fwrite(buffer, 1, *count, map_file);
        *count = 0;
    }
}

int main(int argc, char* argv[]) {
    bool strict_mode = false;
    char** args = malloc(argc * sizeof(char*));
    int arg_count = 0;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--strict") == 0) strict_mode = true;
        else args[arg_count++] = argv[i];
    }

    if (arg_count < 2) { fprintf(stderr, "Use: %s [--strict] <secret_file> <carrier1> ...\n", argv[0]); free(args); return 1; }
    if (strict_mode) printf("--- Running strict mode ---\n");

    const char* secret_filename = args[0];
    const char* map_filename = "map.txt";
    size_t secret_size;
    char* secret_data = read_file_to_buffer(secret_filename, &secret_size);
    if (!secret_data) { perror("Wasn't possible to read the secret file"); free(args); return 1; }

    int num_carriers = arg_count - 1;
    if (num_carriers > 65535) { fprintf(stderr, "Error: Limit of 65535 rechean.\n"); return 1; }
    struct Carrier* carriers = malloc(num_carriers * sizeof(struct Carrier));

    printf("--- Loading and indexing carries files... ---\n");
    for (int i = 0; i < num_carriers; i++) {
        carriers[i].filename = args[i + 1];
        carriers[i].data = NULL;
        carriers[i].index.tree = NULL;
        carriers[i].engine = ENGINE_SAFE_SEARCH;

        if (strcmp(secret_filename, carriers[i].filename) == 0) continue;
        
        carriers[i].data = read_file_to_buffer(carriers[i].filename, &carriers[i].size);
        if (!carriers[i].data) {
            fprintf(stderr, "Warning: Wasn't possibel to read the %s file, will be ignored.\n", carriers[i].filename);
            continue;
        }
        
        printf("  - Loading: %s (%zu bytes)\n", carriers[i].filename, carriers[i].size);
        carriers[i].engine = ENGINE_SUFFIX_TREE; // Try to use the tree firts
        carriers[i].index.tree = st_create(carriers[i].data, carriers[i].size);
        if (!carriers[i].index.tree) {
            fprintf(stderr, "    Warning: Fail in the tree suffix (incompatible file?), using secure motor.\n");
            carriers[i].engine = ENGINE_SAFE_SEARCH;
        }
    }

    FILE* map_file = fopen(map_filename, "wb");
    uint16_t version = MAP_VERSION;
    fwrite("LIDECMAP", 1, 8, map_file);
    fwrite(&version, sizeof(uint16_t), 1, map_file);
    uint16_t num_carriers_u16 = (uint16_t)num_carriers;
    fwrite(&num_carriers_u16, sizeof(uint16_t), 1, map_file);

    for (int i = 0; i < num_carriers; i++) {
        unsigned char hash[SHA256_DIGEST_LENGTH];
        if (carriers[i].data && calculate_sha256_raw(carriers[i].filename, hash) == 0) {
            fwrite(hash, 1, SHA256_DIGEST_LENGTH, map_file);
        } else {
            memset(hash, 0, SHA256_DIGEST_LENGTH);
            fwrite(hash, 1, SHA256_DIGEST_LENGTH, map_file);
        }
    }

    printf("--- Initiating Hybrid Greedy Search ---\n");
    unsigned char literal_buffer[127];
    int literal_count = 0;
    long long total_bytes_processed = 0;

    for (size_t i = 0; i < secret_size; ) {
        const char* remaining_secret = secret_data + i;
        size_t remaining_len = secret_size - i;
        int best_match_len = 0;
        int best_carrier_index = -1;

        for (int j = 0; j < num_carriers; j++) {
            if (!carriers[j].data) continue;
            int current_match_len = 0;
            switch (carriers[j].engine) {
                case ENGINE_SUFFIX_TREE:
                    if (carriers[j].index.tree) current_match_len = st_find_longest_match(carriers[j].index.tree, remaining_secret, remaining_len);
                    break;
                case ENGINE_SAFE_SEARCH:
                    current_match_len = safe_find_longest_prefix_match(carriers[j].data, carriers[j].size, remaining_secret, remaining_len);
                    break;
            }
            if (current_match_len > best_match_len) { best_match_len = current_match_len; best_carrier_index = j; }
        }

        if (best_match_len >= MIN_MATCH_LEN) {
            flush_literal_buffer(map_file, literal_buffer, &literal_count);
            const char* found_ptr = find_pattern(carriers[best_carrier_index].data, carriers[best_carrier_index].size, remaining_secret, best_match_len);
            uint32_t offset = found_ptr - carriers[best_carrier_index].data;
            uint8_t control = 0x80;
            uint16_t carrier_idx_u16 = (uint16_t)best_carrier_index;
            uint16_t length16 = (uint16_t)best_match_len;
            fwrite(&control, 1, 1, map_file);
            fwrite(&carrier_idx_u16, sizeof(uint16_t), 1, map_file);
            fwrite(&offset, sizeof(uint32_t), 1, map_file);
            fwrite(&length16, sizeof(uint16_t), 1, map_file);
            i += best_match_len;
        } else {
            if (strict_mode) {
                fprintf(stderr, "\n\nFatal Error (Strict mode): Was not possible to find a correspondet byte for the position %zu.\n", i);
                fclose(map_file); remove(map_filename); free(secret_data);
                for (int k = 0; k < num_carriers; k++) {
                    if(carriers[k].data) { free(carriers[k].data); if(carriers[k].engine == ENGINE_SUFFIX_TREE && carriers[k].index.tree) st_free(carriers[k].index.tree); }
                }
                free(carriers); free(args);
                return EXIT_FAILURE;
            }
            literal_buffer[literal_count++] = remaining_secret[0];
            i++;
        }

        if (literal_count == 127) flush_literal_buffer(map_file, literal_buffer, &literal_count);
        if (i > total_bytes_processed) {
            total_bytes_processed = i;
            printf("\rProcessando: %.2f%%", (double)total_bytes_processed / secret_size * 100.0);
            fflush(stdout);
        }
    }

    flush_literal_buffer(map_file, literal_buffer, &literal_count);
    fclose(map_file);
    printf("\n--- Maping Process Finished ---\n");

    if (encrypt_file(map_filename) != 0) {
        fprintf(stderr, "Error encrypting the map file.\n");
    }

    free(secret_data);
    for (int i = 0; i < num_carriers; i++) {
        if(carriers[i].data) { free(carriers[i].data); if(carriers[i].engine == ENGINE_SUFFIX_TREE && carriers[i].index.tree) st_free(carriers[i].index.tree); }
    }
    free(carriers);
    free(args);

    return 0;
}
