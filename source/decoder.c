#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/stat.h>
#include <unistd.h> // Para getopt e getpass
#include <stdbool.h> 
#include <openssl/sha.h>
#include <openssl/evp.h>

#define SALT_SIZE 16
#define KEY_SIZE 32 // AES-256
#define IV_SIZE 16  // AES block size
#define MAP_VERSION 2

// --- Funcoes Auxiliares ---

unsigned char* decrypt_map_to_memory(const char* filepath, long* out_map_size) {
    char *password = getpass("Digite a senha para descriptografar o mapa: ");
    if (!password || strlen(password) == 0) {
        fprintf(stderr, "\nSenha vazia. Descriptografia cancelada.\n");
        return NULL;
    }

    FILE* in_file = fopen(filepath, "rb");
    if (!in_file) { perror("Nao foi possivel abrir o arquivo de mapa"); return NULL; }

    char magic[8];
    if (fread(magic, 1, 8, in_file) != 8 || strncmp(magic, "LIDECENC", 8) != 0) {
        fprintf(stderr, "Erro: Arquivo de mapa invalido ou nao esta criptografado.\n");
        fclose(in_file);
        return NULL;
    }

    unsigned char salt[SALT_SIZE];
    if (fread(salt, 1, sizeof(salt), in_file) != sizeof(salt)) { fprintf(stderr, "Erro ao ler o sal do mapa.\n"); fclose(in_file); return NULL; }

    fseek(in_file, 0, SEEK_END);
    long file_size = ftell(in_file);
    long ciphertext_len = file_size - (sizeof(salt) + 8);
    if (ciphertext_len <= 0) { fprintf(stderr, "Erro: Mapa corrompido.\n"); fclose(in_file); return NULL; }
    fseek(in_file, sizeof(salt) + 8, SEEK_SET);

    unsigned char* ciphertext = malloc(ciphertext_len);
    if (!ciphertext) { perror("Erro de alocacao"); fclose(in_file); return NULL; }
    if (fread(ciphertext, 1, ciphertext_len, in_file) != ciphertext_len) { fprintf(stderr, "Erro ao ler mapa.\n"); fclose(in_file); free(ciphertext); return NULL; }
    fclose(in_file);

    unsigned char key[KEY_SIZE], iv[IV_SIZE], derived_bytes[KEY_SIZE + IV_SIZE];
    if (PKCS5_PBKDF2_HMAC(password, strlen(password), salt, sizeof(salt), 4096, EVP_sha256(), sizeof(derived_bytes), derived_bytes) == 0) { free(ciphertext); return NULL; }
    memcpy(key, derived_bytes, sizeof(key));
    memcpy(iv, derived_bytes + sizeof(key), sizeof(iv));

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);

    unsigned char* plaintext = malloc(ciphertext_len + IV_SIZE);
    if (!plaintext) { free(ciphertext); EVP_CIPHER_CTX_free(ctx); return NULL; }
    
    int len, plaintext_len = 0;

    if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len) != 1) { fprintf(stderr, "Erro: Falha ao descriptografar. Senha incorreta ou mapa corrompido.\n"); free(ciphertext); free(plaintext); EVP_CIPHER_CTX_free(ctx); return NULL; }
    plaintext_len = len;

    if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) != 1) { fprintf(stderr, "Erro: Falha ao finalizar descriptografia. Senha incorreta ou mapa corrompido.\n"); free(ciphertext); free(plaintext); EVP_CIPHER_CTX_free(ctx); return NULL; }
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    free(ciphertext);

    *out_map_size = plaintext_len;
    return plaintext;
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

// --- Funcao Principal ---

int main(int argc, char* argv[]) {
    const char* map_filename = NULL;
    const char* output_filename = "recovered_file.bin";
    int opt;

    while ((opt = getopt(argc, argv, "m:o:")) != -1) {
        switch (opt) {
            case 'm': map_filename = optarg; break;
            case 'o': output_filename = optarg; break;
            default: fprintf(stderr, "Uso: %s -m <map_file> [-o <output_file>] <carrier1> ...\n", argv[0]); return EXIT_FAILURE;
        }
    }

    if (map_filename == NULL || optind >= argc) {
        fprintf(stderr, "Uso: %s -m <map_file> [-o <output_file>] <carrier1> ...\n", argv[0]);
        return EXIT_FAILURE;
    }

    long map_size;
    unsigned char* map_data = decrypt_map_to_memory(map_filename, &map_size);
    if (!map_data) return EXIT_FAILURE;
    unsigned char* map_ptr = map_data;
    unsigned char* map_end = map_data + map_size;

    if ((map_ptr + 8) > map_end || strncmp((char*)map_ptr, "LIDECMAP", 8) != 0) { fprintf(stderr, "Erro: Arquivo de mapa invalido.\n"); free(map_data); return EXIT_FAILURE; }
    map_ptr += 8;

    if ((map_ptr + sizeof(uint16_t)) > map_end) { fprintf(stderr, "Erro: Mapa corrompido.\n"); free(map_data); return EXIT_FAILURE; }
    uint16_t version;
    memcpy(&version, map_ptr, sizeof(uint16_t)); map_ptr += sizeof(uint16_t);
    if (version != MAP_VERSION) { 
        fprintf(stderr, "Erro: Versao do mapa incompativel (mapa v%u, programa v%d).\n", version, MAP_VERSION);
        free(map_data); return EXIT_FAILURE; 
    }

    if ((map_ptr + sizeof(uint16_t)) > map_end) { fprintf(stderr, "Erro: Mapa corrompido.\n"); free(map_data); return EXIT_FAILURE; }
    uint16_t num_carriers_from_map;
    memcpy(&num_carriers_from_map, map_ptr, sizeof(uint16_t)); map_ptr += sizeof(uint16_t);
    if ((argc - optind) != num_carriers_from_map) {
        fprintf(stderr, "Erro: Arquivo de mapa ou arquivos transportadores invalidos.\n");
        free(map_data); return EXIT_FAILURE;
    }

    printf("--- Verificando arquivos transportadores... ---\n");
    unsigned char actual_hash[SHA256_DIGEST_LENGTH], zero_hash[SHA256_DIGEST_LENGTH];
    memset(zero_hash, 0, SHA256_DIGEST_LENGTH);

    for (int i = 0; i < num_carriers_from_map; i++) {
        if ((map_ptr + SHA256_DIGEST_LENGTH) > map_end) { fprintf(stderr, "Erro: Mapa corrompido.\n"); free(map_data); return EXIT_FAILURE; }
        unsigned char* expected_hash = map_ptr;
        map_ptr += SHA256_DIGEST_LENGTH;
        const char* carrier_filename = argv[optind + i];
        if (calculate_sha256_raw(carrier_filename, actual_hash) != 0) {
            if (memcmp(expected_hash, zero_hash, SHA256_DIGEST_LENGTH) != 0) {
                fprintf(stderr, "Erro: Arquivo de mapa ou arquivos transportadores invalidos.\n");
                free(map_data); return EXIT_FAILURE;
            }
            printf("  - OK (Ignorado): %s\n", carrier_filename);
        } else {
            if (memcmp(expected_hash, actual_hash, SHA256_DIGEST_LENGTH) != 0) {
                fprintf(stderr, "Erro: Arquivo de mapa ou arquivos transportadores invalidos.\n");
                free(map_data); return EXIT_FAILURE;
            }
            printf("  - OK: %s\n", carrier_filename);
        }
    }

    FILE* output_file = fopen(output_filename, "wb");
    if (!output_file) { perror("Erro ao criar arquivo de saida"); free(map_data); return EXIT_FAILURE; }

    FILE** carrier_files = malloc(num_carriers_from_map * sizeof(FILE*));
    for (int i = 0; i < num_carriers_from_map; i++) {
        struct stat statbuf;
        if (stat(argv[optind + i], &statbuf) == 0 && S_ISREG(statbuf.st_mode)) {
             carrier_files[i] = fopen(argv[optind + i], "rb");
        } else {
             carrier_files[i] = NULL;
        }
    }

    printf("--- Iniciando reconstrucao... ---\n");
    while (map_ptr < map_end) {
        uint8_t control_byte = *map_ptr++;
        if (control_byte & 0x80) { // Match
            if ((map_ptr + sizeof(uint16_t) + sizeof(uint32_t) + sizeof(uint16_t)) > map_end) { break; }
            uint16_t carrier_idx, length;
            uint32_t offset;
            memcpy(&carrier_idx, map_ptr, sizeof(uint16_t)); map_ptr += sizeof(uint16_t);
            memcpy(&offset, map_ptr, sizeof(uint32_t)); map_ptr += sizeof(uint32_t);
            memcpy(&length, map_ptr, sizeof(uint16_t)); map_ptr += sizeof(uint16_t);

            if (carrier_idx >= num_carriers_from_map || carrier_files[carrier_idx] == NULL) continue;
            
            FILE* carrier_file = carrier_files[carrier_idx];
            unsigned char* buffer = malloc(length);
            if (!buffer) break;

            fseek(carrier_file, offset, SEEK_SET);
            if (fread(buffer, 1, length, carrier_file) != length) { free(buffer); break; }
            fwrite(buffer, 1, length, output_file);
            free(buffer);

        } else { // Literal
            uint8_t literal_len = control_byte;
            if (literal_len == 0) continue;
            if ((map_ptr + literal_len) > map_end) break;
            fwrite(map_ptr, 1, literal_len, output_file);
            map_ptr += literal_len;
        }
    }

    printf("--- Arquivo reconstruido com sucesso como '%s' ---\n", output_filename);

    free(map_data);
    fclose(output_file);
    for (int i = 0; i < num_carriers_from_map; i++) {
        if (carrier_files[i]) fclose(carrier_files[i]);
    }
    free(carrier_files);

    return EXIT_SUCCESS;
}
