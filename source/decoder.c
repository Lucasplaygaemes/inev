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
#define KEY_SIZE 32 // AES-256
#define IV_SIZE 16  // AES block size
#define MAP_VERSION 3

#ifdef _WIN32
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
    if (PKCS5_PBKDF2_HMAC(password, strlen(password), salt, sizeof(salt), 600000, EVP_sha256(), sizeof(derived_bytes), derived_bytes) == 0) { free(ciphertext); return NULL; }
    memcpy(key, derived_bytes, sizeof(key));
    memcpy(iv, derived_bytes + sizeof(key), sizeof(iv));

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);

    unsigned char* plaintext = malloc(ciphertext_len + IV_SIZE);
    if (!plaintext) { free(ciphertext); EVP_CIPHER_CTX_free(ctx); return NULL; }
    
    int len, plaintext_len = 0;
    if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len) != 1) { 
        fprintf(stderr, "Erro: Falha ao descriptografar.\n"); 
        free(ciphertext); free(plaintext); EVP_CIPHER_CTX_free(ctx); return NULL; 
    }
    plaintext_len = len;

    if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) != 1) { 
        fprintf(stderr, "Erro: Senha incorreta ou mapa corrompido.\n"); 
        free(ciphertext); free(plaintext); EVP_CIPHER_CTX_free(ctx); return NULL; 
    }
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    free(ciphertext);

    if (plaintext_len < (int)sizeof(uint32_t)) { free(plaintext); return NULL; }
    uint32_t original_size;
    memcpy(&original_size, plaintext, sizeof(uint32_t));
    
    unsigned char *compressed_ptr = plaintext + sizeof(uint32_t);
    int compressed_size = plaintext_len - sizeof(uint32_t);
    
    unsigned char *final_map = malloc(original_size);
    uLongf dest_len = original_size;
    if (uncompress(final_map, &dest_len, compressed_ptr, compressed_size) != Z_OK) {
        fprintf(stderr, "Erro ao descompactar o mapa.\n");
        free(final_map); free(plaintext);
        return NULL;
    }
    
    free(plaintext);
    *out_map_size = (long)original_size;
    return final_map;
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

int main(int argc, char* argv[]) {
    const char* map_filename = NULL;
    const char* carrier_names[100];
    int num_c_args = 0;
    int opt;

    while ((opt = getopt(argc, argv, "m:c:")) != -1) {
        switch (opt) {
            case 'm': map_filename = optarg; break;
            case 'c': if (num_c_args < 100) carrier_names[num_c_args++] = optarg; break;
            default: fprintf(stderr, "Uso: %s -m <map_file> -c <carrier1> [-c <carrier2>] ...\n", argv[0]); return EXIT_FAILURE;
        }
    }

    if (map_filename == NULL) {
        fprintf(stderr, "Uso: %s -m <map_file> -c <carrier1> [-c <carrier2>] ...\n", argv[0]);
        return EXIT_FAILURE;
    }

    long map_size;
    unsigned char* map_data = decrypt_map_to_memory(map_filename, &map_size);
    if (!map_data) return EXIT_FAILURE;
    unsigned char* map_ptr = map_data;
    unsigned char* map_end = map_data + map_size;

    if ((map_ptr + 8) > map_end || strncmp((char*)map_ptr, "LIDECMAP", 8) != 0) { fprintf(stderr, "Erro: Arquivo de mapa invalido.\n"); free(map_data); return EXIT_FAILURE; }
    map_ptr += 8;

    uint16_t version;
    memcpy(&version, map_ptr, 2); map_ptr += 2;
    if (version != MAP_VERSION) { 
        fprintf(stderr, "Erro: Versao do mapa incompativel (mapa v%u, programa v%d).\n", version, MAP_VERSION);
        free(map_data); return EXIT_FAILURE; 
    }

    uint16_t num_carriers_from_map;
    memcpy(&num_carriers_from_map, map_ptr, 2); map_ptr += 2;

    FILE** carrier_files = malloc(num_carriers_from_map * sizeof(FILE*));
    for (int i = 0; i < num_carriers_from_map; i++) {
        map_ptr += SHA256_DIGEST_LENGTH; // Pula hashes por simplicidade
        carrier_files[i] = (i < num_c_args) ? fopen(carrier_names[i], "rb") : NULL;
    }

    uint16_t num_secrets_from_map;
    memcpy(&num_secrets_from_map, map_ptr, 2); map_ptr += 2;

    FILE** output_files = malloc(num_secrets_from_map * sizeof(FILE*));
    for (int i = 0; i < num_secrets_from_map; i++) {
        char out_name[64];
        sprintf(out_name, "recovered_%d.bin", i);
        output_files[i] = fopen(out_name, "wb");
    }

    printf("--- Iniciando reconstrucao Camaleao... ---\n");
    while (map_ptr < map_end) {
        uint16_t sid;
        memcpy(&sid, map_ptr, 2); map_ptr += 2;
        uint8_t control_byte = *map_ptr++;
        
        FILE* out = (sid < num_secrets_from_map) ? output_files[sid] : NULL;

        if (control_byte & 0x80) { // Match
            uint16_t carrier_idx, length;
            uint32_t offset;
            memcpy(&carrier_idx, map_ptr, 2); map_ptr += 2;
            memcpy(&offset, map_ptr, 4); map_ptr += 4;
            memcpy(&length, map_ptr, 2); map_ptr += 2;

            if (out && carrier_idx < num_carriers_from_map && carrier_files[carrier_idx]) {
                unsigned char* buffer = malloc(length);
                fseek(carrier_files[carrier_idx], offset, SEEK_SET);
                if (fread(buffer, 1, length, carrier_files[carrier_idx]) == length) {
                    fwrite(buffer, 1, length, out);
                }
                free(buffer);
            }
        } else { // Literal
            uint8_t literal_len = control_byte;
            if (out) fwrite(map_ptr, 1, literal_len, out);
            map_ptr += literal_len;
        }
    }

    printf("--- Reconstrucao finalizada. Arquivos salvos como recovered_X.bin ---\n");

    free(map_data);
    for (int i = 0; i < num_secrets_from_map; i++) if (output_files[i]) fclose(output_files[i]);
    for (int i = 0; i < num_carriers_from_map; i++) if (carrier_files[i]) fclose(carrier_files[i]);
    free(output_files);
    free(carrier_files);

    return EXIT_SUCCESS;
}
