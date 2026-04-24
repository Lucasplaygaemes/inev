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
#include <dirent.h>
#include <sys/types.h>
#include <pthread.h>

#define MIN_MATCH_LEN 8
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

pthread_mutex_t ranking_mutex = PTHREAD_MUTEX_INITIALIZER;
char file_queue[5000][1024];
int queue_size = 0, queu_current = 0;
pthread_mutex_t queue_mutex = PTHREAD_MUTEX_INITIALIZER;
bool hunting_finished = false;

struct Carrier { const char* filename; char* data; size_t size; union { SuffixTree* tree; } index; };
typedef struct { char *data; size_t size; const char *filename; } Secret;
typedef struct { char filename[1024]; double coverage; double avg_match; } HuntResult;

HuntResult top_results[5];

char* read_file_to_buffer(const char* filename, size_t* out_size);
void update_ranking(const char *name, double cov, double avg);
const char* entry_name_only(const char* path);

#ifdef _WIN32
#include <conio.h>
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

void *hunt_worker(void *arg) {
    Secret *secret = (Secret*)arg;
    char current_file[1024];
    while (true) {
        pthread_mutex_lock(&queue_mutex); 
        if (queu_current >= queue_size) {
            pthread_mutex_unlock(&queue_mutex);
            if (hunting_finished) break;
            usleep(10000); continue;
        }
        strncpy(current_file, file_queue[queu_current++], 1023);
        int current_idx = queu_current;
        pthread_mutex_unlock(&queue_mutex);
        size_t c_size; char *c_data = read_file_to_buffer(current_file, &c_size);
        if (!c_data) continue;
        size_t analyze_size = (c_size > 5 * 1024 * 1024) ? 5 * 1024 * 1024 : c_size;
        SuffixTree *tree = st_create(c_data, analyze_size);
        if (tree) {
            long total_matched = 0, match_count = 0;
            size_t sample = (secret->size > 1024 * 1024) ? 1024 * 1024 : secret->size;
            for (size_t i = 0; i < sample;) {
                int len = st_find_longest_match(tree, secret->data + i, sample - i);
                if (len >= MIN_MATCH_LEN) { total_matched += len; match_count++; i += len; } else i++;
            }
            pthread_mutex_lock(&ranking_mutex);
            update_ranking(current_file, (double)total_matched/sample*100, (double)total_matched/(match_count?match_count:1));
            printf("\r[Hunter] Best: %.2f%% | Files: %d | Current: %s", top_results[0].coverage, current_idx, entry_name_only(current_file));
            fflush(stdout); pthread_mutex_unlock(&ranking_mutex);
            st_free(tree);
        }
        free(c_data);
    }
    return NULL;
}

const char* entry_name_only(const char* path) { const char* s = strrchr(path, '/'); return s ? s + 1 : path; }
void update_ranking(const char *name, double cov, double avg) {
    for (int i = 0; i < 5; i++) {
        if (cov > top_results[i].coverage) {
            for (int j = 4; j > i; j--) top_results[j] = top_results[j-1];
            strncpy(top_results[i].filename, name, 1023); top_results[i].coverage = cov; top_results[i].avg_match = avg;
            break;
        }
    }
}

void hunt_recursive(const char *path, Secret *secret) {
    DIR *dir = opendir(path); if (!dir) return;
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_name[0] == '.') continue;
        char full[1024]; snprintf(full, 1024, "%s/%s", path, entry->d_name);
        struct stat st;
        if (stat(full, &st) == 0) {
            if (S_ISDIR(st.st_mode)) hunt_recursive(full, secret);
            else if (S_ISREG(st.st_mode)) {
                pthread_mutex_lock(&queue_mutex);
                if (queue_size < 5000) strncpy(file_queue[queue_size++], full, 1023);
                pthread_mutex_unlock(&queue_mutex);
            }
        }
    }
    closedir(dir);
}

int encrypt_file(const char* filepath, const char* pass) {
    FILE* in = fopen(filepath, "rb"); if (!in) return -1;
    fseek(in, 0, SEEK_END); long raw_len = ftell(in); rewind(in);
    unsigned char* raw = malloc(raw_len); fread(raw, 1, raw_len, in); fclose(in);
    uLongf c_len = compressBound(raw_len); unsigned char *c_data = malloc(c_len);
    compress(c_data, &c_len, raw, raw_len);
    int pt_len = (int)c_len + 4; unsigned char *pt = malloc(pt_len);
    uint32_t r32 = (uint32_t)raw_len; memcpy(pt, &r32, 4); memcpy(pt + 4, c_data, c_len);
    unsigned char salt[16]; RAND_bytes(salt, 16);
    unsigned char d[48]; PKCS5_PBKDF2_HMAC(pass, strlen(pass), salt, 16, 600000, EVP_sha256(), 48, d);
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, d, d + 32);
    unsigned char *ct = malloc(pt_len + 32); int len, ct_len;
    EVP_EncryptUpdate(ctx, ct, &len, pt, pt_len); ct_len = len;
    EVP_EncryptFinal_ex(ctx, ct + len, &len); ct_len += len;
    
    uint32_t total_encrypted_size = (uint32_t)(SALT_SIZE + ct_len);
    FILE *out = fopen(filepath, "wb"); 
    fwrite("LIDECENC", 1, 8, out); 
    fwrite(&total_encrypted_size, 4, 1, out);
    fwrite(salt, 1, 16, out); 
    fwrite(ct, 1, ct_len, out); 
    fclose(out);
    
    free(raw); free(c_data); free(pt); free(ct); EVP_CIPHER_CTX_free(ctx);
    printf("Map file '%s' encrypted successfully.\n", filepath); return 0;
}

void embed_append(const char* host, const char* map) {
    char out_path[1024]; const char* dot = strrchr(host, '.');
    if (dot) { size_t l = dot - host; memcpy(out_path, host, l); sprintf(out_path + l, "_stego%s", dot); }
    else sprintf(out_path, "%s_stego", host);
    FILE *fh = fopen(host, "rb"), *fm = fopen(map, "rb"), *fo = fopen(out_path, "wb");
    if (!fh || !fm || !fo) return;
    unsigned char b[65536]; size_t n;
    while ((n = fread(b, 1, 65536, fh)) > 0) fwrite(b, 1, n, fo);
    while ((n = fread(b, 1, 65536, fm)) > 0) fwrite(b, 1, n, fo);
    fclose(fh); fclose(fm); fclose(fo);
    printf("[Stego] Map appended: %s\n", out_path);
}

void embed_lsb_robust(const char* host_path, const char* map_path, const char* pass) {
    size_t h_sz, m_sz;
    unsigned char *h = (unsigned char*)read_file_to_buffer(host_path, &h_sz);
    unsigned char *m = (unsigned char*)read_file_to_buffer(map_path, &m_sz);
    if (!h || !m) return;
    uint32_t off = (h[0]=='B' && h[1]=='M') ? *(uint32_t*)(h+10) : 0;
    size_t avail = h_sz - off;
    if (avail < m_sz * 8) { fprintf(stderr, "[LSB] Error: Host too small.\n"); return; }
    uint32_t seed = 0; unsigned char hash[32];
    PKCS5_PBKDF2_HMAC(pass, strlen(pass), (unsigned char*)"INEV_SEED", 9, 1000, EVP_sha256(), 32, hash);
    memcpy(&seed, hash, 4); if (seed == 0) seed = 1;
    uint32_t *idx = malloc(avail * sizeof(uint32_t));
    for (uint32_t i = 0; i < avail; i++) idx[i] = i;
    for (uint32_t i = avail - 1; i > 0; i--) {
        uint32_t j = xorshift32(&seed) % (i + 1);
        uint32_t t = idx[i]; idx[i] = idx[j]; idx[j] = t;
    }
    for (size_t i = 0; i < m_sz; i++) {
        for (int b = 0; b < 8; b++) {
            size_t p = off + idx[i * 8 + b];
            h[p] = (h[p] & 0xFE) | ((m[i] >> (7 - b)) & 0x01);
        }
    }
    char out_path[1024]; const char* dot = strrchr(host_path, '.');
    if (dot) { size_t l = dot - host_path; memcpy(out_path, host_path, l); sprintf(out_path + l, "_stego%s", dot); }
    else sprintf(out_path, "%s_stego.bmp", host_path);
    FILE* fo = fopen(out_path, "wb"); fwrite(h, 1, h_sz, fo); fclose(fo);
    printf("[LSB] Map hidden robustly: %s\n", out_path);
    free(h); free(m); free(idx);
}

char* read_file_to_buffer(const char* f, size_t* s) {
    struct stat st; if (stat(f, &st) != 0) return NULL;
    *s = st.st_size; FILE* fp = fopen(f, "rb"); if (!fp) return NULL;
    char* b = malloc(*s); fread(b, 1, *s, fp); fclose(fp); return b;
}

const char* find_pattern(const char* t, size_t tl, const char* p, size_t pl) {
    for (size_t i = 0; i <= tl - pl; i++) if (memcmp(t + i, p, pl) == 0) return t + i;
    return NULL;
}

int calculate_sha256_raw(const char *f, unsigned char *h) {
    FILE *fp = fopen(f, "rb"); if (!fp) return -1;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new(); EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    unsigned char b[4096]; size_t n;
    while ((n = fread(b, 1, 4096, fp))) EVP_DigestUpdate(ctx, b, n);
    EVP_DigestFinal_ex(ctx, h, NULL); EVP_MD_CTX_free(ctx); fclose(fp); return 0;
}

void flush_literal(FILE* f, unsigned char* b, int* c, uint16_t sid) {
    if (*c > 0) {
        int r = *c; unsigned char *p = b;
        while (r > 0) {
            int ch = (r > 127) ? 127 : r; uint8_t ctrl = (uint8_t)ch;
            fwrite(&sid, 2, 1, f); fwrite(&ctrl, 1, 1, f); fwrite(p, 1, ch, f);
            p += ch; r -= ch;
        }
        *c = 0;
    }
}

int main(int argc, char* argv[]) {
    Secret secrets[100]; int num_s = 0, num_c = 0, opt;
    const char *carrier_names[100], *stego_append = NULL, *stego_lsb = NULL, *hunt_path = ".";
    bool strict_mode = false, analyze_mode = false, hunt_mode = false;
    
    while ((opt = getopt(argc, argv, "s:c:xaH:e:l:")) != -1) {
        switch (opt) {
            case 's':
                while (optind-1 < argc && argv[optind-1][0] != '-') {
                    size_t sz; char *d = read_file_to_buffer(argv[optind-1], &sz);
                    if (d) { secrets[num_s].data = d; secrets[num_s].size = sz; secrets[num_s].filename = argv[optind-1]; num_s++; }
                    optind++;
                }
                optind--; break;
            case 'c':
                while (optind-1 < argc && argv[optind-1][0] != '-') {
                    if (num_c < 100) carrier_names[num_c++] = argv[optind-1];
                    optind++;
                }
                optind--; break;
            case 'x': strict_mode = true; break;
            case 'a': analyze_mode = true; break;
            case 'H': hunt_mode = true; hunt_path = optarg; break;
            case 'e': stego_append = optarg; break;
            case 'l': stego_lsb = optarg; break;
        }
    }

    if (num_s == 0 && !hunt_mode) {
        fprintf(stderr, "Usage: %s -s <secret> [-c <carrier>] [-x] [-a] [-H <path>] [-e <host>] [-l <host>]\n", argv[0]);
        return 1;
    }

    if (hunt_mode) {
        if (num_s == 0) { fprintf(stderr, "Error: Hunt mode requires a secret (-s).\n"); return 1; }
        printf("\n--- INEV MULTICORE HUNTER ---\nSecret: %s\n", secrets[0].filename);
        int cores = sysconf(_SC_NPROCESSORS_ONLN);
        pthread_t w[cores];
        for (int i = 0; i < cores; i++) pthread_create(&w[i], NULL, hunt_worker, &secrets[0]);
        hunt_recursive(hunt_path, &secrets[0]);
        hunting_finished = true;
        for (int i = 0; i < cores; i++) pthread_join(w[i], NULL);
        return 0;
    }

    struct Carrier* carriers = malloc(num_c * sizeof(struct Carrier));
    for (int i = 0; i < num_c; i++) {
        carriers[i].filename = carrier_names[i];
        carriers[i].data = read_file_to_buffer(carriers[i].filename, &carriers[i].size);
        if (carriers[i].data) carriers[i].index.tree = st_create(carriers[i].data, carriers[i].size);
    }
    
    FILE* map_f = fopen("map.txt", "wb");
    uint16_t v = MAP_VERSION, nc = num_c, ns = num_s;
    fwrite("LIDECMAP", 1, 8, map_f); fwrite(&v, 2, 1, map_f); fwrite(&nc, 2, 1, map_f);
    for (int i = 0; i < num_c; i++) { unsigned char h[32]; calculate_sha256_raw(carriers[i].filename, h); fwrite(h, 1, 32, map_f); }
    fwrite(&ns, 2, 1, map_f);
    
    unsigned char libuf[16384]; int licount = 0;
    for (int s = 0; s < num_s; s++) {
        printf("Processing Secret [%d]: %s\n", s, secrets[s].filename);
        for (size_t i = 0; i < secrets[s].size; ) {
            int blen = 0, bidx = -1;
            for (int j = 0; j < num_c; j++) {
                int clen = st_find_longest_match(carriers[j].index.tree, secrets[s].data + i, secrets[s].size - i);
                if (clen > blen) { blen = clen; bidx = j; }
            }
            if (blen >= MIN_MATCH_LEN) {
                flush_literal(map_f, libuf, &licount, s);
                const char* ptr = find_pattern(carriers[bidx].data, carriers[bidx].size, secrets[s].data + i, blen);
                uint32_t off = (uint32_t)(ptr - carriers[bidx].data);
                uint16_t sid = s, cid = bidx, len16 = blen; uint8_t ctrl = 0x80;
                fwrite(&sid, 2, 1, map_f); fwrite(&ctrl, 1, 1, map_f); fwrite(&cid, 2, 1, map_f); fwrite(&off, 4, 1, map_f); fwrite(&len16, 2, 1, map_f);
                i += blen;
            } else { 
                if (strict_mode) {
                    fprintf(stderr, "\nSTRICT MODE ERROR: No match found for byte at offset %zu in secret %d. Aborting.\n", i, s);
                    fclose(map_f); remove("map.txt"); return 1;
                }
                libuf[licount++] = secrets[s].data[i++]; 
                if (licount == 16384) flush_literal(map_f, libuf, &licount, s); 
            }
            
            if (i % 1024 == 0 || i == secrets[s].size) {
                printf("\rProgress: %.2f%%", (double)i / secrets[s].size * 100.0);
                fflush(stdout);
            }
        }
        flush_literal(map_f, libuf, &licount, s);
        printf("\n");
    }
    fclose(map_f); 
    char *pass = getpass("Enter password for map encryption: ");
    encrypt_file("map.txt", pass);
    if (stego_append) embed_append(stego_append, "map.txt");
    if (stego_lsb) embed_lsb_robust(stego_lsb, "map.txt", pass);
    return 0;
}
