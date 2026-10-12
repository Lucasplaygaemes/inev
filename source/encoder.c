#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <dirent.h>
#include <pthread.h>
#include <zlib.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include "suffix_tree.h"
#include "format.h"
#define MIN_MATCH_LEN      8
#define CHUNK_SIZE         (8 * 1024 * 1024)
#define OVERLAP            (MIN_MATCH_LEN - 1)
#define LITERAL_BUF_SIZE   16384
typedef struct {
    uint16_t carrier_id;
    uint32_t carrier_offset;
    uint16_t length;
} MatchRecord;

// PRNG 
uint32_t xorshift32(uint32_t *state) {
    uint32_t x = *state;
    x ^= x << 13; x ^= x >> 17; x ^= x << 5;
    if (x == 0) x = 1;
    return (*state = x);
}

// Utilitary

char* read_file_to_buffer(const char* filename, size_t* out_size) {
    struct stat st;
    if (stat(filename, &st) != 0) return NULL;
    if (st.st_size < 0) return NULL;
    *out_size = (size_t)st.st_size;
    FILE* fp = fopen(filename, "rb");
    if (!fp) return NULL;
    size_t alloc = *out_size ? *out_size : 1;
    char* b = (char*)malloc(alloc);
    if (!b) { fclose(fp); return NULL; }
    if (*out_size) {
        size_t rd = fread(b, 1, *out_size, fp);
        if (rd != *out_size) { free(b); fclose(fp); return NULL; }
    }
    fclose(fp);
    return b;
}
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
    while ((n = fread(b, 1, sizeof b, fp)) > 0)
        EVP_DigestUpdate(ctx, b, n);
    EVP_DigestFinal_ex(ctx, h, NULL);
    EVP_MD_CTX_free(ctx);
    fclose(fp);
    return 0;
}

// getpass Windows 

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
    password[i] = '\0';
    fprintf(stderr, "\n");
    return password;
}
#endif

//  Hunter 

static atomic_bool hunting_finished = false;
static char file_queue[5000][1024];
static int queue_size = 0;
static int queu_current = 0;
static pthread_mutex_t queue_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t ranking_mutex = PTHREAD_MUTEX_INITIALIZER;
typedef struct { char *data; size_t size; const char *filename; } Secret;
typedef struct { char filename[1024]; double coverage; double avg_match; } HuntResult;
static HuntResult top_results[5];
const char* entry_name_only(const char* path) {
    const char* s = strrchr(path, '/');
    return s ? s + 1 : path;
}

void update_ranking(const char *name, double cov, double avg) {
    for (int i = 0; i < 5; i++) {
        if (cov > top_results[i].coverage) {
            for (int j = 4; j > i; j--) top_results[j] = top_results[j-1];
            strncpy(top_results[i].filename, name, sizeof(top_results[i].filename) - 1);
            top_results[i].filename[sizeof(top_results[i].filename) - 1] = '\0';
            top_results[i].coverage = cov;
            top_results[i].avg_match = avg;
            break;
        }
    }
}

void hunt_recursive(const char *path, Secret *secret) {
    DIR *dir = opendir(path);
    if (!dir) return;
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_name[0] == '.') continue;
        char full[1024];
        if (snprintf(full, sizeof full, "%s/%s", path, entry->d_name) >= (int)sizeof full)
            continue;
        struct stat st;
        if (stat(full, &st) == 0) {
            if (S_ISDIR(st.st_mode)) hunt_recursive(full, secret);
            else if (S_ISREG(st.st_mode)) {
                pthread_mutex_lock(&queue_mutex);
                if (queue_size < 5000) {
                    strncpy(file_queue[queue_size], full, 1023);
                    file_queue[queue_size][1023] = '\0';
                    queue_size++;
                }
                pthread_mutex_unlock(&queue_mutex);
            }
        }
    }
    closedir(dir);
}

void *hunt_worker(void *arg) {
    Secret *secret = (Secret*)arg;
    char current_file[1024];
    while (true) {
        pthread_mutex_lock(&queue_mutex);
        if (queu_current >= queue_size) {
            pthread_mutex_unlock(&queue_mutex);
            if (atomic_load(&hunting_finished)) break;
            usleep(10000);
            continue;
        }
        strncpy(current_file, file_queue[queu_current], sizeof(current_file) - 1);
        current_file[sizeof(current_file) - 1] = '\0';
        int current_idx = ++queu_current;
        pthread_mutex_unlock(&queue_mutex);
        size_t c_size = 0;
        char *c_data = read_file_to_buffer(current_file, &c_size);
        if (!c_data) continue;
        size_t analyze_size = (c_size > 5 * 1024 * 1024) ? 5 * 1024 * 1024 : c_size;
        SuffixTree *tree = st_create(c_data, analyze_size);
        if (tree) {
            long total_matched = 0, match_count = 0;
            size_t sample = (secret->size > 1024 * 1024) ? 1024 * 1024 : secret->size;
            for (size_t i = 0; i < sample; ) {
                int len = st_find_longest_match(tree, secret->data + i, sample - i);
                if (len >= MIN_MATCH_LEN) { total_matched += len; match_count++; i += (size_t)len; }
                else i++;
            }
            pthread_mutex_lock(&ranking_mutex);
            update_ranking(current_file,
                           (double)total_matched / (sample ? sample : 1) * 100.0,
                           (double)total_matched / (match_count ? match_count : 1));
            printf("\r[Hunter] Best: %.2f%% | Files: %d | Current: %s",
                   top_results[0].coverage, current_idx, entry_name_only(current_file));
            fflush(stdout);
            pthread_mutex_unlock(&ranking_mutex);
            st_free(tree);
        }
        free(c_data);
    }
    return NULL;
}


// Embedding (append) 


void embed_append(const char* host, const char* map) {
    char out_path[1024];
    const char* dot = strrchr(host, '.');
    if (dot) {
        size_t l = (size_t)(dot - host);
        if (l + 32 >= sizeof out_path) { fprintf(stderr, "[Append] Path too long.\n"); return; }
        memcpy(out_path, host, l);
        snprintf(out_path + l, sizeof(out_path) - l, "_stego%s", dot);
    } else {
        if (snprintf(out_path, sizeof out_path, "%s_stego", host) >= (int)sizeof out_path) {
            fprintf(stderr, "[Append] Path too long.\n"); return;
        }
    }
    FILE *fh = fopen(host, "rb");
    FILE *fm = fopen(map, "rb");
    FILE *fo = fopen(out_path, "wb");
    if (!fh || !fm || !fo) {
        if (fh) fclose(fh);
        if (fm) fclose(fm);
        if (fo) fclose(fo);
        fprintf(stderr, "[Append] Failed to open files.\n");
        return;
    }
    unsigned char b[65536];
    size_t n;
    int ok = 1;
    while ((n = fread(b, 1, sizeof b, fh)) > 0) {
        if (fwrite(b, 1, n, fo) != n) { ok = 0; break; }
    }
    if (ok) {
        while ((n = fread(b, 1, sizeof b, fm)) > 0) {
            if (fwrite(b, 1, n, fo) != n) { ok = 0; break; }
        }
    }
    fclose(fh); fclose(fm);
    if (fclose(fo) != 0) ok = 0;
    if (!ok) {
        fprintf(stderr, "[Append] I/O error, output may be corrupt.\n");
        remove(out_path);
        return;
    }
    printf("[Stego] Map appended: %s\n", out_path);
}


// Embedding (LSB) 


void embed_lsb_robust(const char* host_path, const char* map_path, const char* pass) {
    size_t h_sz = 0, m_sz = 0;
    unsigned char *h = (unsigned char*)read_file_to_buffer(host_path, &h_sz);
    unsigned char *m = (unsigned char*)read_file_to_buffer(map_path, &m_sz);
    if (!h || !m) { free(h); free(m); return; }
    if (h_sz < 54) { fprintf(stderr, "[LSB] Host too small.\n"); free(h); free(m); return; }
    uint32_t off = (h[0]=='B' && h[1]=='M') ? get_u32le(h + 10) : 0;
    if (off >= h_sz) { fprintf(stderr, "[LSB] Invalid BMP offset.\n"); free(h); free(m); return; }
    size_t avail = h_sz - off;
    if (avail < m_sz * 8) {
        fprintf(stderr, "[LSB] Error: Host too small (need %zu bits, have %zu).\n",
                m_sz * 8, avail);
        free(h); free(m); return;
    }
    uint32_t seed = 0;
    unsigned char hash[32];
    if (PKCS5_PBKDF2_HMAC(pass, (int)strlen(pass),
                          (unsigned char*)"INEV_SEED", 9,
                          INEV_SEED_ITERS, EVP_sha256(), 32, hash) != 1) {
        free(h); free(m); return;
    }
    seed = get_u32le(hash);
    if (seed == 0) seed = 1;
    uint32_t *idx = (uint32_t*)malloc(avail * sizeof(uint32_t));
    if (!idx) { free(h); free(m); return; }
    for (uint32_t i = 0; i < avail; i++) idx[i] = i;
    for (uint32_t i = (uint32_t)avail - 1; i > 0; i--) {
        uint32_t j = xorshift32(&seed) % (i + 1);
        uint32_t t = idx[i]; idx[i] = idx[j]; idx[j] = t;
    }
    for (size_t i = 0; i < m_sz; i++) {
        for (int b = 0; b < 8; b++) {
            size_t p = off + idx[i * 8 + b];
            h[p] = (h[p] & 0xFE) | ((m[i] >> (7 - b)) & 0x01);
        }
    }
    char out_path[1024];
    const char* dot = strrchr(host_path, '.');
    if (dot) {
        size_t l = (size_t)(dot - host_path);
        if (l + 32 >= sizeof out_path) { free(h); free(m); free(idx); return; }
        memcpy(out_path, host_path, l);
        snprintf(out_path + l, sizeof(out_path) - l, "_stego%s", dot);
    } else {
        if (snprintf(out_path, sizeof out_path, "%s_stego.bmp", host_path) >= (int)sizeof out_path) {
            free(h); free(m); free(idx); return;
        }
    }
    FILE* fo = fopen(out_path, "wb");
    if (!fo) { free(h); free(m); free(idx); return; }
    size_t wr = fwrite(h, 1, h_sz, fo);
    if (fclose(fo) != 0 || wr != h_sz) {
        fprintf(stderr, "[LSB] Write error.\n");
        remove(out_path);
    } else {
        printf("[LSB] Map hidden robustly: %s\n", out_path);
    }
    free(h); free(m); free(idx);
}



// encryption (AES-256-GCM)

int encrypt_file(const char* filepath, const char* pass) {
    FILE* in = fopen(filepath, "rb");
    if (!in) return -1;
    if (fseek(in, 0, SEEK_END) != 0) { fclose(in); return -1; }
    long raw_len = ftell(in);
    if (raw_len < 0) { fclose(in); return -1; }
    rewind(in);
    unsigned char* raw = (unsigned char*)malloc(raw_len ? (size_t)raw_len : 1);
    if (!raw) { fclose(in); return -1; }
    if (raw_len > 0 && fread(raw, 1, (size_t)raw_len, in) != (size_t)raw_len) {
        free(raw); fclose(in); return -1;
    }
    fclose(in);
    uLongf c_len = compressBound((uLong)raw_len);
    unsigned char *c_data = (unsigned char*)malloc(c_len ? c_len : 1);
    if (!c_data) { free(raw); return -1; }
    if (compress(c_data, &c_len, raw, (uLong)raw_len) != Z_OK) {
        free(raw); free(c_data); return -1;
    }
    free(raw);
    size_t pt_len = (size_t)c_len + 4;
    if (pt_len > UINT32_MAX) { free(c_data); return -1; }
    unsigned char *pt = (unsigned char*)malloc(pt_len);
    if (!pt) { free(c_data); return -1; }
    put_u32le(pt, (uint32_t)raw_len);
    memcpy(pt + 4, c_data, c_len);
    free(c_data);
    unsigned char salt[INEV_SALT_SIZE];
    unsigned char nonce[INEV_NONCE_SIZE];
    if (RAND_bytes(salt, sizeof salt) != 1) { free(pt); return -1; }
    if (RAND_bytes(nonce, sizeof nonce) != 1) { free(pt); return -1; }
    unsigned char d[INEV_KEY_SIZE + INEV_IV_SIZE];
    if (PKCS5_PBKDF2_HMAC(pass, (int)strlen(pass), salt, sizeof salt,
                          INEV_PBKDF2_ITERS, EVP_sha256(), sizeof d, d) != 1) {
        free(pt); return -1;
    }
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) { inev_secure_zero(d, sizeof d); free(pt); return -1; }
    unsigned char *ct = (unsigned char*)malloc(pt_len + INEV_TAG_SIZE);
    if (!ct) { EVP_CIPHER_CTX_free(ctx); inev_secure_zero(d, sizeof d); free(pt); return -1; }
    unsigned char tag[INEV_TAG_SIZE];
    int len = 0, ct_len = 0, ok = 1;
    ok &= EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    ok &= EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, INEV_NONCE_SIZE, NULL);
    ok &= EVP_EncryptInit_ex(ctx, NULL, NULL, d, nonce);
    ok &= EVP_EncryptUpdate(ctx, ct, &len, pt, (int)pt_len);
    ct_len = len;
    ok &= EVP_EncryptFinal_ex(ctx, ct + len, &len);
    ct_len += len;
    ok &= EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, INEV_TAG_SIZE, tag);
    EVP_CIPHER_CTX_free(ctx);
    inev_secure_zero(d, sizeof d);
    free(pt);
    if (!ok) { free(ct); return -1; }
    uint32_t total = (uint32_t)(INEV_SALT_SIZE + INEV_NONCE_SIZE + (size_t)ct_len + INEV_TAG_SIZE);
    /* Escrita atômica: tmp + rename */
    char tmp_path[1024];
    if (snprintf(tmp_path, sizeof tmp_path, "%s.tmp", filepath) >= (int)sizeof tmp_path) {
        free(ct); return -1;
    }
    FILE *out = fopen(tmp_path, "wb");
    if (!out) { free(ct); return -1; }
    unsigned char hdr[4];
    put_u32le(hdr, total);
    int ok2 = 1;
    ok2 &= fwrite(INEV_ENC_MAGIC, 1, INEV_ENC_MAGIC_LEN, out) == INEV_ENC_MAGIC_LEN;
    ok2 &= fwrite(hdr, 1, 4, out) == 4;
    ok2 &= fwrite(salt, 1, INEV_SALT_SIZE, out) == INEV_SALT_SIZE;
    ok2 &= fwrite(nonce, 1, INEV_NONCE_SIZE, out) == INEV_NONCE_SIZE;
    ok2 &= fwrite(ct, 1, (size_t)ct_len, out) == (size_t)ct_len;
    ok2 &= fwrite(tag, 1, INEV_TAG_SIZE, out) == INEV_TAG_SIZE;
    if (fclose(out) != 0) ok2 = 0;
    free(ct);
    if (!ok2) { remove(tmp_path); return -1; }
    if (rename(tmp_path, filepath) != 0) { remove(tmp_path); return -1; }
    printf("Map file '%s' encrypted successfully.\n", filepath);
    return 0;
}

// literal helpers

void flush_literal(FILE* f, unsigned char* b, int* c, uint16_t sid) {
    if (*c <= 0) return;
    int r = *c;
    unsigned char *p = b;
    while (r > 0) {
        int ch = (r > 127) ? 127 : r;
        unsigned char hdr[3];
        put_u16le(hdr, sid);
        hdr[2] = (uint8_t)ch;
        fwrite(hdr, 1, 3, f);
        fwrite(p, 1, (size_t)ch, f);
        p += ch;
        r -= ch;
    }
    *c = 0;
}

// main


int main(int argc, char* argv[]) {
    Secret secrets[INEV_MAX_SECRETS];
    memset(secrets, 0, sizeof secrets);
    int num_s = 0, num_c = 0, opt;
    const char *carrier_names[INEV_MAX_CARRIERS] = {0};
    const char *stego_append = NULL, *stego_lsb = NULL, *hunt_path = ".";
    bool strict_mode = false, analyze_mode = false, hunt_mode = false;
    while ((opt = getopt(argc, argv, "s:c:xaH:e:l:")) != -1) {
        switch (opt) {
            case 's':
                while (optind - 1 < argc && argv[optind - 1][0] != '-') {
                    if (num_s >= INEV_MAX_SECRETS) {
                        fprintf(stderr, "Error: too many secrets (max %d).\n", INEV_MAX_SECRETS);
                        return 1;
                    }
                    size_t sz = 0;
                    char *d = read_file_to_buffer(argv[optind - 1], &sz);
                    if (!d) {
                        fprintf(stderr, "Error: cannot read secret '%s'.\n", argv[optind - 1]);
                        return 1;
                    }
                    secrets[num_s].data = d;
                    secrets[num_s].size = sz;
                    secrets[num_s].filename = argv[optind - 1];
                    num_s++;
                    optind++;
                }
                optind--;
                break;
            case 'c':
                while (optind - 1 < argc && argv[optind - 1][0] != '-') {
                    if (num_c >= INEV_MAX_CARRIERS) {
                        fprintf(stderr, "Error: too many carriers (max %d).\n", INEV_MAX_CARRIERS);
                        return 1;
                    }
                    carrier_names[num_c++] = argv[optind - 1];
                    optind++;
                }
                optind--;
                break;
            case 'x': strict_mode = true; break;
            case 'a': analyze_mode = true; break;
            case 'H': hunt_mode = true; hunt_path = optarg; break;
            case 'e': stego_append = optarg; break;
            case 'l': stego_lsb = optarg; break;
        }
    }
    if (num_s == 0 && !hunt_mode) {
        fprintf(stderr,
                "Usage: %s -s <secret> [-c <carrier>] [-x] [-a] [-H <path>] [-e <host>] [-l <host>]\n",
                argv[0]);
        return 1;
    }
    if (hunt_mode) {
        if (num_s == 0) {
            fprintf(stderr, "Error: Hunt mode requires a secret (-s).\n");
            return 1;
        }
        printf("\n--- INEV MULTICORE HUNTER ---\nSecret: %s\n", secrets[0].filename);
        long ncores = sysconf(_SC_NPROCESSORS_ONLN);
        if (ncores < 1) ncores = 1;
        if (ncores > 64) ncores = 64;
        pthread_t w[64];
        for (int i = 0; i < ncores; i++) pthread_create(&w[i], NULL, hunt_worker, &secrets[0]);
        hunt_recursive(hunt_path, &secrets[0]);
        atomic_store(&hunting_finished, true);
        for (int i = 0; i < ncores; i++) pthread_join(w[i], NULL);
        free(secrets[0].data);
        return 0;
    }
    FILE* map_f = fopen("map.txt", "wb");
    if (!map_f) {
        fprintf(stderr, "Error: Unable to create map.txt\n");
        return 1;
    }
    /* Header do mapa */
    {
        unsigned char hdr[14];
        memcpy(hdr, INEV_MAP_MAGIC, 8);
        put_u16le(hdr + 8,  INEV_MAP_VERSION);
        put_u16le(hdr + 10, (uint16_t)num_c);
        fwrite(hdr, 1, 12, map_f);
    }
    for (int i = 0; i < num_c; i++) {
        unsigned char h[32];
        if (calculate_sha256_raw(carrier_names[i], h) != 0) {
            fprintf(stderr, "Error: cannot hash carrier '%s'.\n", carrier_names[i]);
            fclose(map_f);
            remove("map.txt");
            for (int k = 0; k < num_s; k++) free(secrets[k].data);
            return 1;
        }
        fwrite(h, 1, 32, map_f);
    }
    {
        unsigned char ns[2];
        put_u16le(ns, (uint16_t)num_s);
        fwrite(ns, 1, 2, map_f);
    }
    unsigned char libuf[LITERAL_BUF_SIZE];
    int licount = 0;
    unsigned char *chunk_buf = (unsigned char*)malloc(CHUNK_SIZE + OVERLAP);
    if (!chunk_buf) { fclose(map_f); remove("map.txt"); return 1; }
    for (int s = 0; s < num_s; s++) {
        printf("\nIndexing Secret [%d]: %s (%zu bytes)...\n",
               s, secrets[s].filename, secrets[s].size);
        SuffixTree* sec_tree = st_create(secrets[s].data, secrets[s].size);
        if (!sec_tree) {
            fprintf(stderr, "Error: Failed to create suffix tree for secret %d\n", s);
            free(secrets[s].data);
            secrets[s].data = NULL;
            continue;
        }
        MatchRecord* matches = (MatchRecord*)calloc(secrets[s].size ? secrets[s].size : 1,
                                                   sizeof(MatchRecord));
        if (!matches) {
            st_free(sec_tree);
            free(secrets[s].data);
            secrets[s].data = NULL;
            continue;
        }
        for (int c = 0; c < num_c; c++) {
            FILE* cfp = fopen(carrier_names[c], "rb");
            if (!cfp) {
                fprintf(stderr, "Warning: Failed to open carrier '%s'\n", carrier_names[c]);
                continue;
            }
            if (fseek(cfp, 0, SEEK_END) != 0) { fclose(cfp); continue; }
            long carrier_size = ftell(cfp);
            rewind(cfp);
            if (carrier_size < 0) { fclose(cfp); continue; }
            printf("  Streaming Carrier [%d]: %s (%ld MB)...\n",
                   c, carrier_names[c], carrier_size / (1024 * 1024));
            uint64_t carrier_file_offset = 0;
            size_t bytes_read;
            while ((bytes_read = fread(chunk_buf, 1, CHUNK_SIZE, cfp)) > 0) {
                for (size_t c_idx = 0; c_idx < bytes_read; c_idx++) {
                    size_t sec_offset = 0;
                    int match_len = st_find_match_with_offset(
                        sec_tree, (const char*)(chunk_buf + c_idx),
                        bytes_read - c_idx, &sec_offset);
                    if (match_len >= MIN_MATCH_LEN &&
                        sec_offset < secrets[s].size &&
                        (uint16_t)match_len > matches[sec_offset].length) {
                        matches[sec_offset].length = (uint16_t)match_len;
                        matches[sec_offset].carrier_id = (uint16_t)c;
                        matches[sec_offset].carrier_offset =
                            (uint32_t)(carrier_file_offset + c_idx);
                    }
                }
                if (bytes_read == CHUNK_SIZE) {
                    carrier_file_offset += (CHUNK_SIZE - OVERLAP);
                    if (fseek(cfp, (long)carrier_file_offset, SEEK_SET) != 0) break;
                } else {
                    carrier_file_offset += bytes_read;
                }
                if (carrier_size > 0) {
                    printf("\r  Progress Carrier [%d]: %.2f%%", c,
                           (double)carrier_file_offset / (double)carrier_size * 100.0);
                    fflush(stdout);
                }
            }
            fclose(cfp);
            printf("\n");
        }
        st_free(sec_tree);
        size_t total_covered = 0, match_count = 0;
        for (size_t i = 0; i < secrets[s].size; ) {
            if (matches[i].length >= MIN_MATCH_LEN) {
                total_covered += matches[i].length;
                match_count++;
                i += matches[i].length;
            } else {
                i++;
            }
        }
        double cov_pct = (double)total_covered / (double)(secrets[s].size ? secrets[s].size : 1) * 100.0;
        printf("Secret [%d] Coverage: %.2f%% (%zu matches, %zu bytes covered out of %zu)\n",
               s, cov_pct, match_count, total_covered, secrets[s].size);
        if (analyze_mode) {
            free(matches);
            free(secrets[s].data);
            secrets[s].data = NULL;
            continue;
        }
        if (strict_mode && total_covered < secrets[s].size) {
            fprintf(stderr,
                    "\nSTRICT MODE ERROR: Secret %d was not 100%% covered (only %.2f%%). Aborting.\n",
                    s, cov_pct);
            free(matches);
            free(chunk_buf);
            fclose(map_f);
            remove("map.txt");
            for (int k = s; k < num_s; k++) free(secrets[k].data);
            return 1;
        }
        for (size_t i = 0; i < secrets[s].size; ) {
            if (matches[i].length >= MIN_MATCH_LEN) {
                flush_literal(map_f, libuf, &licount, (uint16_t)s);
                unsigned char rec[11];
                put_u16le(rec,     (uint16_t)s);
                rec[2] = 0x80;
                put_u16le(rec + 3, matches[i].carrier_id);
                put_u32le(rec + 5, matches[i].carrier_offset);
                put_u16le(rec + 9, matches[i].length);
                fwrite(rec, 1, 11, map_f);
                i += matches[i].length;
            } else {
                libuf[licount++] = secrets[s].data[i++];
                if (licount == LITERAL_BUF_SIZE)
                    flush_literal(map_f, libuf, &licount, (uint16_t)s);
            }
        }
        flush_literal(map_f, libuf, &licount, (uint16_t)s);
        free(matches);
        free(secrets[s].data);
        secrets[s].data = NULL;
    }
    free(chunk_buf);
    if (fclose(map_f) != 0) {
        fprintf(stderr, "Error: failed to flush map.txt.\n");
        remove("map.txt");
        return 1;
    }
    if (analyze_mode) {
        printf("\nAnalysis finished. No map file generated.\n");
        remove("map.txt");
        return 0;
    }
    char *pass = getpass("Enter password for map encryption: ");
    if (!pass || strlen(pass) == 0) {
        fprintf(stderr, "Error: empty password.\n");
        remove("map.txt");
        return 1;
    }
   if (encrypt_file("map.txt", pass) != 0) {
    fprintf(stderr, "Error: encryption failed.\n");
    remove("map.txt");
    return 1;
    }
    if (stego_append) embed_append(stego_append, "map.txt");
    if (stego_lsb)   embed_lsb_robust(stego_lsb, "map.txt", pass);
    return 0;
}

