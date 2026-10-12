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
#include "rolling_hash.h"
#include "format.h"
#define MIN_MATCH_LEN       RH_KEY_LEN          /* 16 */
#define CHUNK_SIZE          (8 * 1024 * 1024)
#define BUF_SIZE            (CHUNK_SIZE + RH_KEY_LEN - 1)
#define LITERAL_BUF_SIZE    16384
// Structures
typedef struct {
    uint32_t secret_offset;
    uint16_t carrier_id;
    uint32_t carrier_offset;
    uint32_t length;
} SparseMatch;
typedef struct { 
    char *data; 
    size_t size; 
    const char *filename; 
} Secret;
typedef struct { 
    char filename[1024]; 
    double coverage; 
    double avg_match; 
} HuntResult;
typedef struct {
    RollingHashTable *table;
    const uint8_t *secret;
    size_t secret_size;
} HuntCtx;
// PRNG and utilities
uint32_t xorshift32(uint32_t *state) {
    uint32_t x = *state;
    x ^= x << 13; 
    x ^= x >> 17; 
    x ^= x << 5;
    if (x == 0) x = 1;
    return (*state = x);
}
char *read_file_to_buffer(const char *filename, size_t *out_size) {
    struct stat st;
    if (stat(filename, &st) != 0 || st.st_size < 0) return NULL;
    *out_size = (size_t)st.st_size;
    
    FILE *fp = fopen(filename, "rb");
    if (!fp) return NULL;
    
    size_t alloc = *out_size ? *out_size : 1;
    char *b = (char *)malloc(alloc);
    if (!b) { 
        fclose(fp); 
        return NULL; 
    }
    
    if (*out_size && fread(b, 1, *out_size, fp) != *out_size) {
        free(b); 
        fclose(fp); 
        return NULL;
    }
    
    fclose(fp);
    return b;
}
int calculate_sha256_raw(const char *f, unsigned char *h) {
    FILE *fp = fopen(f, "rb");
    if (!fp) return -1;
    
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) { 
        fclose(fp); 
        return -1; 
    }
    
    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) {
        EVP_MD_CTX_free(ctx); 
        fclose(fp); 
        return -1;
    }
    
    unsigned char b[4096];
    size_t n;
    while ((n = fread(b, 1, sizeof b, fp)) > 0) {
        EVP_DigestUpdate(ctx, b, n);
    }
    
    EVP_DigestFinal_ex(ctx, h, NULL);
    EVP_MD_CTX_free(ctx);
    fclose(fp);
    return 0;
}
#ifdef _WIN32
#include <conio.h>
char *getpass(const char *prompt) {
    static char password[128];
    int i = 0, ch;
    fprintf(stderr, "%s", prompt);
    while ((ch = _getch()) != '\r') {
        if (ch == '\b') { 
            if (i > 0) i--; 
        } else if (i < 127) {
            password[i++] = (char)ch;
        }
    }
    password[i] = '\0';
    fprintf(stderr, "\n");
    return password;
}
#endif
// Hunter
static atomic_bool hunting_finished = false;
static char file_queue[5000][1024];
static int queue_size = 0;
static int queue_current = 0;
static pthread_mutex_t queue_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t ranking_mutex = PTHREAD_MUTEX_INITIALIZER;
static HuntResult top_results[5];
const char *entry_name_only(const char *path) {
    const char *s = strrchr(path, '/');
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
void hunt_recursive(const char *path) {
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
            if (S_ISDIR(st.st_mode)) {
                hunt_recursive(full);
            } else if (S_ISREG(st.st_mode)) {
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
// Scans a file against the secret index and returns (matched_bytes, num_matches).
static void scan_candidate(const uint8_t *data, size_t size,
                           const RollingHashTable *table,
                           const uint8_t *secret, size_t secret_size,
                           long *out_matched, long *out_matches) {
    *out_matched = 0;
    *out_matches = 0;
    if (size < RH_KEY_LEN) return;
    
    size_t limit = size - RH_KEY_LEN + 1;
    uint64_t h = buzhash_init(data);
    
    for (size_t i = 0; i < limit; ) {
        uint32_t sec_off;
        if (rh_lookup(table, data + i, h, &sec_off)) {
            size_t ml = RH_KEY_LEN;
            while (i + ml < size &&
                   sec_off + ml < secret_size &&
                   data[i + ml] == secret[sec_off + ml])
                ml++;
            *out_matched += (long)ml;
            (*out_matches)++;
            i += ml;
            if (i < limit) h = buzhash_init(data + i);
        } else {
            if (i + 1 >= limit) break;
            h = buzhash_roll(h, data[i], data[i + RH_KEY_LEN]);
            i++;
        }
    }
}
void *hunt_worker(void *arg) {
    HuntCtx *ctx = (HuntCtx *)arg;
    char current_file[1024];
    uint8_t *buf = (uint8_t *)malloc(BUF_SIZE);
    if (!buf) return NULL;
    
    while (true) {
        pthread_mutex_lock(&queue_mutex);
        if (queue_current >= queue_size) {
            pthread_mutex_unlock(&queue_mutex);
            if (atomic_load(&hunting_finished)) break;
            usleep(10000);
            continue;
        }
        
        strncpy(current_file, file_queue[queue_current], sizeof(current_file) - 1);
        current_file[sizeof(current_file) - 1] = '\0';
        int current_idx = ++queue_current;
        pthread_mutex_unlock(&queue_mutex);
        
        FILE *f = fopen(current_file, "rb");
        if (!f) continue;
        
        long total_matched = 0, total_matches = 0;
        size_t bytes_read;
        while ((bytes_read = fread(buf, 1, BUF_SIZE, f)) > 0) {
            long m, mc;
            scan_candidate(buf, bytes_read, ctx->table,
                           ctx->secret, ctx->secret_size, &m, &mc);
            total_matched += m;
            total_matches += mc;
            if (bytes_read < BUF_SIZE) break;
        }
        fclose(f);
        
        pthread_mutex_lock(&ranking_mutex);
        update_ranking(current_file,
                       (double)total_matched / (bytes_read ? (double)bytes_read : 1.0) * 100.0,
                       (double)total_matched / (total_matches ? total_matches : 1));
                       
        printf("\r[Hunter] Best: %.2f%% | Files: %d | Current: %s",
               top_results[0].coverage, current_idx, entry_name_only(current_file));
        fflush(stdout);
        pthread_mutex_unlock(&ranking_mutex);
    }
    free(buf);
    return NULL;
}
// Embedding
void embed_append(const char *host, const char *map) {
    char out_path[1024];
    const char *dot = strrchr(host, '.');
    if (dot) {
        size_t l = (size_t)(dot - host);
        if (l + 32 >= sizeof out_path) { 
            fprintf(stderr, "[Append] Path too long.\n"); 
            return; 
        }
        memcpy(out_path, host, l);
        snprintf(out_path + l, sizeof(out_path) - l, "_stego%s", dot);
    } else {
        if (snprintf(out_path, sizeof out_path, "%s_stego", host) >= (int)sizeof out_path) {
            fprintf(stderr, "[Append] Path too long.\n"); 
            return;
        }
    }
    
    FILE *fh = fopen(host, "rb"), *fm = fopen(map, "rb"), *fo = fopen(out_path, "wb");
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
    
    fclose(fh); 
    fclose(fm);
    if (fclose(fo) != 0) ok = 0;
    if (!ok) { 
        fprintf(stderr, "[Append] I/O error.\n"); 
        remove(out_path); 
        return; 
    }
    printf("[Stego] Map appended: %s\n", out_path);
}
void embed_lsb_robust(const char *host_path, const char *map_path, const char *pass) {
    size_t h_sz = 0, m_sz = 0;
    unsigned char *h = (unsigned char *)read_file_to_buffer(host_path, &h_sz);
    unsigned char *m = (unsigned char *)read_file_to_buffer(map_path, &m_sz);
    if (!h || !m) { free(h); free(m); return; }
    if (h_sz < 54) { 
        fprintf(stderr, "[LSB] Host too small.\n"); 
        free(h); free(m); 
        return; 
    }
    
    uint32_t off = (h[0] == 'B' && h[1] == 'M') ? get_u32le(h + 10) : 0;
    if (off >= h_sz) { free(h); free(m); return; }
    
    size_t avail = h_sz - off;
    if (avail < m_sz * 8) {
        fprintf(stderr, "[LSB] Host too small.\n"); 
        free(h); free(m); 
        return;
    }
    
    unsigned char hash[32];
    if (PKCS5_PBKDF2_HMAC(pass, (int)strlen(pass),
                          (unsigned char *)"INEV_SEED", 9,
                          INEV_SEED_ITERS, EVP_sha256(), 32, hash) != 1) {
        free(h); free(m); return;
    }
    
    uint32_t seed = get_u32le(hash);
    if (seed == 0) seed = 1;
    
    uint32_t *idx = (uint32_t *)malloc(avail * sizeof(uint32_t));
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
    const char *dot = strrchr(host_path, '.');
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
    
    FILE *fo = fopen(out_path, "wb");
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
// Encryption (AES-256-GCM)
int encrypt_file(const char *filepath, const char *pass) {
    FILE *in = fopen(filepath, "rb");
    if (!in) return -1;
    if (fseek(in, 0, SEEK_END) != 0) { fclose(in); return -1; }
    
    long raw_len = ftell(in);
    if (raw_len < 0) { fclose(in); return -1; }
    rewind(in);
    
    unsigned char *raw = (unsigned char *)malloc(raw_len ? (size_t)raw_len : 1);
    if (!raw) { fclose(in); return -1; }
    if (raw_len > 0 && fread(raw, 1, (size_t)raw_len, in) != (size_t)raw_len) {
        free(raw); fclose(in); return -1;
    }
    fclose(in);
    
    uLongf c_len = compressBound((uLong)raw_len);
    unsigned char *c_data = (unsigned char *)malloc(c_len ? c_len : 1);
    if (!c_data) { free(raw); return -1; }
    
    if (compress(c_data, &c_len, raw, (uLong)raw_len) != Z_OK) {
        free(raw); free(c_data); return -1;
    }
    free(raw);
    
    size_t pt_len = (size_t)c_len + 4;
    if (pt_len > UINT32_MAX) { free(c_data); return -1; }
    
    unsigned char *pt = (unsigned char *)malloc(pt_len);
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
    
    unsigned char *ct = (unsigned char *)malloc(pt_len + INEV_TAG_SIZE);
    if (!ct) {
        EVP_CIPHER_CTX_free(ctx);
        inev_secure_zero(d, sizeof d);
        free(pt);
        return -1;
    }
    
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
// Literals
void flush_literal(FILE *f, unsigned char *b, int *c, uint16_t sid) {
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
static void emit_reference(FILE *f, uint16_t sid, uint16_t cid,
                          uint32_t off, uint16_t len) {
    unsigned char rec[11];
    put_u16le(rec, sid);
    rec[2] = 0x80;
    put_u16le(rec + 3, cid);
    put_u32le(rec + 5, off);
    put_u16le(rec + 9, len);
    fwrite(rec, 1, 11, f);
}
// Matching
static int cmp_sparse_match(const void *a, const void *b) {
    const SparseMatch *x = (const SparseMatch *)a;
    const SparseMatch *y = (const SparseMatch *)b;
    if (x->secret_offset < y->secret_offset) return -1;
    if (x->secret_offset > y->secret_offset) return  1;
    if (x->length > y->length) return -1;
    if (x->length < y->length) return  1;
    return 0;
}
static int append_match(SparseMatch **arr, size_t *n, size_t *cap, SparseMatch m) {
    if (*n == *cap) {
        size_t nc = (*cap) ? (*cap) * 2 : 4096;
        if (nc > SIZE_MAX / sizeof(SparseMatch)) return 0;
        SparseMatch *na = (SparseMatch *)realloc(*arr, nc * sizeof(SparseMatch));
        if (!na) return 0;
        *arr = na; *cap = nc;
    }
    (*arr)[(*n)++] = m;
    return 1;
}
// Streams a carrier and collects matches.
static void scan_carrier(FILE *cfp,
                         const RollingHashTable *table,
                         const uint8_t *secret, size_t secret_size,
                         uint16_t cid,
                         SparseMatch **arr, size_t *n_arr, size_t *cap_arr,
                         int progress_c) {
    long carrier_size = 0;
    if (fseek(cfp, 0, SEEK_END) == 0) carrier_size = ftell(cfp);
    rewind(cfp);
    
    uint8_t *buf = (uint8_t *)malloc(BUF_SIZE);
    if (!buf) return;
    
    uint64_t file_offset = 0;
    size_t bytes_read;
    while ((bytes_read = fread(buf, 1, BUF_SIZE, cfp)) > 0) {
        if (bytes_read < RH_KEY_LEN) break;
        size_t kmer_limit = bytes_read - RH_KEY_LEN + 1;
        size_t process_limit = kmer_limit < CHUNK_SIZE ? kmer_limit : CHUNK_SIZE;
        uint64_t h = buzhash_init(buf);
        
        for (size_t i = 0; i < process_limit; ) {
            uint32_t sec_off;
            if (rh_lookup(table, buf + i, h, &sec_off)) {
                size_t ml = RH_KEY_LEN;
                size_t max_ext = bytes_read - i;
                while (ml < max_ext &&
                       sec_off + ml < secret_size &&
                       buf[i + ml] == secret[sec_off + ml])
                    ml++;
                if (file_offset + i <= UINT32_MAX) {
                    SparseMatch sm;
                    sm.secret_offset  = sec_off;
                    sm.carrier_id     = cid;
                    sm.carrier_offset = (uint32_t)(file_offset + i);
                    sm.length         = (uint32_t)ml;
                    append_match(arr, n_arr, cap_arr, sm);
                }
                i += ml;
                if (i < process_limit) h = buzhash_init(buf + i);
            } else {
                if (i + 1 >= process_limit) break;
                h = buzhash_roll(h, buf[i], buf[i + RH_KEY_LEN]);
                i++;
            }
        }
        file_offset += process_limit;
        if (carrier_size > 0) {
            printf("\r  Progress Carrier [%d]: %.2f%%", progress_c,
                   (double)file_offset / (double)carrier_size * 100.0);
            fflush(stdout);
        }
        if (bytes_read < BUF_SIZE) break;
        if (fseek(cfp, (long)file_offset, SEEK_SET) != 0) break;
    }
    free(buf);
    printf("\n");
}
// main
static int choose_w(size_t size) {
    if (size > 4ULL * 1024 * 1024 * 1024) return 32;
    if (size > 1024ULL * 1024 * 1024)     return 16;
    if (size > 256ULL * 1024 * 1024)      return 8;
    if (size > 64ULL * 1024 * 1024)       return 4;
    return 1;
}
int main(int argc, char *argv[]) {
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
                        fprintf(stderr, "Error: too many secrets.\n");
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
                        fprintf(stderr, "Error: too many carriers.\n");
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
        fprintf(stderr, "Usage: %s -s <secret> [-c <carriers>] [-x] [-a] [-H <path>] [-e <host>] [-l <host>]\n",
                argv[0]);
        return 1;
    }
    
    // HUNTER
    if (hunt_mode) {
        if (num_s == 0) { fprintf(stderr, "Error: Hunt mode requires -s.\n"); return 1; }
        printf("\n--- INEV MULTICORE HUNTER ---\nSecret: %s\n", secrets[0].filename);
        size_t sample = secrets[0].size > 1024 * 1024 ? 1024 * 1024 : secrets[0].size;
        RollingHashTable *table = rh_build((const uint8_t *)secrets[0].data, sample, 1);
        if (!table) {
            fprintf(stderr, "Error: secret too small (need >= %d bytes).\n", RH_KEY_LEN);
            free(secrets[0].data);
            return 1;
        }
        HuntCtx ctx = { table, (const uint8_t *)secrets[0].data, sample };
        long ncores = sysconf(_SC_NPROCESSORS_ONLN);
        if (ncores < 1) ncores = 1;
        if (ncores > 64) ncores = 64;
        pthread_t w[64];
        for (int i = 0; i < ncores; i++) pthread_create(&w[i], NULL, hunt_worker, &ctx);
        hunt_recursive(hunt_path);
        atomic_store(&hunting_finished, true);
        for (int i = 0; i < ncores; i++) pthread_join(w[i], NULL);
        rh_free(table);
        free(secrets[0].data);
        return 0;
    }
    
    // MAP HEADER
    FILE *map_f = fopen("map.txt", "wb");
    if (!map_f) { fprintf(stderr, "Error: cannot create map.txt\n"); return 1; }
    {
        unsigned char hdr[12];
        memcpy(hdr, INEV_MAP_MAGIC, 8);
        put_u16le(hdr + 8,  INEV_MAP_VERSION);
        put_u16le(hdr + 10, (uint16_t)num_c);
        fwrite(hdr, 1, 12, map_f);
    }
    for (int i = 0; i < num_c; i++) {
        unsigned char h[32];
        if (calculate_sha256_raw(carrier_names[i], h) != 0) {
            fprintf(stderr, "Error: cannot hash carrier '%s'.\n", carrier_names[i]);
            fclose(map_f); remove("map.txt");
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
    
    // PROCESS EACH SECRET
    for (int s = 0; s < num_s; s++) {
        printf("\nIndexing Secret [%d]: %s (%zu bytes)...\n", s, secrets[s].filename, secrets[s].size);
        int w = choose_w(secrets[s].size);
        RollingHashTable *table = rh_build((const uint8_t *)secrets[s].data, secrets[s].size, w);
        if (table) {
            printf("  Index built: w=%d, %zu entries, %.1f MB\n",
                   w, rh_num_entries(table),
                   (double)rh_memory_bytes(table) / (1024.0 * 1024.0));
        } else {
            printf("  Warning: could not build index (secret too small?), emitting all literals.\n");
        }
        
        SparseMatch *matches = NULL;
        size_t num_matches = 0, cap_matches = 0;
        for (int c = 0; c < num_c; c++) {
            FILE *cfp = fopen(carrier_names[c], "rb");
            if (!cfp) {
                fprintf(stderr, "Warning: Failed to open carrier '%s'\n", carrier_names[c]);
                continue;
            }
            printf("  Streaming Carrier [%d]: %s\n", c, carrier_names[c]);
            if (table) {
                scan_carrier(cfp, table, (const uint8_t *)secrets[s].data, secrets[s].size,
                             (uint16_t)c, &matches, &num_matches, &cap_matches, c);
            }
            fclose(cfp);
        }
        
        // Sorts by offset in the secret, longest first
        if (num_matches > 1) {
            qsort(matches, num_matches, sizeof(SparseMatch), cmp_sparse_match);
        }
        
        // Statistics
        {
            size_t total_covered = 0, match_count = 0;
            for (size_t k = 0; k < num_matches; k++) {
                if (matches[k].length >= MIN_MATCH_LEN) {
                    total_covered += matches[k].length;
                    match_count++;
                }
            }
            printf("Secret [%d] matches: %zu, bytes potencialmente cobertos: %zu/%zu\n",
                   s, match_count, total_covered, secrets[s].size);
            (void)match_count;
        }
        
        if (analyze_mode) {
            free(matches);
            if (table) rh_free(table);
            free(secrets[s].data);
            secrets[s].data = NULL;
            continue;
        }
        
        // Emit
        size_t m_idx = 0;
        for (size_t i = 0; i < secrets[s].size; ) {
            while (m_idx < num_matches && matches[m_idx].secret_offset < i) m_idx++;
            SparseMatch *best = NULL;
            size_t j = m_idx;
            while (j < num_matches && matches[j].secret_offset == i) {
                if (!best || matches[j].length > best->length) best = &matches[j];
                j++;
            }
            if (best && best->length >= MIN_MATCH_LEN) {
                flush_literal(map_f, libuf, &licount, (uint16_t)s);
                uint32_t off = best->carrier_offset;
                uint32_t len = best->length;
                while (len > 0) {
                    uint16_t chunk = (len > 65535) ? 65535 : (uint16_t)len;
                    emit_reference(map_f, (uint16_t)s, best->carrier_id, off, chunk);
                    off += chunk;
                    len -= chunk;
                }
                i += best->length;
            } else {
                libuf[licount++] = (unsigned char)secrets[s].data[i++];
                if (licount == LITERAL_BUF_SIZE)
                    flush_literal(map_f, libuf, &licount, (uint16_t)s);
            }
        }
        flush_literal(map_f, libuf, &licount, (uint16_t)s);
        
        if (strict_mode) {
            size_t covered = 0;
            size_t k = 0;
            for (size_t i = 0; i < secrets[s].size; ) {
                while (k < num_matches && matches[k].secret_offset < i) k++;
                SparseMatch *best2 = NULL;
                size_t jj = k;
                while (jj < num_matches && matches[jj].secret_offset == i) {
                    if (!best2 || matches[jj].length > best2->length) best2 = &matches[jj];
                    jj++;
                }
                if (best2 && best2->length >= MIN_MATCH_LEN) {
                    covered += best2->length;
                    i += best2->length;
                } else i++;
            }
            if (covered < secrets[s].size) {
                fprintf(stderr, "\nSTRICT MODE ERROR: secret %d not 100%% covered (%zu/%zu).\n",
                        s, covered, secrets[s].size);
                free(matches);
                if (table) rh_free(table);
                fclose(map_f); remove("map.txt");
                for (int kk = s; kk < num_s; kk++) free(secrets[kk].data);
                return 1;
            }
        }
        free(matches);
        if (table) rh_free(table);
        free(secrets[s].data);
        secrets[s].data = NULL;
    }
    
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
    
