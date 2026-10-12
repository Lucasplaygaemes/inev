#include "rolling_hash.h"
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#define EMPTY 0u  /* slots store offset+1; 0 = empty */
static uint64_t buz_table[256];
static uint64_t buz_rot_k[256];
static int buz_initialized = 0;
static uint64_t splitmix64(uint64_t* s) {
    uint64_t z = (*s += 0x9E3779B97F4A7C15ULL);
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}
static void buz_init(void) {
    if (buz_initialized) return;
    uint64_t s = 0xDEADBEEFCAFEBABEULL;
    for (int i = 0; i < 256; i++) {
        buz_table[i] = splitmix64(&s);
        buz_rot_k[i] = (buz_table[i] << RH_KEY_LEN)
                     | (buz_table[i] >> (64 - RH_KEY_LEN));
    }
    buz_initialized = 1;
}
static inline uint64_t rotl64(uint64_t x, int r) {
    return (x << r) | (x >> (64 - r));
}
uint64_t buzhash_init(const uint8_t* data) {
    buz_init();
    uint64_t h = 0;
    for (int i = 0; i < RH_KEY_LEN; i++)
        h = rotl64(h, 1) ^ buz_table[data[i]];
    return h;
}
uint64_t buzhash_roll(uint64_t h, uint8_t out, uint8_t in) {
    return rotl64(h, 1) ^ buz_rot_k[out] ^ buz_table[in];
}
struct RollingHashTable {
    const uint8_t* secret;
    size_t secret_size;
    uint32_t* slots;
    size_t num_slots;
    size_t mask;
    size_t num_entries;
    int w;
};
/* Minimizers selection — monotonic deque, O(n) time, O(w) memory.
 * `w` must be a power of 2. */
static size_t emit_minimizers(const uint64_t* hashes, size_t n, int w,
                              uint32_t* out_offsets) {
    size_t* dq = (size_t*)malloc(sizeof(size_t) * (size_t)w);
    if (!dq) return 0;
    size_t head = 0, tail = 0;
    size_t emitted = 0;
    uint32_t last_emitted = UINT32_MAX;
    size_t mask = (size_t)w - 1;
    for (size_t i = 0; i < n; i++) {
        while (head < tail && dq[head & mask] + (size_t)w <= i) head++;
        while (tail > head && hashes[dq[(tail - 1) & mask]] >= hashes[i]) tail--;
        dq[tail & mask] = i;
        tail++;
        if (i >= (size_t)w - 1) {
            size_t m = dq[head & mask];
            if (m != last_emitted) {
                out_offsets[emitted++] = (uint32_t)m;
                last_emitted = (uint32_t)m;
            }
        }
    }
    free(dq);
    return emitted;
}
RollingHashTable* rh_build(const uint8_t* secret, size_t secret_size, int w) {
    buz_init();
    if (!secret || secret_size < RH_KEY_LEN) return NULL;
    /* w: power of 2 >= 2, or 1 (dense) */
    if (w <= 1) w = 1;
    else {
        int p = 2;
        while (p < w) p <<= 1;
        w = p;
    }
    size_t num_kmers = secret_size - RH_KEY_LEN + 1;
    uint64_t* hashes = (uint64_t*)malloc(sizeof(uint64_t) * num_kmers);
    if (!hashes) return NULL;
    hashes[0] = buzhash_init(secret);
    for (size_t i = 1; i < num_kmers; i++)
        hashes[i] = buzhash_roll(hashes[i-1], secret[i-1], secret[i + RH_KEY_LEN - 1]);
    uint32_t* positions = (uint32_t*)malloc(sizeof(uint32_t) * num_kmers);
    if (!positions) { free(hashes); return NULL; }
    size_t num_positions;
    if (w == 1) {
        for (size_t i = 0; i < num_kmers; i++) positions[i] = (uint32_t)i;
        num_positions = num_kmers;
    } else {
        num_positions = emit_minimizers(hashes, num_kmers, w, positions);
    }
    /* Table: load factor 0.5, size = next power of 2 */
    size_t min_slots = num_positions * 2;
    size_t num_slots = 1;
    while (num_slots < min_slots) {
        if (num_slots > (SIZE_MAX >> 1)) {
            free(hashes); free(positions); return NULL;
        }
        num_slots <<= 1;
    }
    uint32_t* slots = (uint32_t*)calloc(num_slots, sizeof(uint32_t));
    if (!slots) { free(hashes); free(positions); return NULL; }
    for (size_t i = 0; i < num_positions; i++) {
        uint32_t off = positions[i];
        uint64_t h = hashes[off];
        size_t slot = (size_t)(h & (num_slots - 1));
        for (;;) {
            uint32_t existing = slots[slot];
            if (existing == EMPTY) { slots[slot] = off + 1; break; }
            /* Dedup: same k-mer already indexed — skip */
            if (memcmp(secret + existing - 1, secret + off, RH_KEY_LEN) == 0)
                break;
            slot = (slot + 1) & (num_slots - 1);
        }
    }
    free(hashes);
    free(positions);
    RollingHashTable* t = (RollingHashTable*)malloc(sizeof(RollingHashTable));
    if (!t) { free(slots); return NULL; }
    t->secret = secret;
    t->secret_size = secret_size;
    t->slots = slots;
    t->num_slots = num_slots;
    t->mask = num_slots - 1;
    t->num_entries = num_positions;
    t->w = w;
    return t;
}
bool rh_lookup(const RollingHashTable* t, const uint8_t* kmer,
               uint64_t hash, uint32_t* out_offset) {
    size_t slot = (size_t)(hash & t->mask);
    for (size_t probes = 0; probes <= t->mask; probes++) {
        uint32_t existing = t->slots[slot];
        if (existing == EMPTY) return false;
        if (memcmp(t->secret + existing - 1, kmer, RH_KEY_LEN) == 0) {
            *out_offset = existing - 1;
            return true;
        }
        slot = (slot + 1) & t->mask;
    }
    return false;
}
const uint8_t* rh_secret(const RollingHashTable* t) { return t->secret; }
int            rh_window(const RollingHashTable* t) { return t->w; }
size_t         rh_num_entries(const RollingHashTable* t) { return t->num_entries; }
size_t         rh_memory_bytes(const RollingHashTable* t) {
    return t->secret_size + t->num_slots * sizeof(uint32_t) + sizeof(RollingHashTable);
}
void rh_free(RollingHashTable* t) {
    if (!t) return;
    free(t->slots);
    free(t);
}

