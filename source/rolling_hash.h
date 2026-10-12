#ifndef INEV_ROLLING_HASH_H
#define INEV_ROLLING_HASH_H
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#define RH_KEY_LEN 16

typedef struct RollingHashTable RollingHashTable;

/* Builds the secret index via buzhash + minimizers.
 * w <= 1 disables minimizers (dense index).
 * `secret` pointer is borrowed (not copied) — must live
 * as long as the table lives.
 * Returns NULL if secret_size < RH_KEY_LEN or in OOM. */

RollingHashTable* rh_build(const uint8_t* secret, size_t secret_size, int w);

/* Search for a k-mer. hash is the buzhash of k-mer. */

bool rh_lookup(const RollingHashTable* t, const uint8_t* kmer, uint64_t hash, uint32_t* out_offset);

const uint8_t* rh_secret(const RollingHashTable* t);
int rh_window(const RollingHashTable* t);
size_t rh_num_entries(const RollingHashTable* t);
size_t rh_memory_bytes(const RollingHashTable* t);
void rh_free(RollingHashTable* t);

/* buzhash: hash of RH_KEY_LEN bytes, and rolling by 1 byte. */

uint64_t buzhash_init(const uint8_t* data);
uint64_t buzhash_roll(uint64_t h, uint8_t out, uint8_t in);

#endif /* INEV_ROLLING_HASH_H */
