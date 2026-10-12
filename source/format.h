#ifndef INEV_FORMAT_H
#define INEV_FORMAT_H
#include <stdint.h>
#include <stddef.h>
#include <string.h>

// Magics e version 

#define INEV_ENC_MAGIC       "LIDECENC"
#define INEV_ENC_MAGIC_LEN   8
#define INEV_MAP_MAGIC       "LIDECMAP"
#define INEV_MAP_MAGIC_LEN   8
#define INEV_MAP_VERSION     4

// Sizes 

#define INEV_SALT_SIZE       16
#define INEV_NONCE_SIZE      12   /* GCM nonce default */
#define INEV_TAG_SIZE        16   /* GCM tag */
#define INEV_KEY_SIZE        32
#define INEV_IV_SIZE         16   /* legacy (CBC) - kept for reference  */

// cripto parameter

#define INEV_PBKDF2_ITERS    600000
#define INEV_SEED_ITERS      1000

//  Limits

#define INEV_MAX_MAP_SIZE    (8ULL * 1024 * 1024 * 1024)  /* 8 GB */
#define INEV_MAX_SECRETS     100
#define INEV_MAX_CARRIERS    100
#define INEV_MIN_ENC_OVERHEAD (INEV_SALT_SIZE + INEV_NONCE_SIZE + INEV_TAG_SIZE)

//  Zeroing safe

static inline void inev_secure_zero(void* p, size_t n) {
#if defined(__STDC_LIB_EXT1__)
    memset_s(p, n, 0, n);
#elif defined(__GLIBC__) && defined(__GLIBC_PREREQ) && __GLIBC_PREREQ(2,25)
    explicit_bzero(p, n);
#else
    volatile unsigned char* v = (volatile unsigned char*)p;
    while (n--) *v++ = 0;
#endif
}
/* --- Little-endian explícito --- */
static inline void put_u16le(unsigned char* p, uint16_t v) {
    p[0] = (unsigned char)( v        & 0xFF);
    p[1] = (unsigned char)((v >>  8) & 0xFF);
}
static inline void put_u32le(unsigned char* p, uint32_t v) {
    p[0] = (unsigned char)( v        & 0xFF);
    p[1] = (unsigned char)((v >>  8) & 0xFF);
    p[2] = (unsigned char)((v >> 16) & 0xFF);
    p[3] = (unsigned char)((v >> 24) & 0xFF);
}
static inline uint16_t get_u16le(const unsigned char* p) {
    return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}
static inline uint32_t get_u32le(const unsigned char* p) {
    return (uint32_t)((uint32_t)p[0]        |
                     ((uint32_t)p[1] <<  8) |
                     ((uint32_t)p[2] << 16) |
                     ((uint32_t)p[3] << 24));
}
#endif /* INEV_FORMAT_H */
    
