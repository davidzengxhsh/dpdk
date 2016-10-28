
/*
 *TBD: License 
 * */

#ifndef _RTE_CRC_PPC64_H_
#define _RTE_CRC_PPC64_H_

/**
 * @file
 *
 * RTE CRC ppc64 Hash
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <rte_cpuflags.h>
#include <rte_branch_prediction.h>
#include <rte_common.h>

#define CRC_TABLE
#include "crc32_constants.h"

#define VMX_ALIGN       16
#define VMX_ALIGN_MASK  (VMX_ALIGN-1)

#ifdef REFLECT
static unsigned int crc32_align(unsigned int crc, unsigned char *p,
                               unsigned long len)
{
        while (len--)
                crc = crc_table[(crc ^ *p++) & 0xff] ^ (crc >> 8);
        return crc;
}
#else
static unsigned int crc32_align(unsigned int crc, unsigned char *p,
                                unsigned long len)
{
        while (len--)
                crc = crc_table[((crc >> 24) ^ *p++) & 0xff] ^ (crc << 8);
        return crc;
}
#endif

unsigned int __crc32_vpmsum(unsigned int crc, unsigned char *p,
                            unsigned long len);

static unsigned int crc32_vpmsum(unsigned int crc, unsigned char *p,
                          unsigned long len)
{
        unsigned int prealign;
        unsigned int tail;

#ifdef CRC_XOR
        crc ^= 0xffffffff;
#endif

        if (len < VMX_ALIGN + VMX_ALIGN_MASK) {
                crc = crc32_align(crc, p, len);
                goto out;
        }

        if ((unsigned long)p & VMX_ALIGN_MASK) {
                prealign = VMX_ALIGN - ((unsigned long)p & VMX_ALIGN_MASK);
                crc = crc32_align(crc, p, prealign);
                len -= prealign;
                p += prealign;
        }

        crc = __crc32_vpmsum(crc, p, len & ~VMX_ALIGN_MASK);

        tail = len & VMX_ALIGN_MASK;
        if (tail) {
                p += len & ~VMX_ALIGN_MASK;
                crc = crc32_align(crc, p, tail);
        }

out:
#ifdef CRC_XOR
        crc ^= 0xffffffff;
#endif

        return crc;
}


static inline uint32_t
crc32c_ppc64_u8(uint8_t data, uint32_t init_val)
{
        init_val = crc32_vpmsum(init_val, &data, 1);
        return init_val;
}

static inline uint32_t
crc32c_ppc64_u16(uint16_t data, uint32_t init_val)
{
        init_val = crc32_vpmsum(init_val, (uint8_t *)&data, 2);
        return init_val;
}

static inline uint32_t
crc32c_ppc64_u32(uint32_t data, uint32_t init_val)
{
        init_val = crc32_vpmsum(init_val, (uint8_t *)&data, 4);
        return init_val;
}

static inline uint32_t
crc32c_ppc64_u64(uint64_t data, uint32_t init_val)
{
        init_val = crc32_vpmsum(init_val, (uint8_t *)&data, 8);
        return init_val;
}

/**
 * Allow or disallow use of ppc64 vpmsum instructions for CRC32 hash
 * calculation.
 *
 * @param alg
 *   An OR of following flags:
 *   - (CRC32_SW) Don't use ppc64 vpmsum crc instructions
 *   - (CRC32_PPC64) Use ppc64 vpmsum instructions if available
 *
 */
static inline void
rte_hash_crc_set_alg(uint8_t alg)
{
        switch (alg) {
        case CRC32_PPC64:
                if (!rte_cpu_get_flag_enabled(RTE_CPUFLAG_ARCH_2_07))
                        alg = CRC32_SW;
        case CRC32_SW:
                crc32_alg = alg;
        default:
                break;
        }
}

/* Setting the best available algorithm */
static inline void __attribute__((constructor))
rte_hash_crc_init_alg(void)
{
        rte_hash_crc_set_alg(CRC32_PPC64);
}

/**
 * Use single crc32 instruction to perform a hash on a 1 byte value.
 * Fall back to software crc32 implementation in case ppc64 crc intrinsics is
 * not supported
 *
 * @param data
 *   Data to perform hash on.
 * @param init_val
 *   Value to initialise hash generator.
 * @return
 *   32bit calculated hash value.
 */
static inline uint32_t
rte_hash_crc_1byte(uint8_t data, uint32_t init_val)
{
        if (likely(crc32_alg & CRC32_PPC64))
                return crc32c_ppc64_u8(data, init_val);

        return crc32c_1byte(data, init_val);
}

/**
 * Use single crc32 instruction to perform a hash on a 2 bytes value.
 * Fall back to software crc32 implementation in case ppc64 crc intrinsics is
 * not supported
 *
 * @param data
 *   Data to perform hash on.
 * @param init_val
 *   Value to initialise hash generator.
 * @return
 *   32bit calculated hash value.
 */
static inline uint32_t
rte_hash_crc_2byte(uint16_t data, uint32_t init_val)
{
        if (likely(crc32_alg & CRC32_PPC64))
                return crc32c_ppc64_u16(data, init_val);

        return crc32c_2bytes(data, init_val);
}

/**
 * Use single crc32 instruction to perform a hash on a 4 byte value.
 * Fall back to software crc32 implementation in case ppc64 crc intrinsics is
 * not supported
 *
 * @param data
 *   Data to perform hash on.
 * @param init_val
 *   Value to initialise hash generator.
 * @return
 *   32bit calculated hash value.
 */
static inline uint32_t
rte_hash_crc_4byte(uint32_t data, uint32_t init_val)
{
        if (likely(crc32_alg & CRC32_PPC64))
                return crc32c_ppc64_u32(data, init_val);

        return crc32c_1word(data, init_val);
}

/**
 * Use single crc32 instruction to perform a hash on a 8 byte value.
 * Fall back to software crc32 implementation in case ppc64 crc intrinsics is
 * not supported
 *
 * @param data
 *   Data to perform hash on.
 * @param init_val
 *   Value to initialise hash generator.
 * @return
 *   32bit calculated hash value.
 */
static inline uint32_t
rte_hash_crc_8byte(uint64_t data, uint32_t init_val)
{
        if (likely(crc32_alg == CRC32_PPC64))
                return crc32c_ppc64_u64(data, init_val);

        return crc32c_2words(data, init_val);
}

#ifdef __cplusplus
}
#endif


#endif /* _RTE_CRC_PPC64_H_ */



