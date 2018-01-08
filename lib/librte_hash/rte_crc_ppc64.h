/*
 * Calculate the checksum of data that is 16 byte aligned and a multiple of
 * 16 bytes.
 *
 * The first step is to reduce it to 1024 bits. We do this in 8 parallel
 * chunks in order to mask the latency of the vpmsum instructions. If we
 * have more than 32 kB of data to checksum we repeat this step multiple
 * times, passing in the previous 1024 bits.
 *
 * The next step is to reduce the 1024 bits to 64 bits. This step adds
 * 32 bits of 0s to the end - this matches what a CRC does. We just
 * calculate constants that land the data in this 32 bits.
 *
 * We then use fixed point Barrett reduction to compute a mod n over GF(2)
 * for n = CRC using POWER8 instructions. We use x = 32.
 *
 * http://en.wikipedia.org/wiki/Barrett_reduction
 *
 * This code uses gcc vector builtins instead using assembly directly.
 *
 * Copyright (C) 2017 Rogerio Alves <rogealve@br.ibm.com>, IBM
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of either:
 *
 *  a) the GNU General Public License as published by the Free Software
 *     Foundation; either version 2 of the License, or (at your option)
 *     any later version, or
 *  b) the Apache License, Version 2.0
 */

#ifndef _RTE_CRC_PPC64_H_
#define _RTE_CRC_PPC64_H_

#include <stdint.h>
#include <rte_cpuflags.h>
#include <rte_branch_prediction.h>
#include <rte_common.h>
extern unsigned int crc32_vpmsum(unsigned int crc, unsigned char *p,
								 unsigned long len);

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

#endif
