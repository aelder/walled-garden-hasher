/*
* This uses veriations of the clhash algorithm for Verus Coin, licensed
* with the Apache-2.0 open source license.
*
* Copyright (c) 2018 Michael Toutonghi
* Distributed under the Apache 2.0 software license, available in the original form for clhash
* here: https://github.com/lemire/clhash/commit/934da700a2a54d8202929a826e2763831bd43cf7#diff-9879d6db96fd29134fc802214163b95a
*
* Original CLHash code and any portions herein, (C) 2017, 2018 Daniel Lemire and Owen Kaser
* Faster 64-bit universal hashing
* using carry-less multiplications, Journal of Cryptographic Engineering (to appear)
*
* Best used on recent x64 processors (Haswell or better).
*
* This implements an intermediate step in the last part of a Verus block hash. The intent of this step
* is to more effectively equalize FPGAs over GPUs and CPUs.
*
**/


#include "verus_clhash.h"


#include <assert.h>
#include <string.h>

#if defined(__clang__) || defined(__GNUC__)
#define VERUS_ALWAYS_INLINE static inline __attribute__((always_inline))
#else
#define VERUS_ALWAYS_INLINE static inline
#endif

#if defined(ARM) && (defined(__clang__) || defined(__GNUC__))
#define VERUS_NO_STACK_PROTECTOR __attribute__((no_stack_protector))
#else
#define VERUS_NO_STACK_PROTECTOR
#endif
//#include <intrin.h>
//#include "cpu_verushash.hpp"

#ifdef _WIN32
#define posix_memalign(p, a, s) (((*(p)) = _aligned_malloc((s), (a))), *(p) ?0 :errno)
#endif


int __cpuverusoptimized = 0x80;

// multiply the length and the some key, no modulo
__m128i lazyLengthHash(uint64_t keylength, uint64_t length) {
	const __m128i lengthvector = _mm_set_epi64x(keylength, length);
	const __m128i clprod1 = _mm_clmulepi64_si128(lengthvector, lengthvector, 0x10);
	return clprod1;
}

// modulo reduction to 64-bit value. The high 64 bits contain garbage, see precompReduction64
__m128i precompReduction64_si128(__m128i A) {

	//const __m128i C = _mm_set_epi64x(1U,(1U<<4)+(1U<<3)+(1U<<1)+(1U<<0)); // C is the irreducible poly. (64,4,3,1,0)
	const __m128i C = _mm_cvtsi64_si128((1U << 4) + (1U << 3) + (1U << 1) + (1U << 0));
	const  __m128i Q2 = _mm_clmulepi64_si128(A, C, 0x01);
#ifdef ARM
	const __m128i Q2High = vreinterpretq_m128i_u8(vextq_u8(
		vreinterpretq_u8_m128i(Q2), vdupq_n_u8(0), 8));
#else
	const __m128i Q2High = _mm_srli_si128(Q2, 8);
#endif
	const __m128i Q3 = _mm_shuffle_epi8(_mm_setr_epi8(0, 27, 54, 45, 108, 119, 90, 65, (char)216, (char)195, (char)238, (char)245, (char)180, (char)175, (char)130, (char)153),
		Q2High);
	const __m128i Q4 = _mm_xor_si128(Q2, A);
	const __m128i final = _mm_xor_si128(Q3, Q4);
	return final;/// WARNING: HIGH 64 BITS CONTAIN GARBAGE
}

uint64_t precompReduction64(__m128i A) {
	return _mm_cvtsi128_si64(precompReduction64_si128(A));
}

#ifdef ARM
VERUS_ALWAYS_INLINE
__m128i verus_mulhrs_epi16(__m128i a, __m128i b)
{
	const int16x8_t a16 = vreinterpretq_s16_m128i(a);
	const int16x8_t b16 = vreinterpretq_s16_m128i(b);
	const int16x8_t rounded = vqrdmulhq_s16(a16, b16);
	const int16x8_t minimum = vdupq_n_s16(-32768);
	const uint16x8_t both_minimum =
		vceqq_s16(vmaxq_s16(a16, b16), minimum);
	return vreinterpretq_m128i_s16(
		veorq_s16(rounded, vreinterpretq_s16_u16(both_minimum)));
}
#else
VERUS_ALWAYS_INLINE
__m128i verus_mulhrs_epi16(__m128i a, __m128i b)
{
	return _mm_mulhrs_epi16(a, b);
}
#endif

#ifdef VERUS_TESTING
extern "C" __m128i verus_test_mulhrs_epi16(__m128i a, __m128i b)
{
	return verus_mulhrs_epi16(a, b);
}
#endif

struct clhash_lane {
	__m128i *randomsource;
	uint64_t keyMask;
#ifdef ARM
	uint32_t *touched;
#else
	uint32_t *fixrand;
	uint32_t *fixrandex;
	u128 *g_prand;
	u128 *g_prandex;
#endif
	__m128i pbuf_copy[4];
	__m128i acc;
};

VERUS_ALWAYS_INLINE
void init_lane(
	clhash_lane &lane, __m128i *randomsource, const __m128i *buf,
	uint64_t keyMask, uint32_t *fixrand, uint32_t *fixrandex,
	u128 *g_prand, u128 *g_prandex)
{
	lane.randomsource = randomsource;
	lane.keyMask = keyMask;
#ifdef ARM
	lane.touched = fixrand;
	(void)fixrandex;
	(void)g_prand;
	(void)g_prandex;
#else
	lane.fixrand = fixrand;
	lane.fixrandex = fixrandex;
	lane.g_prand = g_prand;
	lane.g_prandex = g_prandex;
#endif
	lane.pbuf_copy[0] = _mm_xor_si128(buf[0], buf[2]);
	lane.pbuf_copy[1] = _mm_xor_si128(buf[1], buf[3]);
	lane.pbuf_copy[2] = buf[2];
	lane.pbuf_copy[3] = buf[3];
	lane.acc = _mm_load_si128(randomsource + (keyMask + 2));
}


// The eight CLHash step bodies, shared by the switch dispatcher and the
// wave kernel below. Bodies are exact transplants of the switch cases;
// only the dispatch around them differs.
VERUS_ALWAYS_INLINE
void clhash_case0(
	__m128i &acc, const uint64_t selector, const __m128i *pbuf,
	__m128i *prand, __m128i *prandex)
{
	const __m128i temp1 = _mm_load_si128(prandex);
	const __m128i temp2 = pbuf[(selector & 1) ? -1 : 1];
	const __m128i add1 = _mm_xor_si128(temp1, temp2);
	const __m128i clprod1 = _mm_clmulepi64_si128(add1, add1, 0x10);
	acc = _mm_xor_si128(clprod1, acc);

	const __m128i tempa1 = verus_mulhrs_epi16(acc, temp1);
	const __m128i tempa2 = _mm_xor_si128(tempa1, temp1);

	const __m128i temp12 = _mm_load_si128(prand);
	_mm_store_si128(prand, tempa2);

	const __m128i temp22 = _mm_load_si128(pbuf);
	const __m128i add12 = _mm_xor_si128(temp12, temp22);
	const __m128i clprod12 = _mm_clmulepi64_si128(add12, add12, 0x10);
	acc = _mm_xor_si128(clprod12, acc);

	const __m128i tempb1 = verus_mulhrs_epi16(acc, temp12);
	const __m128i tempb2 = _mm_xor_si128(tempb1, temp12);
	_mm_store_si128(prandex, tempb2);
}

VERUS_ALWAYS_INLINE
void clhash_case1(
	__m128i &acc, const uint64_t selector, const __m128i *pbuf,
	__m128i *prand, __m128i *prandex)
{
	const __m128i temp1 = _mm_load_si128(prand);
	const __m128i temp2 = _mm_load_si128(pbuf);
	const __m128i add1 = _mm_xor_si128(temp1, temp2);
	const __m128i clprod1 = _mm_clmulepi64_si128(add1, add1, 0x10);
	acc = _mm_xor_si128(clprod1, acc);
	const __m128i clprod2 = _mm_clmulepi64_si128(temp2, temp2, 0x10);
	acc = _mm_xor_si128(clprod2, acc);

	const __m128i tempa1 = verus_mulhrs_epi16(acc, temp1);
	const __m128i tempa2 = _mm_xor_si128(tempa1, temp1);

	const __m128i temp12 = _mm_load_si128(prandex);
	_mm_store_si128(prandex, tempa2);

	const __m128i temp22 = pbuf[(selector & 1) ? -1 : 1];
	const __m128i add12 = _mm_xor_si128(temp12, temp22);
	acc = _mm_xor_si128(add12, acc);

	const __m128i tempb1 = verus_mulhrs_epi16(acc, temp12);
	_mm_store_si128(prand,_mm_xor_si128(tempb1, temp12));
	//_mm_store_si128(prand, tempb2);
}

VERUS_ALWAYS_INLINE
void clhash_case2(
	__m128i &acc, const uint64_t selector, const __m128i *pbuf,
	__m128i *prand, __m128i *prandex)
{
	const __m128i temp1 = _mm_load_si128(prandex);
	const __m128i temp2 = _mm_load_si128(pbuf);
	const __m128i add1 = _mm_xor_si128(temp1, temp2);
	acc = _mm_xor_si128(add1, acc);

	const __m128i tempa1 = verus_mulhrs_epi16(acc, temp1);
	const __m128i tempa2 = _mm_xor_si128(tempa1, temp1);

	const __m128i temp12 = _mm_load_si128(prand);
	_mm_store_si128(prand, tempa2);

	const __m128i temp22 = pbuf[(selector & 1) ? -1 : 1];
	const __m128i add12 = _mm_xor_si128(temp12, temp22);
	const __m128i clprod12 = _mm_clmulepi64_si128(add12, add12, 0x10);
	acc = _mm_xor_si128(clprod12, acc);
	const __m128i clprod22 = _mm_clmulepi64_si128(temp22, temp22, 0x10);
	acc = _mm_xor_si128(clprod22, acc);

	const __m128i tempb1 = verus_mulhrs_epi16(acc, temp12);
	const __m128i tempb2 = _mm_xor_si128(tempb1, temp12);
	_mm_store_si128(prandex, tempb2);
}

VERUS_ALWAYS_INLINE
void clhash_case3(
	__m128i &acc, const uint64_t selector, const __m128i *pbuf,
	__m128i *prand, __m128i *prandex)
{
	const __m128i temp1 = _mm_load_si128(prand);
	const __m128i temp2 = pbuf[(selector & 1) ? -1 : 1];
	const __m128i add1 = _mm_xor_si128(temp1, temp2);

	// cannot be zero here
	const int32_t divisor = (uint32_t)selector;

	acc = _mm_xor_si128(add1, acc);

	const int64_t dividend = _mm_cvtsi128_si64(acc);
	const __m128i modulo = _mm_cvtsi32_si128(dividend % divisor);
	acc = _mm_xor_si128(modulo, acc);

	const __m128i tempa1 = verus_mulhrs_epi16(acc, temp1);
	const __m128i tempa2 = _mm_xor_si128(tempa1, temp1);

	if (dividend & 1)
	{
		const __m128i temp12 = _mm_load_si128(prandex);
		_mm_store_si128(prandex, tempa2);

		const __m128i temp22 = _mm_load_si128(pbuf);
		const __m128i add12 = _mm_xor_si128(temp12, temp22);
		const __m128i clprod12 = _mm_clmulepi64_si128(add12, add12, 0x10);
		acc = _mm_xor_si128(clprod12, acc);
		const __m128i clprod22 = _mm_clmulepi64_si128(temp22, temp22, 0x10);
		acc = _mm_xor_si128(clprod22, acc);

		const __m128i tempb1 = verus_mulhrs_epi16(acc, temp12);
		const __m128i tempb2 = _mm_xor_si128(tempb1, temp12);
		_mm_store_si128(prand, tempb2);
	}
	else
	{
		_mm_store_si128(prand, _mm_load_si128(prandex));
		_mm_store_si128(prandex, tempa2);
		acc = _mm_xor_si128(_mm_load_si128(pbuf), acc);
	}
}

VERUS_ALWAYS_INLINE
void clhash_case4(
	__m128i &acc, const uint64_t selector, const __m128i *pbuf,
	__m128i *prand, __m128i *prandex)
{
	// a few AES operations
	const __m128i *rc = prand;
	__m128i tmp;
#ifdef ARM
	// Start the random load early so a miss can overlap the AES chain.
	__m128i staged_prandex = _mm_load_si128(prandex);
	__asm__ volatile("" : "+w"(staged_prandex));
#endif

	__m128i temp1 = pbuf[(selector & 1) ? -1 : 1];
	__m128i temp2 = _mm_load_si128(pbuf);

	AES2(temp1, temp2, 0);
	MIX2(temp1, temp2);

	AES2(temp1, temp2, 4);
	MIX2(temp1, temp2);

	AES2(temp1, temp2, 8);
	MIX2(temp1, temp2);

	acc = _mm_xor_si128(temp2, _mm_xor_si128(temp1, acc));

	const __m128i tempa1 = _mm_load_si128(prand);
	const __m128i tempa2 = verus_mulhrs_epi16(acc, tempa1);

#ifdef ARM
	_mm_store_si128(prand, staged_prandex);
#else
	_mm_store_si128(prand, _mm_load_si128(prandex));
#endif
	_mm_store_si128(prandex, _mm_xor_si128(tempa1, tempa2));
}

VERUS_ALWAYS_INLINE
void clhash_case5(
	__m128i &acc, const uint64_t selector, const __m128i *pbuf,
	__m128i *prand, __m128i *prandex)
{
	// Monkins loop, restructured. No iteration reads acc except to
	// XOR into it, rc advances exactly once per iteration, and the
	// branch pattern is selector bits [28 .. 28+r0] MSB-first — all
	// known at step entry. So the data-dependent per-iteration
	// branch is replaced by two mask-driven loops (carry-less and
	// AES iterations), every contribution is computed independently,
	// and the results fold into acc with the same XOR set the
	// original serial loop produced. Iteration j (original rounds
	// value r0 - j) reads key vector prand[j]; the AES iteration
	// with ordinal a additionally reads round keys
	// prand[j + 1 + 4a .. j + 4 + 4a], matching the original
	// rc/aesroundoffset walk.
	const __m128i *buftmp = &pbuf[(selector & 1) ? -1 : 1];

	const uint64_t r0 = selector >> 61; // iterations = r0 + 1 (1..8)
	const uint64_t lanecount = r0 + 1;
	const uint64_t field = (selector >> 28) & ((1ULL << lanecount) - 1);
	// clmask bit j = selector bit (28 + r0 - j): reverse the field.
	const uint64_t clmask =
		__builtin_bitreverse64(field) >> (64 - lanecount);
	const uint64_t aesmask = ~clmask & ((1ULL << lanecount) - 1);

	__m128i fold_cl = _mm_setzero_si128();
	for (uint64_t m = clmask; m; m &= (m - 1))
	{
		const uint64_t j = __builtin_ctzll(m);
		const __m128i temp2 =
			_mm_load_si128(((r0 ^ j) & 1) ? pbuf : buftmp);
		const __m128i add1 = _mm_xor_si128(prand[j], temp2);
		const __m128i clprod1 =
			_mm_clmulepi64_si128(add1, add1, 0x10);
		fold_cl = _mm_xor_si128(fold_cl, clprod1);
	}

	__m128i fold_aes = _mm_setzero_si128();
	uint64_t keyoff = 1; // 1 + 4 * (AES ordinal)
	for (uint64_t m = aesmask; m; m &= (m - 1))
	{
		const uint64_t j = __builtin_ctzll(m);
		const __m128i *keys = prand + j + keyoff;
		__m128i onekey = prand[j];
		__m128i temp2 =
			_mm_load_si128(((r0 ^ j) & 1) ? buftmp : pbuf);
		onekey = _mm_aesenc_si128(onekey, keys[0]);
		temp2 = _mm_aesenc_si128(temp2, keys[1]);
		onekey = _mm_aesenc_si128(onekey, keys[2]);
		temp2 = _mm_aesenc_si128(temp2, keys[3]);
		const __m128i mixed_lo = _mm_unpacklo_epi32(onekey, temp2);
		const __m128i mixed_hi = _mm_unpackhi_epi32(onekey, temp2);
		fold_aes = _mm_xor_si128(
			fold_aes, _mm_xor_si128(mixed_lo, mixed_hi));
		keyoff += 4;
	}

	acc = _mm_xor_si128(acc, _mm_xor_si128(fold_cl, fold_aes));

	const __m128i tempa1 = _mm_load_si128(prand);
	const __m128i tempa2 = verus_mulhrs_epi16(acc, tempa1);
	const __m128i tempa3 = _mm_xor_si128(tempa1, tempa2);

	const __m128i tempa4 = _mm_load_si128(prandex);
	_mm_store_si128(prandex, tempa3);
	_mm_store_si128(prand, tempa4);
}

VERUS_ALWAYS_INLINE
void clhash_case6(
	__m128i &acc, const uint64_t selector, const __m128i *pbuf,
	__m128i *prand, __m128i *prandex)
{
	const __m128i *buftmp = &pbuf[(selector & 1) ? -1 : 1];
	__m128i tmp; // used by MIX2

	uint64_t rounds = selector >> 61; // loop randomly between 1 and 8 times
	__m128i *rc = prand;
	__m128i onekey;

	do
	{
		if (selector & (((uint64_t)0x10000000) << rounds))
		{
			//	onekey = _mm_load_si128(rc++);
			const __m128i temp2 = _mm_load_si128(rounds & 1 ? pbuf : buftmp);
			onekey = _mm_xor_si128(rc[0], temp2); rc++;
			// cannot be zero here, may be negative
			const int32_t divisor = (uint32_t)selector;
			const int64_t dividend = _mm_cvtsi128_si64(onekey);
			const __m128i modulo = _mm_cvtsi32_si128(dividend % divisor);
			acc = _mm_xor_si128(modulo, acc);
		}
		else
		{
			//	onekey = _mm_load_si128(rc++);
			__m128i temp2 = _mm_load_si128(rounds & 1 ? buftmp : pbuf);
			const __m128i add1 = _mm_xor_si128(rc[0], temp2); rc++;
			onekey = _mm_clmulepi64_si128(add1, add1, 0x10);
			const __m128i clprod2 = verus_mulhrs_epi16(acc, onekey);
			acc = _mm_xor_si128(clprod2, acc);
		}
	} while (rounds--);

	const __m128i tempa3 = _mm_load_si128(prandex);

	_mm_store_si128(prandex, onekey);
	_mm_store_si128(prand, _mm_xor_si128(tempa3, acc));
	//	_mm_store_si128(prand, tempa4);
}

VERUS_ALWAYS_INLINE
void clhash_case7(
	__m128i &acc, const uint64_t selector, const __m128i *pbuf,
	__m128i *prand, __m128i *prandex)
{
	const __m128i temp1 = _mm_load_si128(pbuf);
	const __m128i temp2 = _mm_load_si128(prandex);
	const __m128i add1 = _mm_xor_si128(temp1, temp2);
	const __m128i clprod1 = _mm_clmulepi64_si128(add1, add1, 0x10);
	acc = _mm_xor_si128(clprod1, acc);

	const __m128i tempa1 = verus_mulhrs_epi16(acc, temp2);
	const __m128i tempa2 = _mm_xor_si128(tempa1, temp2);

	const __m128i tempa3 = _mm_load_si128(prand);
	_mm_store_si128(prand, tempa2);

	acc = _mm_xor_si128(tempa3, acc);
	const __m128i temp4 = pbuf[(selector & 1) ? -1 : 1];
	acc = _mm_xor_si128(temp4, acc);
	const __m128i tempb1 = verus_mulhrs_epi16(acc, tempa3);
	*prandex = _mm_xor_si128(tempb1, tempa3);
	//	_mm_store_si128(prandex, tempb2);
}

VERUS_ALWAYS_INLINE
void clhash_step(clhash_lane &lane, int64_t i)
{
	__m128i *randomsource = lane.randomsource;
	const uint64_t keyMask = lane.keyMask;
#ifdef ARM
	uint32_t *touched = lane.touched;
#else
	uint32_t *fixrand = lane.fixrand;
	uint32_t *fixrandex = lane.fixrandex;
	u128 *g_prand = lane.g_prand;
	u128 *g_prandex = lane.g_prandex;
#endif
	const __m128i *pbuf_copy = lane.pbuf_copy;
	__m128i &acc = lane.acc;
	const __m128i *pbuf;

		const uint64_t selector = _mm_cvtsi128_si64(acc);

		uint32_t prand_idx = (selector >> 5) & keyMask;
		uint32_t prandex_idx = (selector >> 32) & keyMask;
		// get two random locations in the key, which will be mutated and swapped
		__m128i *prand = randomsource + prand_idx;
		__m128i *prandex = randomsource + prandex_idx;

		// select random start and order of pbuf processing
		pbuf = pbuf_copy + (selector & 3);
#ifdef ARM
		touched[i] = prand_idx | (prandex_idx << 16);
#else
		_mm_store_si128(&g_prand[i], prand[0]);
		_mm_store_si128(&g_prandex[i], prandex[0]);
		fixrand[i] = prand_idx;
		fixrandex[i] = prandex_idx;
#endif

		switch ((selector >> 2) & 7)
		{
		case 0:
			clhash_case0(acc, selector, pbuf, prand, prandex);
			break;
		case 1:
			clhash_case1(acc, selector, pbuf, prand, prandex);
			break;
		case 2:
			clhash_case2(acc, selector, pbuf, prand, prandex);
			break;
		case 3:
			clhash_case3(acc, selector, pbuf, prand, prandex);
			break;
		case 4:
			clhash_case4(acc, selector, pbuf, prand, prandex);
			break;
		case 5:
			clhash_case5(acc, selector, pbuf, prand, prandex);
			break;
		case 6:
			clhash_case6(acc, selector, pbuf, prand, prandex);
			break;
		case 7:
			clhash_case7(acc, selector, pbuf, prand, prandex);
			break;
		}
}

__m128i __verusclmulwithoutreduction64alignedrepeatv2_2(
	__m128i *randomsource, const __m128i *buf, uint64_t keyMask,
	uint32_t *fixrand, uint32_t *fixrandex, u128 *g_prand, u128 *g_prandex)
{
	clhash_lane lane;
	init_lane(
		lane, randomsource, buf, keyMask, fixrand, fixrandex,
		g_prand, g_prandex);
	for (int64_t i = 0; i < 32; ++i)
		clhash_step(lane, i);
	return lane.acc;
}

// hashes 64 bytes only by doing a carryless multiplication and reduction of the repeated 64 byte sequence 16 times,
// returning a 64 bit hash value

VERUS_NO_STACK_PROTECTOR
uint64_t verusclhashv2_2(void * random, const unsigned char buf[64], uint64_t keyMask, uint32_t *fixrand, uint32_t *fixrandex,
	u128 *g_prand, u128 *g_prandex) {
	__m128i  acc = __verusclmulwithoutreduction64alignedrepeatv2_2((__m128i *)random, (const __m128i *)buf, 511, fixrand, fixrandex, g_prand, g_prandex);
	acc = _mm_xor_si128(acc, _mm_cvtsi64_si128(0x10000));


	return precompReduction64(acc);
}

#ifdef ARM
extern "C" VERUS_NO_STACK_PROTECTOR void verusclhashv2_2_dual(
	void *__restrict random0, const unsigned char *__restrict buf0,
	uint32_t *__restrict touched0,
	void *__restrict random1, const unsigned char *__restrict buf1,
	uint32_t *__restrict touched1, uint64_t *__restrict out)
{
	clhash_lane lane0;
	clhash_lane lane1;
	init_lane(
		lane0, (__m128i *) random0, (const __m128i *) buf0, 511,
		touched0, NULL, NULL, NULL);
	init_lane(
		lane1, (__m128i *) random1, (const __m128i *) buf1, 511,
		touched1, NULL, NULL, NULL);

	for (int64_t i = 0; i < 32; ++i) {
		clhash_step(lane0, i);
		clhash_step(lane1, i);
	}

	const __m128i length_hash = _mm_cvtsi64_si128(0x10000);
	out[0] = precompReduction64(_mm_xor_si128(lane0.acc, length_hash));
	out[1] = precompReduction64(_mm_xor_si128(lane1.acc, length_hash));
}


extern "C" VERUS_NO_STACK_PROTECTOR void verusclhashv2_2_wave(
	void *const *randoms, const unsigned char *const *bufs,
	uint32_t *const *touched, uint64_t *out, int nlanes)
{
	// N hashes advance in lockstep, one CLHash step per wave, executed in
	// case-grouped order. The mechanism was isolated at +35% single-thread
	// (sorted versus identity order at 32 lanes), so the structure earns
	// its keep only if its own overhead stays small:
	//  - Lane buckets are built by each step's tail (double-buffered per
	//    wave parity), so there is no sort pass at all.
	//  - The case dispatch is hoisted out of the run: one switch per
	//    distinct case per wave, with a plain counted loop over that
	//    case's lanes inside. Within a run there is no indirect branch,
	//    no jump-table load, and no order[] indirection.
	//  - Empty buckets are skipped by a ctz walk over a nonempty mask, so
	//    a wave costs one hoisted dispatch per distinct case (~5.2 of 8 at
	//    32 lanes, ~0.2 mispredicts per step against ~0.875 for the dual
	//    kernel's per-step random dispatch).
	//  - Each tail prefetches the lane's next two random key vectors plus
	//    two following lines of the prand neighborhood (cases 5/6 walk up
	//    to 40 vectors from prand), a full wave ahead of use, so the
	//    enlarged working set rides L2 without stalling the bodies.
	// Lane contexts are memory-resident by design: the only registers live
	// across dispatch joins are loop bookkeeping, which is what keeps the
	// register allocator from spilling (the failure mode that killed the
	// label-threaded experiment). Per-lane dataflow is bit-identical to
	// the scalar/dual kernels.
	struct wave_ctx {
		__m128i pbuf_copy[4];
		__m128i acc;
		uint64_t sel;
		__m128i *key;
		uint32_t *touched;
	};

	wave_ctx ctx[VERUS_WAVE_MAX_LANES];
	uint8_t buckets[2][8][VERUS_WAVE_MAX_LANES];
	uint8_t bucklen[2][8];

	if (nlanes < 2)
		nlanes = 2;
	if (nlanes > VERUS_WAVE_MAX_LANES)
		nlanes = VERUS_WAVE_MAX_LANES;
	const int n = nlanes;

	for (int c = 0; c < 8; ++c)
	{
		bucklen[0][c] = 0;
		bucklen[1][c] = 0;
	}
	uint32_t nonempty[2] = {0, 0};

	for (int l = 0; l < n; ++l)
	{
		wave_ctx &c = ctx[l];
		const __m128i *buf = (const __m128i *)bufs[l];
		c.key = (__m128i *)randoms[l];
		c.touched = touched[l];
		c.pbuf_copy[0] = _mm_xor_si128(buf[0], buf[2]);
		c.pbuf_copy[1] = _mm_xor_si128(buf[1], buf[3]);
		c.pbuf_copy[2] = buf[2];
		c.pbuf_copy[3] = buf[3];
		c.acc = _mm_load_si128(c.key + 513);
		c.sel = (uint64_t)_mm_cvtsi128_si64(c.acc);
		const uint32_t cs = (uint32_t)((c.sel >> 2) & 7);
		buckets[0][cs][bucklen[0][cs]++] = (uint8_t)l;
		nonempty[0] |= (1u << cs);
		__builtin_prefetch(c.key + ((c.sel >> 5) & 511), 1, 3);
		__builtin_prefetch(c.key + ((c.sel >> 32) & 511), 1, 3);
	}

	for (int step = 0; step < 32; ++step)
	{
		const int par = step & 1;
		const int nxt = par ^ 1;

		// One hoisted dispatch per distinct case; a plain counted loop
		// runs that case's lanes back to back.
		for (uint32_t mask = nonempty[par]; mask; mask &= (mask - 1))
		{
			const int cs = __builtin_ctz(mask);
			const uint8_t *lanes = buckets[par][cs];
			const int cnt = bucklen[par][cs];

#define VERUS_WAVE_RUN(CASEFN) \
			for (int j = 0; j < cnt; ++j) \
			{ \
				wave_ctx &c = ctx[lanes[j]]; \
				const uint64_t selector = c.sel; \
				const uint32_t prand_idx = \
					(uint32_t)((selector >> 5) & 511); \
				const uint32_t prandex_idx = \
					(uint32_t)((selector >> 32) & 511); \
				c.touched[step] = prand_idx | (prandex_idx << 16); \
				__m128i *prand = c.key + prand_idx; \
				__m128i *prandex = c.key + prandex_idx; \
				const __m128i *pbuf = c.pbuf_copy + (selector & 3); \
				__m128i acc = c.acc; \
				CASEFN(acc, selector, pbuf, prand, prandex); \
				c.acc = acc; \
				const uint64_t nsel = \
					(uint64_t)_mm_cvtsi128_si64(acc); \
				c.sel = nsel; \
				const uint32_t ncs = (uint32_t)((nsel >> 2) & 7); \
				buckets[nxt][ncs][bucklen[nxt][ncs]++] = lanes[j]; \
				nonempty[nxt] |= (1u << ncs); \
				__m128i *nprand = c.key + ((nsel >> 5) & 511); \
				/* Deep prand prefetch only when the next case walks rc \
				 * (5/6); otherwise re-touch line 0 (LSU dedupes) so the \
				 * multi-thread bandwidth cost stays proportional. */ \
				const uint64_t walk = \
					((ncs == 5) | (ncs == 6)) ? 128 : 0; \
				__builtin_prefetch(nprand, 1, 3); \
				__builtin_prefetch((const char *)nprand + walk, 0, 3); \
				__builtin_prefetch( \
					(const char *)nprand + 2 * walk, 0, 3); \
				__builtin_prefetch(c.key + ((nsel >> 32) & 511), 1, 3); \
			}

			switch (cs)
			{
			case 0:
				VERUS_WAVE_RUN(clhash_case0)
				break;
			case 1:
				VERUS_WAVE_RUN(clhash_case1)
				break;
			case 2:
				VERUS_WAVE_RUN(clhash_case2)
				break;
			case 3:
				VERUS_WAVE_RUN(clhash_case3)
				break;
			case 4:
				VERUS_WAVE_RUN(clhash_case4)
				break;
			case 5:
				VERUS_WAVE_RUN(clhash_case5)
				break;
			case 6:
				VERUS_WAVE_RUN(clhash_case6)
				break;
			case 7:
				VERUS_WAVE_RUN(clhash_case7)
				break;
			}
#undef VERUS_WAVE_RUN
		}

		// Reset consumed buckets for reuse two waves from now.
		for (int c = 0; c < 8; ++c)
			bucklen[par][c] = 0;
		nonempty[par] = 0;
	}

	const __m128i length_hash = _mm_cvtsi64_si128(0x10000);
	for (int l = 0; l < n; ++l)
		out[l] = precompReduction64(
			_mm_xor_si128(ctx[l].acc, length_hash));
}

#endif
