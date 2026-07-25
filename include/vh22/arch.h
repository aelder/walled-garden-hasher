// vh22 — native AArch64 VerusHash 2.2
//
// Architecture layer: every NEON primitive the algorithm needs, mapped
// directly onto the instruction we actually want. No sse2neon anywhere.
//
// Section numbers in comments refer to the Apple Silicon port notes.
#pragma once

#if !defined(__aarch64__)
#  error "vh22 targets AArch64 only"
#endif

// §1 — the fast path must be compiled in. __ARM_FEATURE_CRYPTO is deprecated
// and some toolchain/flag combinations define only the split macros, so gate
// on __ARM_FEATURE_AES and never on CRYPTO.
#if !defined(__ARM_FEATURE_AES)
#  error "AES extension not enabled - build with -mcpu=apple-m1 (or later) / -mcpu=native"
#endif
#if !defined(__ARM_NEON)
#  error "NEON not enabled"
#endif

#include <arm_neon.h>
#include <stddef.h>
#include <stdint.h>

#define VH_INLINE static inline __attribute__((always_inline))

namespace vh22 {

// One 128-bit vector. Carried as uint8x16_t because that is what AESE/AESMC
// and TBL want; everything else reinterprets, which is free.
using v128 = uint8x16_t;

VH_INLINE v128 vzero() { return vdupq_n_u8(0); }
VH_INLINE v128 vload(const void *p) { return vld1q_u8((const uint8_t *)p); }
VH_INLINE void vstore(void *p, v128 x) { vst1q_u8((uint8_t *)p, x); }
VH_INLINE v128 vxor(v128 a, v128 b) { return veorq_u8(a, b); }
VH_INLINE v128 vxor3(v128 a, v128 b, v128 c) { return veorq_u8(a, veorq_u8(b, c)); }

VH_INLINE uint64_t vlow64(v128 a) { return vgetq_lane_u64(vreinterpretq_u64_u8(a), 0); }
VH_INLINE uint64_t vhigh64(v128 a) { return vgetq_lane_u64(vreinterpretq_u64_u8(a), 1); }

// _mm_cvtsi32_si128: 32-bit value in the low lane, everything above zeroed.
VH_INLINE v128 vfrom_u32(uint32_t x)
{
	return vreinterpretq_u8_u32(vsetq_lane_u32(x, vdupq_n_u32(0), 0));
}
VH_INLINE v128 vfrom_u64(uint64_t x)
{
	return vreinterpretq_u8_u64(vsetq_lane_u64(x, vdupq_n_u64(0), 0));
}

// EXT #8: [hi, lo]. The swapped duplicate the clmul below needs (§3).
VH_INLINE v128 vswap64(v128 a) { return vextq_u8(a, a, 8); }

// _mm_unpacklo/hi — exact ZIP1/ZIP2 equivalents (§2).
VH_INLINE v128 vzip1_32(v128 a, v128 b)
{
	return vreinterpretq_u8_u32(vzip1q_u32(vreinterpretq_u32_u8(a), vreinterpretq_u32_u8(b)));
}
VH_INLINE v128 vzip2_32(v128 a, v128 b)
{
	return vreinterpretq_u8_u32(vzip2q_u32(vreinterpretq_u32_u8(a), vreinterpretq_u32_u8(b)));
}
VH_INLINE v128 vzip1_64(v128 a, v128 b)
{
	return vreinterpretq_u8_u64(vzip1q_u64(vreinterpretq_u64_u8(a), vreinterpretq_u64_u8(b)));
}
VH_INLINE v128 vzip2_64(v128 a, v128 b)
{
	return vreinterpretq_u8_u64(vzip2q_u64(vreinterpretq_u64_u8(a), vreinterpretq_u64_u8(b)));
}

// §3 — carry-less multiply. VerusHash only ever wants CL(v) = v_lo (x) v_hi.
// x86 selects both halves with one immediate; NEON needs an EXT first because
// PMULL takes the low half of both operands.
//
// Left to itself clang rewrites EXT+PMULL into DUP+PMULL2. The port notes say
// not to let it: PMULL2 is 5-6 cycles at 2/cycle against PMULL's 3 at 4/cycle
// on Firestorm, and this sits on the hottest dependency chain in the algorithm.
//
// MEASURED OTHERWISE ON M5. Forcing PMULL via asm is consistently *slower*
// here, at every point from the latency-bound single stream to the
// throughput-bound 64-lane wave (1 thread, 10 s, interleaved runs to cancel
// thermal drift):
//
//     lanes    DUP+PMULL2      EXT+PMULL     delta
//     scalar   2166 kH/s       2150 kH/s     +0.7%
//     4        2859 kH/s       2850 kH/s     +0.3%
//     16       4124 kH/s       4094 kH/s     +0.7%
//     64       4405 kH/s       4290 kH/s     +2.6%
//
// The notes are explicit that their timings are M1-era and must be re-measured,
// and this is one of the places that has changed. Both forms are two
// instructions; whatever the M1 penalty was, it is gone, and the DUP form
// schedules better as lane count rises. So clang's choice stands.
//
// Build with -DVH22_PMULL_ASM=1 to pin the encoding and re-check on other
// silicon -- do not assume either answer.
#ifndef VH22_PMULL_ASM
#define VH22_PMULL_ASM 0
#endif

VH_INLINE v128 vclmul_lo(v128 a, v128 b)
{
#if VH22_PMULL_ASM
	v128 r;
	__asm__("pmull %0.1q, %1.1d, %2.1d" : "=w"(r) : "w"(a), "w"(b));
	return r;
#else
	const poly64_t x = (poly64_t)vgetq_lane_u64(vreinterpretq_u64_u8(a), 0);
	const poly64_t y = (poly64_t)vgetq_lane_u64(vreinterpretq_u64_u8(b), 0);
	return vreinterpretq_u8_p128(vmull_p64(x, y));
#endif
}

// CL(v) — the only clmul shape in the algorithm.
VH_INLINE v128 vclmul_self(v128 v) { return vclmul_lo(v, vswap64(v)); }

// CL(a ^ b) with b's swapped form already in hand. EXT(a^b) = EXT(a)^EXT(b),
// so this trades one EXT of the combined value for one EXT of the varying
// operand — same instruction count, but the two EORs are independent and the
// swap starts as soon as `a` lands instead of waiting on the XOR.
VH_INLINE v128 vclmul_self_preswapped(v128 a, v128 b, v128 b_swapped)
{
	return vclmul_lo(vxor(a, b), vxor(vswap64(a), b_swapped));
}

// §4 — _mm_mulhrs_epi16 maps to a single SQRDMULH.
//
//   PMULHRSW: r = (ab + 2^14) >> 15
//   SQRDMULH: r = sat((2ab + 2^15) >> 16)
//
// Algebraically identical; they diverge only at a = b = -32768, where the true
// value +32768 wraps to 0x8000 on x86 and saturates to 0x7FFF on ARM.
// sse2neon refuses the mapping entirely and emits 2x SMULL + 2x RSHRN +
// combine, roughly 5 ops and ~8 cycles where one instruction and 3 will do.
VH_INLINE v128 vmulhrs_fast(v128 a, v128 b)
{
	return vreinterpretq_u8_s16(
		vqrdmulhq_s16(vreinterpretq_s16_u8(a), vreinterpretq_s16_u8(b)));
}

// The exact form, for the reference path and for re-checking a candidate.
// -32768 is the minimum representable int16, so max(a,b) == -32768 holds
// exactly when both lanes are -32768; 0x7FFF ^ 0xFFFF = 0x8000 supplies the
// x86 wrap.
VH_INLINE v128 vmulhrs_exact(v128 a, v128 b)
{
	const int16x8_t x = vreinterpretq_s16_u8(a);
	const int16x8_t y = vreinterpretq_s16_u8(b);
	const int16x8_t rounded = vqrdmulhq_s16(x, y);
	const uint16x8_t both_min = vceqq_s16(vmaxq_s16(x, y), vdupq_n_s16(-32768));
	return vreinterpretq_u8_s16(veorq_s16(rounded, vreinterpretq_s16_u16(both_min)));
}

// §9 — TBL, not PSHUFB-with-a-mask. The two differ only in out-of-range
// handling (PSHUFB zeroes on the high bit, TBL on index >= 16). Every index
// this is used with is provably in [0,15] (see clhash.cpp), so sse2neon's
// defensive AND #0x8F is pure overhead.
VH_INLINE v128 vtbl16(v128 table, v128 idx) { return vqtbl1q_u8(table, idx); }

// §5 — Haraka on ARM.
//
//   x86  AESENC(x, k) = MC(SB(SR(x))) ^ k      key XOR last
//   ARM  AESE(x, k)   = SB(SR(x ^ k))          key XOR first
//
// So an N-round x86 chain is N AESE+AESMC pairs plus ONE trailing EOR, with
// each round key absorbed into the following round's AESE. sse2neon translates
// each _mm_aesenc_si128 independently and therefore emits a zero-key AESE plus
// a separate EOR every single round.
//
// Keep AESE and AESMC adjacent with matching operands or Firestorm will not
// fuse them into the 3-cycle, 4/cycle pair. clang mostly cooperates, but under
// register pressure it will hoist a round-key load between the two -- see
// tools/audit-disas.py, which counts exactly this.
//
// Pinning the pair together also stops clang scheduling across the block, so
// it is not an obvious win. Measured on M5 at 64 lanes, 1 thread, interleaved
// runs: 4419 kH/s pinned against 4370 kH/s free, +1.1%, consistent in
// direction across five paired comparisons at 8 s, 10 s and 30 s. It also
// takes the broken-pair count in the finalisation Haraka from 5 to 0.
//
// Build with -DVH22_AES_ASM=0 to hand the scheduling back to clang.
#ifndef VH22_AES_ASM
#define VH22_AES_ASM 1
#endif

VH_INLINE v128 aes_begin(v128 s)
{
#if VH22_AES_ASM
	__asm__("aese %0.16b, %1.16b\n\taesmc %0.16b, %0.16b" : "+w"(s) : "w"(vzero()));
	return s;
#else
	return vaesmcq_u8(vaeseq_u8(s, vzero()));
#endif
}

VH_INLINE v128 aes_round(v128 s, v128 k)
{
#if VH22_AES_ASM
	__asm__("aese %0.16b, %1.16b\n\taesmc %0.16b, %0.16b" : "+w"(s) : "w"(k));
	return s;
#else
	return vaesmcq_u8(vaeseq_u8(s, k));
#endif
}

// Two chained x86 AESENCs with keys ka then kb: 2 AESE + 2 AESMC + 1 EOR,
// against sse2neon's 2 AESE + 2 AESMC + 2 EOR, and with the pairing guaranteed.
VH_INLINE v128 aes2_fused(v128 s, v128 ka, v128 kb)
{
	return vxor(aes_round(aes_begin(s), ka), kb);
}

// A single x86 AESENC, for the places where the chain really is length one.
VH_INLINE v128 aesenc(v128 s, v128 k) { return vxor(aes_begin(s), k); }

} // namespace vh22
