// Haraka256 / Haraka512 for AArch64 (§5).
//
// Three things separate this from a translated-intrinsics build:
//
//  1. Chains are fused. ARM's AESE takes the key first, so an N-round x86
//     chain is N AESE+AESMC pairs and ONE trailing EOR, not N EORs.
//  2. AESE and AESMC are emitted adjacent with matching operands, which is
//     the only way the core fuses them into the 3-cycle, 4/cycle pair.
//  3. Where the round keys are compile-time constants, the trailing key XOR
//     is pushed through the MIX permutation (which is linear) and absorbed
//     into the next group's AESE, so it costs nothing at all.
#pragma once

#include "vh22/arch.h"
#include "vh22/haraka_tables.h"

#include <string.h>

namespace vh22 {

VH_INLINE v128 rc_const(int i)
{
	return vreinterpretq_u8_u32(vld1q_u32(kHarakaRC[i]));
}
VH_INLINE v128 rc_absorb256(int g, int j)
{
	return vreinterpretq_u8_u32(vld1q_u32(kHaraka256Absorb[g][j]));
}

// --- Haraka256: 5 groups of AES2 + MIX2, then feed-forward ----------------
//
// Used only for key expansion, which runs once per block template. Full key
// absorption applies because every round constant is fixed.
VH_INLINE void haraka256(uint8_t out[32], const uint8_t in[32])
{
	const v128 in0 = vload(in), in1 = vload(in + 16);
	v128 s0 = in0, s1 = in1;

	// Group 0 starts from a zero key; later groups start from the previous
	// group's deferred (and MIX2-permuted) constants.
	s0 = aes_round(aes_begin(s0), rc_const(0));
	s1 = aes_round(aes_begin(s1), rc_const(1));
	for (int g = 1; g < 5; ++g) {
		const v128 m0 = vzip1_32(s0, s1);
		const v128 m1 = vzip2_32(s0, s1);
		s0 = aes_round(aes_round(m0, rc_absorb256(g - 1, 0)), rc_const(4 * g + 0));
		s1 = aes_round(aes_round(m1, rc_absorb256(g - 1, 1)), rc_const(4 * g + 1));
	}
	const v128 m0 = vzip1_32(s0, s1);
	const v128 m1 = vzip2_32(s0, s1);

	vstore(out, vxor3(m0, rc_absorb256(4, 0), in0));
	vstore(out + 16, vxor3(m1, rc_absorb256(4, 1), in1));
}

// --- Haraka512 ------------------------------------------------------------
//
// The hot instance is keyed: its 40 "round constants" are read out of the
// mutated key at a nonce-dependent offset, so nothing can be folded ahead of
// time and each group ends with one real EOR.

VH_INLINE void haraka512_mix4(v128 &s0, v128 &s1, v128 &s2, v128 &s3)
{
	const v128 tmp = vzip1_32(s0, s1);
	const v128 a = vzip2_32(s0, s1);
	const v128 b = vzip1_32(s2, s3);
	const v128 c = vzip2_32(s2, s3);
	s3 = vzip1_32(a, c);
	s0 = vzip2_32(a, c);
	s2 = vzip2_32(b, tmp);
	s1 = vzip1_32(b, tmp);
}

VH_INLINE void haraka512_keyed(uint8_t out[32], const uint8_t in[64], const v128 *rc)
{
	v128 s0 = vload(in), s1 = vload(in + 16), s2 = vload(in + 32), s3 = vload(in + 48);

	// §5 free tail: only b[8:16] || b[24:32] || b[32:40] || b[48:56] survives
	// the truncation, and ZIP distributes over the feed-forward XOR. Building
	// the two surviving input halves up front turns the tail into 2 ZIP + 2
	// EOR instead of 4 EOR + 2 ZIP, off the critical path.
	const v128 ff0 = vzip2_64(s0, s1);
	const v128 ff1 = vzip1_64(s2, s3);

	for (int g = 0; g < 5; ++g) {
		const v128 *k = rc + 8 * g;
		s0 = aes2_fused(s0, k[0], k[4]);
		s1 = aes2_fused(s1, k[1], k[5]);
		s2 = aes2_fused(s2, k[2], k[6]);
		s3 = aes2_fused(s3, k[3], k[7]);
		haraka512_mix4(s0, s1, s2, s3);
	}

	vstore(out, vxor(vzip2_64(s0, s1), ff0));
	vstore(out + 16, vxor(vzip1_64(s2, s3), ff1));
}

// The share pre-filter. Only bytes 28..31 of the digest are needed to reject a
// nonce, and they come from exactly one lane of the last round: after the
// final MIX4, out[28:32] is s3'[4:8] = s2[8:12] taken before that MIX4. So the
// last group needs one lane instead of four, and the last MIX4 collapses to
// three ZIPs. 34 AES rounds instead of 40, and no truncation or store at all.
VH_INLINE uint32_t haraka512_keyed_highword(const uint8_t in[64], const v128 *rc)
{
	v128 s0 = vload(in), s1 = vload(in + 16), s2 = vload(in + 32), s3 = vload(in + 48);

	for (int g = 0; g < 4; ++g) {
		const v128 *k = rc + 8 * g;
		s0 = aes2_fused(s0, k[0], k[4]);
		s1 = aes2_fused(s1, k[1], k[5]);
		s2 = aes2_fused(s2, k[2], k[6]);
		s3 = aes2_fused(s3, k[3], k[7]);
		if (g < 3) {
			haraka512_mix4(s0, s1, s2, s3);
		} else {
			const v128 tmp = vzip1_32(s0, s1);
			const v128 b = vzip1_32(s2, s3);
			s2 = vzip2_32(b, tmp);
		}
	}
	s2 = aes2_fused(s2, rc[34], rc[38]);

	// Word 2 straight out of the vector register -- one UMOV, no spill.
	const uint32_t state_word = vgetq_lane_u32(vreinterpretq_u32_u8(s2), 2);
	uint32_t input_word;
	memcpy(&input_word, in + 52, 4);
	return state_word ^ input_word;
}

// The fixed round constants viewed as vectors. The table is alignas(16) and
// uint32_t words in memory order, which is bit-identical to the x86 register.
VH_INLINE const v128 *haraka_rc_vectors()
{
	return reinterpret_cast<const v128 *>(&kHarakaRC[0][0]);
}

VH_INLINE void haraka512(uint8_t out[32], const uint8_t in[64])
{
	haraka512_keyed(out, in, haraka_rc_vectors());
}

} // namespace vh22
