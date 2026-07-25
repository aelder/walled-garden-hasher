// The eight CLHash step bodies.
//
// Every body is bit-exact against ref/ref.cpp; the differential harness is
// what makes that a claim rather than a hope. Two of them are restructured
// rather than transcribed -- see cases 5 and 6.
//
// Templated on `Exact` so the same source produces both the mining kernel
// (bare SQRDMULH) and the verification kernel (SQRDMULH plus the x86 wrap
// fixup). See §4 and vh22/verushash.h for why the fast path can be bare.
#pragma once

#include "vh22/arch.h"
#include "vh22/haraka.h"

// Case 3 branches on `dividend & 1`, a coin flip the bucketed dispatch cannot
// reach. See the body for the store-order subtlety this has to preserve.
#ifndef VH22_CASE3_BRANCHLESS
#define VH22_CASE3_BRANCHLESS 1
#endif

// Case 6's loop runs 1..8 times, drawn from the top three selector bits, so
// its exit branch is unpredictable too. See the body.
#ifndef VH22_CASE6_FIXED
#define VH22_CASE6_FIXED 0
#endif

namespace vh22 {

// Per-hash loop invariants. pbuf is the classic pbuf_copy[4]; clprod is the
// new part -- CL() of each of those four vectors, which cases 1, 2 and 3 would
// otherwise recompute inside the walk.
struct StepConst {
	v128 pbuf[4];
	v128 clprod[4];
};

namespace detail {

template <bool Exact>
VH_INLINE v128 mhrs(v128 a, v128 b)
{
	if constexpr (Exact)
		return vmulhrs_exact(a, b);
	else
		return vmulhrs_fast(a, b);
}

// pbuf_copy + (selector & 3) is the walk's base; the "other" buffer, written
// pbuf[-1] or pbuf[+1] depending on selector's low bit, is always the base
// index with bit 0 flipped. Both stay inside pbuf_copy[0..3].
VH_INLINE int base_of(uint64_t selector) { return (int)(selector & 3); }

template <bool Exact>
VH_INLINE void case0(v128 &acc, uint64_t selector, const StepConst &k, v128 *prand,
                     v128 *prandex)
{
	const int b = base_of(selector);
	const v128 temp1 = vload(prandex);
	const v128 temp2 = k.pbuf[b ^ 1];
	acc = vxor(vclmul_self(vxor(temp1, temp2)), acc);

	const v128 tempa2 = vxor(mhrs<Exact>(acc, temp1), temp1);
	const v128 temp12 = vload(prand);
	vstore(prand, tempa2);

	const v128 temp22 = k.pbuf[b];
	acc = vxor(vclmul_self(vxor(temp12, temp22)), acc);
	vstore(prandex, vxor(mhrs<Exact>(acc, temp12), temp12));
}

template <bool Exact>
VH_INLINE void case1(v128 &acc, uint64_t selector, const StepConst &k, v128 *prand,
                     v128 *prandex)
{
	const int b = base_of(selector);
	const v128 temp1 = vload(prand);
	const v128 temp2 = k.pbuf[b];
	acc = vxor(vclmul_self(vxor(temp1, temp2)), acc);
	acc = vxor(k.clprod[b], acc);  // CL(temp2): loop-invariant, precomputed

	const v128 tempa2 = vxor(mhrs<Exact>(acc, temp1), temp1);
	const v128 temp12 = vload(prandex);
	vstore(prandex, tempa2);

	const v128 temp22 = k.pbuf[b ^ 1];
	acc = vxor(vxor(temp12, temp22), acc);
	vstore(prand, vxor(mhrs<Exact>(acc, temp12), temp12));
}

template <bool Exact>
VH_INLINE void case2(v128 &acc, uint64_t selector, const StepConst &k, v128 *prand,
                     v128 *prandex)
{
	const int b = base_of(selector);
	const v128 temp1 = vload(prandex);
	const v128 temp2 = k.pbuf[b];
	acc = vxor(vxor(temp1, temp2), acc);

	const v128 tempa2 = vxor(mhrs<Exact>(acc, temp1), temp1);
	const v128 temp12 = vload(prand);
	vstore(prand, tempa2);

	const v128 temp22 = k.pbuf[b ^ 1];
	acc = vxor(vclmul_self(vxor(temp12, temp22)), acc);
	acc = vxor(k.clprod[b ^ 1], acc);  // CL(temp22): precomputed
	vstore(prandex, vxor(mhrs<Exact>(acc, temp12), temp12));
}

template <bool Exact>
VH_INLINE void case3(v128 &acc, uint64_t selector, const StepConst &k, v128 *prand,
                     v128 *prandex)
{
	const int b = base_of(selector);
	const v128 temp1 = vload(prand);
	const v128 temp2 = k.pbuf[b ^ 1];

	// Reaching this case forces selector & 0x1c == 0x0c, so the low 32 bits
	// are at least 0x0000000C and the divisor cannot be zero. (Note the
	// failure modes differ: x86 IDIV raises #DE, AArch64 SDIV quietly returns
	// zero -- a bug here would be silent on this target.)
	const int32_t divisor = (int32_t)(uint32_t)selector;
	acc = vxor(vxor(temp1, temp2), acc);

	const int64_t dividend = (int64_t)vlow64(acc);
	acc = vxor(vfrom_u32((uint32_t)(int32_t)(dividend % divisor)), acc);

	const v128 tempa2 = vxor(mhrs<Exact>(acc, temp1), temp1);

#if VH22_CASE3_BRANCHLESS
	// `dividend & 1` is a coin flip on cryptographically random data, and the
	// bucketed dispatch cannot help with a branch *inside* a body. Both sides
	// are cheap, so compute both and select.
	//
	// The two sides do not just differ in value, they store in opposite
	// orders: the odd side writes prandex then prand, the even side writes
	// prand then prandex. That is only observable when the two slots are the
	// same vector, which happens 1 time in 512 -- and then the second store
	// wins, so the sides disagree about the surviving value. Folding the
	// alias case into the selected value lets one store order serve both.
	const v128 temp12 = vload(prandex);
	const v128 acc_odd =
		vxor(vxor(vclmul_self(vxor(temp12, k.pbuf[b])), k.clprod[b]), acc);
	const v128 acc_even = vxor(k.pbuf[b], acc);
	const v128 tempb2 = vxor(mhrs<Exact>(acc_odd, temp12), temp12);

	const v128 odd = vdupq_n_u8((dividend & 1) ? 0xff : 0x00);
	const v128 alias = vdupq_n_u8(prand == prandex ? 0xff : 0x00);
	acc = vbslq_u8(odd, acc_odd, acc_even);

	vstore(prandex, tempa2);
	vstore(prand, vbslq_u8(odd, tempb2, vbslq_u8(alias, tempa2, temp12)));
#else
	if (dividend & 1) {
		const v128 temp12 = vload(prandex);
		vstore(prandex, tempa2);

		const v128 temp22 = k.pbuf[b];
		acc = vxor(vclmul_self(vxor(temp12, temp22)), acc);
		acc = vxor(k.clprod[b], acc);  // CL(temp22): precomputed
		vstore(prand, vxor(mhrs<Exact>(acc, temp12), temp12));
	} else {
		vstore(prand, vload(prandex));
		vstore(prandex, tempa2);
		acc = vxor(k.pbuf[b], acc);
	}
#endif
}

// Three AES2 + MIX2 groups. The round keys are prand[0..11] -- key material,
// not the fixed Haraka constants: the upstream body opens with
// `const __m128i *rc = prand;`, which shadows the global table. That rules out
// the compile-time key absorption the fixed-constant chains get, so each fused
// pair still ends in one real EOR. Six pairs, six EORs, against the twelve a
// translated build spends.
template <bool Exact>
VH_INLINE void case4(v128 &acc, uint64_t selector, const StepConst &k, v128 *prand,
                     v128 *prandex)
{
	const int b = base_of(selector);
	const v128 *rc = prand;
	v128 t1 = k.pbuf[b ^ 1];
	v128 t2 = k.pbuf[b];

	for (int g = 0; g < 3; ++g) {
		const v128 *r = rc + 4 * g;
		t1 = aes2_fused(t1, r[0], r[2]);
		t2 = aes2_fused(t2, r[1], r[3]);
		const v128 m1 = vzip1_32(t1, t2);
		t2 = vzip2_32(t1, t2);
		t1 = m1;
	}
	acc = vxor(t2, vxor(t1, acc));

	const v128 tempa1 = vload(prand);
	const v128 tempa2 = mhrs<Exact>(acc, tempa1);
	vstore(prand, vload(prandex));
	vstore(prandex, vxor(tempa1, tempa2));
}

// Case 5, restructured. The original is a do-while of 1..8 iterations that
// branches per iteration on a cryptographically random selector bit. But no
// iteration reads acc -- each only XORs into it -- rc advances exactly once
// per iteration regardless of branch, and the whole branch pattern is
// selector bits [28 .. 28+r0] read MSB-first, which is known on entry.
//
// So the per-iteration unpredictable branch becomes two mask-driven walks
// whose contributions fold into acc with the same XOR set. Iteration j reads
// key vector prand[j]; the AES iteration with ordinal a additionally reads
// prand[j+1+4a .. j+4+4a], matching the original's rc/aesroundoffset walk.
template <bool Exact>
VH_INLINE void case5(v128 &acc, uint64_t selector, const StepConst &k, v128 *prand,
                     v128 *prandex)
{
	const int b = base_of(selector);
	const uint64_t r0 = selector >> 61;  // iterations = r0 + 1, so 1..8
	const uint64_t n = r0 + 1;
	const uint64_t field = (selector >> 28) & ((1ULL << n) - 1);
	// Bit j of the walk is selector bit (28 + r0 - j): reverse the field.
	const uint64_t clmask = __builtin_bitreverse64(field) >> (64 - n);
	const uint64_t aesmask = ~clmask & ((1ULL << n) - 1);

	// Buffer selection is written as an index, not a ternary on two live
	// vector registers: the parity is data-dependent, and a conditional
	// select between registers is one more thing for clang to turn into a
	// branch. `parity ? pbuf[b] : pbuf[b^1]` is just `pbuf[b ^ !parity]`.
	v128 fold = vzero();
	for (uint64_t m = clmask; m; m &= (m - 1)) {
		const uint64_t j = (uint64_t)__builtin_ctzll(m);
		const int parity = (int)((r0 ^ j) & 1);
		fold = vxor(fold, vclmul_self(vxor(prand[j], k.pbuf[b ^ (parity ^ 1)])));
	}

	uint64_t keyoff = 1;  // 1 + 4 * (AES ordinal)
	for (uint64_t m = aesmask; m; m &= (m - 1)) {
		const uint64_t j = (uint64_t)__builtin_ctzll(m);
		const int parity = (int)((r0 ^ j) & 1);
		const v128 *keys = prand + j + keyoff;
		const v128 onekey = aes2_fused(prand[j], keys[0], keys[2]);
		const v128 temp2 = aes2_fused(k.pbuf[b ^ parity], keys[1], keys[3]);
		fold = vxor(fold, vxor(vzip1_32(onekey, temp2), vzip2_32(onekey, temp2)));
		keyoff += 4;
	}
	acc = vxor(acc, fold);

	const v128 tempa1 = vload(prand);
	const v128 tempa3 = vxor(tempa1, mhrs<Exact>(acc, tempa1));
	const v128 tempa4 = vload(prandex);
	vstore(prandex, tempa3);
	vstore(prand, tempa4);
}

// Case 6, restructured. Unlike case 5 this loop does read acc, but only in
// one place: the mulhrs of the carry-less branch. Everything else --  the key
// XOR, the carry-less product, and the 64/32 division -- depends only on data
// known at entry.
//
// Hoisting that work off the accumulator chain leaves a 5-cycle serial step
// (EOR in parallel with SQRDMULH, then EOR) instead of ~12, and lets the
// per-iteration branch disappear: mulhrs(acc, 0) is exactly 0 in both the
// x86 and the SQRDMULH definition, so zeroing the unused operand makes the
// two branches one straight-line expression.
template <bool Exact>
VH_INLINE void case6(v128 &acc, uint64_t selector, const StepConst &k, v128 *prand,
                     v128 *prandex)
{
	const int b = base_of(selector);
	const uint64_t r0 = selector >> 61;  // iterations = r0 + 1, so 1..8
	const uint64_t n = r0 + 1;
	const uint64_t field = (selector >> 28) & ((1ULL << n) - 1);
	const uint64_t modmask = __builtin_bitreverse64(field) >> (64 - n);

	// Reaching this case forces selector & 0x1c == 0x18, so the divisor is
	// at least 0x18 and cannot be zero.
	const int32_t divisor = (int32_t)(uint32_t)selector;

	// The trip count is 1..8 drawn from the top three selector bits, so the
	// loop-exit branch is unpredictable. VH22_CASE6_FIXED trades that for a
	// constant eight iterations with the surplus ones masked to identity:
	// mulhrs(x, 0) is exactly 0 and acc ^ 0 is acc, so an inactive iteration
	// contributes nothing. prand[j] for j <= 7 is always in range.
	const uint64_t trip = VH22_CASE6_FIXED ? 8 : n;

	v128 onekey = vzero();
	for (uint64_t j = 0; j < trip; ++j) {
		const uint64_t live = VH22_CASE6_FIXED ? (j < n) : 1;
		const uint64_t is_mod = (modmask >> j) & 1;
		const uint64_t parity = (r0 ^ j) & 1;
		// The two branches pick opposite buffers for the same parity, so
		// one XOR covers both selections.
		const v128 v = vxor(prand[j], k.pbuf[b ^ (int)(parity ^ is_mod)]);

		const int64_t dividend = (int64_t)vlow64(v);
		const v128 modulo = vfrom_u32((uint32_t)(int32_t)(dividend % divisor));
		const v128 product = vclmul_self(v);

		const v128 sel = vdupq_n_u8(is_mod ? 0xff : 0x00);
		const v128 keep = vdupq_n_u8(live ? 0xff : 0x00);
		const v128 modterm = vandq_u8(vandq_u8(modulo, sel), keep);
		const v128 clterm = vandq_u8(vbicq_u8(product, sel), keep);

		const v128 a = vxor(acc, modterm);
		acc = vxor(a, mhrs<Exact>(a, clterm));
		onekey = vbslq_u8(keep, vbslq_u8(sel, v, product), onekey);
	}

	const v128 tempa3 = vload(prandex);
	vstore(prandex, onekey);
	vstore(prand, vxor(tempa3, acc));
}

template <bool Exact>
VH_INLINE void case7(v128 &acc, uint64_t selector, const StepConst &k, v128 *prand,
                     v128 *prandex)
{
	const int b = base_of(selector);
	const v128 temp1 = k.pbuf[b];
	const v128 temp2 = vload(prandex);
	acc = vxor(vclmul_self(vxor(temp1, temp2)), acc);

	const v128 tempa2 = vxor(mhrs<Exact>(acc, temp2), temp2);
	const v128 tempa3 = vload(prand);
	vstore(prand, tempa2);

	acc = vxor(tempa3, acc);
	acc = vxor(k.pbuf[b ^ 1], acc);
	vstore(prandex, vxor(mhrs<Exact>(acc, tempa3), tempa3));
}

} // namespace detail

// Per-hash setup: the four pbuf_copy vectors and their carry-less squares.
VH_INLINE void step_const_init(StepConst &k, const uint8_t buf[64])
{
	const v128 b0 = vload(buf), b1 = vload(buf + 16);
	const v128 b2 = vload(buf + 32), b3 = vload(buf + 48);
	k.pbuf[0] = vxor(b0, b2);
	k.pbuf[1] = vxor(b1, b3);
	k.pbuf[2] = b2;
	k.pbuf[3] = b3;
	for (int i = 0; i < 4; ++i)
		k.clprod[i] = vclmul_self(k.pbuf[i]);
}

// Modulo reduction to 64 bits over the (64,4,3,1,0) polynomial.
//
// §9: C has degree 4 and A's high half is 64 bits, so Q2's high half is at
// most 4 bits and every shuffle index is provably in [0,15]. TBL and PSHUFB
// agree there, so sse2neon's defensive AND #0x8F is dropped.
VH_INLINE uint64_t precomp_reduction64(v128 A)
{
	alignas(16) static constexpr uint8_t kTable[16] = {0,   27,  54,  45,  108, 119,
	                                                   90,  65,  216, 195, 238, 245,
	                                                   180, 175, 130, 153};
	const v128 C = vfrom_u64((1U << 4) + (1U << 3) + (1U << 1) + (1U << 0));
	// _mm_clmulepi64_si128(A, C, 0x01): A's high half against C's low half.
	const v128 Q2 = vclmul_lo(vswap64(A), C);
	const v128 Q2High = vextq_u8(Q2, vzero(), 8);
	const v128 Q3 = vtbl16(vload(kTable), Q2High);
	return vlow64(vxor(Q3, vxor(Q2, A)));
}

} // namespace vh22
