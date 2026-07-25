// The VerusHash 2.2 CLHash walk: 32 steps over an 8 KB mutable key region.
#pragma once

#include "vh22/clhash_bodies.h"

namespace vh22 {

enum : int {
	kSteps = 32,
	kMaxLanes = 64,
};
enum : size_t {
	kKeyBytes = 8832,     // 8 KB mutable + 40 round-constant vectors
	kKeyVecs = 552,
	kMutableVecs = 512,
};

// One stream, 32 steps, straightforward dispatch. Used for verification and as
// the benchmark's latency-bound baseline.
template <bool Exact>
uint64_t clhash_scalar(v128 *key, const uint8_t buf[64], uint32_t touched[kSteps])
{
	StepConst k;
	step_const_init(k, buf);
	v128 acc = vload(key + kMutableVecs + 1);  // keyMask + 2

	for (int i = 0; i < kSteps; ++i) {
		const uint64_t selector = vlow64(acc);
		const uint32_t prand_idx = (uint32_t)((selector >> 5) & 511);
		const uint32_t prandex_idx = (uint32_t)((selector >> 32) & 511);
		// §6: record slot indices, not pointers. 128 bytes per stream
		// instead of 512, and the restore loop reconstructs the address
		// with the same scaled addressing the walk used.
		touched[i] = prand_idx | (prandex_idx << 16);
		v128 *prand = key + prand_idx;
		v128 *prandex = key + prandex_idx;

		switch ((selector >> 2) & 7) {
		case 0: detail::case0<Exact>(acc, selector, k, prand, prandex); break;
		case 1: detail::case1<Exact>(acc, selector, k, prand, prandex); break;
		case 2: detail::case2<Exact>(acc, selector, k, prand, prandex); break;
		case 3: detail::case3<Exact>(acc, selector, k, prand, prandex); break;
		case 4: detail::case4<Exact>(acc, selector, k, prand, prandex); break;
		case 5: detail::case5<Exact>(acc, selector, k, prand, prandex); break;
		case 6: detail::case6<Exact>(acc, selector, k, prand, prandex); break;
		default: detail::case7<Exact>(acc, selector, k, prand, prandex); break;
		}
	}

	// §9: lazyLengthHash(1024, 64) = clmul(x^6, x^10) = x^16. A literal.
	return precomp_reduction64(vxor(acc, vfrom_u64(0x10000)));
}

// N independent streams advanced in lockstep, one step per wave, executed in
// case-bucketed order (§7c). Bodies use the bare-SQRDMULH arithmetic.
void clhash_wave(v128 *const *keys, const uint8_t *const *bufs, uint32_t *const *touched,
                 uint64_t *out, int nlanes);

// Restore the <= 64 slots a walk dirtied from the shared pristine copy (§6).
// Cheaper than rebuilding, and cheaper than double-buffering the key.
VH_INLINE void restore_key(const uint32_t *touched, v128 *key, const v128 *pristine)
{
	for (int i = 0; i < kSteps; ++i) {
		const uint32_t packed = touched[i];
		const uint32_t a = packed & 0xffff;
		const uint32_t b = packed >> 16;
		key[a] = pristine[a];
		key[b] = pristine[b];
	}
}

} // namespace vh22
