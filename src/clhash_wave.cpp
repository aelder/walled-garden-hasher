// §6 + §7c: N-way stream interleaving with case-bucketed dispatch.
//
// The core loop is latency-bound, not throughput-bound. `selector = acc[63:0]`
// at the top of each step makes a single stream strictly serial, with roughly
// 15-18 cycles of critical path during which a 4-wide NEON pipeline is mostly
// idle. Running independent nonces concurrently in one thread is the only fix.
//
// But interleaving and branch misprediction fight each other: the 8-way
// dispatch on cryptographically random data mispredicts ~87.5% of the time,
// and a flush discards in-flight work from *every* lane, so the cost does not
// amortise. Bucketing the lanes by case turns that unpredictable indirect
// branch into predictable loop control -- one hoisted dispatch per distinct
// case per wave, with a plain counted loop over that case's lanes inside.
//
// The buckets for the next wave are built by each step's tail rather than by a
// separate sort pass, double-buffered on wave parity.
//
// Measured against an identity-order control -- same interleaving, same bodies,
// lanes walked in index order so the dispatch is one unpredictable indirect
// branch per lane per step (VH22_WAVE_BUCKET=0). M5, 1 thread, 8 s:
//
//     lanes    bucketed     identity order
//     16       4313 kH/s    2980 kH/s      +45%
//     64       4667 kH/s    2762 kH/s      +69%
//
// Both halves of §7 hold, and hold hard. The mispredict term dominates; and
// without bucketing, going from 16 lanes to 64 makes things *worse*, which is
// exactly the predicted fight between interleaving and misprediction -- more
// streams in flight means a flush discards more work. Bucketing removes the
// conflict, and only then does lane count scale monotonically.
#include "vh22/clhash.h"

namespace vh22 {
namespace {

struct alignas(64) WaveCtx {
	StepConst k;
	v128 acc;
	uint64_t sel;
	v128 *key;
	uint32_t *touched;
};

using Body = void (*)(v128 &, uint64_t, const StepConst &, v128 *, v128 *);

struct WaveState {
	WaveCtx *ctx;
	uint8_t (*buckets)[8][kMaxLanes];
	uint8_t (*bucklen)[8];
	uint32_t *nonempty;
};

// §8 says not to prefetch at all: the accesses are random and
// address-dependent, so software prefetch can only pollute.
//
// It was worth doubting. That reasoning assumes the key is L1-resident, which
// holds at the lane counts §6 suggests (N ~ 8-14) but not here -- at 64 lanes
// the working set is 565 KB and lives in L2, where a full wave of lead time
// looks like it should pay. It does not. Measured on M5, 8 s runs:
//
//     config              none     +2 slots   +deep walk
//     64 lanes,  1 thr    4645 kH/s  4528       4363      -6.5%
//     16 lanes,  1 thr    4265 kH/s    --       4062      -5.0%
//     64 lanes, 10 thr   28177 kH/s    --      26470      -6.4%
//     scalar kernel       2142 kH/s    --       2142      (control: no
//                                                          prefetches there)
//
// Four prfm per lane per step is 128 extra memory-pipe operations per hash,
// and the addresses are only known one step ahead -- far too late to cover an
// L2 hit, early enough to compete with the loads that matter. §8 was right.
//
// Kept switchable because it is the kind of thing that flips with cache
// hierarchy: VH22_PREFETCH 0 none, 1 the next step's two slots, 2 also two
// lines deeper when the next case is 5 or 6, which walk up to 40 vectors
// forward from prand.
#ifndef VH22_PREFETCH
#define VH22_PREFETCH 0
#endif

// §7c: bucket the lanes by case so the unpredictable 8-way indirect branch
// becomes predictable loop control. Set to 0 for the identity-order control.
#ifndef VH22_WAVE_BUCKET
#define VH22_WAVE_BUCKET 1
#endif

// A lane's tail: publish acc, derive the next selector, drop the lane into its
// next-wave bucket, and start the two random key loads a full wave ahead.
VH_INLINE void lane_tail(WaveState &w, WaveCtx &c, v128 acc, int nxt, uint8_t lane)
{
	c.acc = acc;
	const uint64_t nsel = vlow64(acc);
	c.sel = nsel;
	const uint32_t ncs = (uint32_t)((nsel >> 2) & 7);
#if VH22_WAVE_BUCKET
	w.buckets[nxt][ncs][w.bucklen[nxt][ncs]++] = lane;
	w.nonempty[nxt] |= (1u << ncs);
#else
	(void)nxt;
	(void)lane;
#endif

#if VH22_PREFETCH > 0
	v128 *nprand = c.key + ((nsel >> 5) & 511);
	__builtin_prefetch(nprand, 1, 3);
	__builtin_prefetch(c.key + ((nsel >> 32) & 511), 1, 3);
#if VH22_PREFETCH > 1
	// Re-touching line 0 for the shallow cases (walk == 0) keeps the
	// multi-thread bandwidth cost proportional; the LSU dedupes it.
	const uint64_t walk = ((ncs == 5) | (ncs == 6)) ? 128 : 0;
	__builtin_prefetch((const char *)nprand + walk, 0, 3);
	__builtin_prefetch((const char *)nprand + 2 * walk, 0, 3);
#endif
#endif
}

template <Body Fn>
VH_INLINE void run_bucket(WaveState &w, const uint8_t *lanes, int cnt, int step, int nxt)
{
	for (int j = 0; j < cnt; ++j) {
		const uint8_t lane = lanes[j];
		WaveCtx &c = w.ctx[lane];
		const uint64_t selector = c.sel;
		const uint32_t prand_idx = (uint32_t)((selector >> 5) & 511);
		const uint32_t prandex_idx = (uint32_t)((selector >> 32) & 511);
		c.touched[step] = prand_idx | (prandex_idx << 16);

		v128 acc = c.acc;
		Fn(acc, selector, c.k, c.key + prand_idx, c.key + prandex_idx);
		lane_tail(w, c, acc, nxt, lane);
	}
}

#if !VH22_WAVE_BUCKET
// One lane, dispatched on its own case. Used only by the unbucketed control.
VH_INLINE void run_bucket_one(WaveState &w, uint8_t lane, int step, int nxt)
{
	WaveCtx &c = w.ctx[lane];
	const uint64_t selector = c.sel;
	const uint32_t prand_idx = (uint32_t)((selector >> 5) & 511);
	const uint32_t prandex_idx = (uint32_t)((selector >> 32) & 511);
	c.touched[step] = prand_idx | (prandex_idx << 16);

	v128 acc = c.acc;
	v128 *prand = c.key + prand_idx;
	v128 *prandex = c.key + prandex_idx;
	switch ((selector >> 2) & 7) {
	case 0: detail::case0<false>(acc, selector, c.k, prand, prandex); break;
	case 1: detail::case1<false>(acc, selector, c.k, prand, prandex); break;
	case 2: detail::case2<false>(acc, selector, c.k, prand, prandex); break;
	case 3: detail::case3<false>(acc, selector, c.k, prand, prandex); break;
	case 4: detail::case4<false>(acc, selector, c.k, prand, prandex); break;
	case 5: detail::case5<false>(acc, selector, c.k, prand, prandex); break;
	case 6: detail::case6<false>(acc, selector, c.k, prand, prandex); break;
	default: detail::case7<false>(acc, selector, c.k, prand, prandex); break;
	}
	lane_tail(w, c, acc, nxt, lane);
}
#endif

} // namespace

void clhash_wave(v128 *const *keys, const uint8_t *const *bufs, uint32_t *const *touched,
                 uint64_t *out, int nlanes)
{
	if (nlanes < 1)
		nlanes = 1;
	if (nlanes > kMaxLanes)
		nlanes = kMaxLanes;
	const int n = nlanes;

	alignas(64) WaveCtx ctx[kMaxLanes];
	alignas(64) uint8_t buckets[2][8][kMaxLanes];
	uint8_t bucklen[2][8] = {{0}, {0}};
	uint32_t nonempty[2] = {0, 0};

	WaveState w = {ctx, buckets, bucklen, nonempty};

	for (int l = 0; l < n; ++l) {
		WaveCtx &c = ctx[l];
		step_const_init(c.k, bufs[l]);
		c.key = keys[l];
		c.touched = touched[l];
		c.acc = vload(c.key + kMutableVecs + 1);
		const uint64_t sel = vlow64(c.acc);
		c.sel = sel;
		const uint32_t cs = (uint32_t)((sel >> 2) & 7);
		buckets[0][cs][bucklen[0][cs]++] = (uint8_t)l;
		nonempty[0] |= (1u << cs);
#if VH22_PREFETCH > 0
		__builtin_prefetch(c.key + ((sel >> 5) & 511), 1, 3);
		__builtin_prefetch(c.key + ((sel >> 32) & 511), 1, 3);
#endif
	}

	for (int step = 0; step < kSteps; ++step) {
		const int par = step & 1;
		const int nxt = par ^ 1;

#if VH22_WAVE_BUCKET
		// One hoisted dispatch per distinct case; empty buckets are skipped
		// by a ctz walk, so a wave costs about 5 of 8 dispatches at 32 lanes
		// rather than one unpredictable indirect branch per lane per step.
		for (uint32_t mask = nonempty[par]; mask; mask &= (mask - 1)) {
			const int cs = __builtin_ctz(mask);
			const uint8_t *lanes = buckets[par][cs];
			const int cnt = bucklen[par][cs];
			switch (cs) {
			case 0: run_bucket<detail::case0<false>>(w, lanes, cnt, step, nxt); break;
			case 1: run_bucket<detail::case1<false>>(w, lanes, cnt, step, nxt); break;
			case 2: run_bucket<detail::case2<false>>(w, lanes, cnt, step, nxt); break;
			case 3: run_bucket<detail::case3<false>>(w, lanes, cnt, step, nxt); break;
			case 4: run_bucket<detail::case4<false>>(w, lanes, cnt, step, nxt); break;
			case 5: run_bucket<detail::case5<false>>(w, lanes, cnt, step, nxt); break;
			case 6: run_bucket<detail::case6<false>>(w, lanes, cnt, step, nxt); break;
			default: run_bucket<detail::case7<false>>(w, lanes, cnt, step, nxt); break;
			}
		}

		for (int c = 0; c < 8; ++c)
			bucklen[par][c] = 0;
		nonempty[par] = 0;
#else
		// Control: identical interleaving, identical bodies, but lanes are
		// walked in index order so the dispatch is one unpredictable indirect
		// branch per lane per step. The delta against the bucketed path is
		// what case-bucketing is actually worth.
		(void)nxt;
		for (int l = 0; l < n; ++l) {
			const uint8_t lane = (uint8_t)l;
			run_bucket_one(w, lane, step, nxt);
		}
#endif
	}

	const v128 length_hash = vfrom_u64(0x10000);
	for (int l = 0; l < n; ++l)
		out[l] = precomp_reduction64(vxor(ctx[l].acc, length_hash));
}

} // namespace vh22
