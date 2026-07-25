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

// A lane's tail: publish acc, derive the next selector, drop the lane into its
// next-wave bucket, and start the two random key loads a full wave ahead.
VH_INLINE void lane_tail(WaveState &w, WaveCtx &c, v128 acc, int nxt, uint8_t lane)
{
	c.acc = acc;
	const uint64_t nsel = vlow64(acc);
	c.sel = nsel;
	const uint32_t ncs = (uint32_t)((nsel >> 2) & 7);
	w.buckets[nxt][ncs][w.bucklen[nxt][ncs]++] = lane;
	w.nonempty[nxt] |= (1u << ncs);

	v128 *nprand = c.key + ((nsel >> 5) & 511);
	// Cases 5 and 6 walk up to 40 vectors forward from prand; everything
	// else touches one line. Re-touching line 0 for the shallow cases keeps
	// the multi-thread bandwidth cost proportional (the LSU dedupes it).
	const uint64_t walk = ((ncs == 5) | (ncs == 6)) ? 128 : 0;
	__builtin_prefetch(nprand, 1, 3);
	__builtin_prefetch((const char *)nprand + walk, 0, 3);
	__builtin_prefetch((const char *)nprand + 2 * walk, 0, 3);
	__builtin_prefetch(c.key + ((nsel >> 32) & 511), 1, 3);
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
		__builtin_prefetch(c.key + ((sel >> 5) & 511), 1, 3);
		__builtin_prefetch(c.key + ((sel >> 32) & 511), 1, 3);
	}

	for (int step = 0; step < kSteps; ++step) {
		const int par = step & 1;
		const int nxt = par ^ 1;

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
	}

	const v128 length_hash = vfrom_u64(0x10000);
	for (int l = 0; l < n; ++l)
		out[l] = precomp_reduction64(vxor(ctx[l].acc, length_hash));
}

} // namespace vh22
