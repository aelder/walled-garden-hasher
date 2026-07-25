// Cost-sieve ceiling measurement.
//
// The GPU nonce sieve is a *work-cost* sieve, not a share-probability one. It
// forecasts how expensive each nonce's CLHash walk will be, and the CPU
// completes only the cheapest fraction. Every nonce is an equally likely
// lottery ticket, so completing more cheap ones per second is a real gain.
//
// Its entire leverage is the variance of per-nonce cost. Before building any
// Metal plumbing, this measures the ceiling: the forecast is computed here on
// the CPU and NOT counted against the clock, exactly as if an infinitely fast,
// perfectly accurate GPU had supplied it for free. No real sieve can beat this
// number, so if the ceiling is small the idea is dead regardless of how fast
// the GPU is.
//
//   --depth D   forecast horizon in steps (32 = perfect knowledge)
//   --keep F    fraction of nonces to complete, cheapest first
#include "vh22/verushash.h"

#include <algorithm>
#include <mach/mach_time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <vector>

using namespace vh22;

static double now_seconds()
{
	static mach_timebase_info_data_t tb;
	if (tb.denom == 0)
		mach_timebase_info(&tb);
	return (double)mach_absolute_time() * (double)tb.numer / (double)tb.denom / 1e9;
}

// Transcribed verbatim from the Metal sieve kernel on m2max-sieve-opt, so the
// ceiling is measured against the model the prior campaign actually used.
static uint32_t step_cost_score(uint64_t selector)
{
	const uint32_t sel_case = (uint32_t)((selector >> 2) & 7);
	switch (sel_case) {
	case 0:
	case 1:
	case 2:
		return 6;
	case 3:
		return 13;
	case 4:
		return 14;
	case 5:
	case 6: {
		const uint32_t iterations = (uint32_t)(selector >> 61) + 1;
		const uint32_t pattern = (uint32_t)(selector >> 28) & ((1u << iterations) - 1);
		const uint32_t branches = (uint32_t)__builtin_popcount(pattern);
		if (sel_case == 5)
			return 2 + branches + 4 * (iterations - branches);
		return 10 * branches + 3 * (iterations - branches);
	}
	default:
		return 5;
	}
}

// Run `depth` real steps on a scratch key and sum the predicted cost. Step 0's
// selector is acc0 = key[513], identical for every nonce of a template, so it
// contributes a constant and only steps 1.. discriminate.
static uint32_t forecast(v128 *scratch, const v128 *pristine, const uint8_t *buf, int depth)
{
	memcpy(scratch, pristine, kKeyBytes);
	StepConst k;
	step_const_init(k, buf);
	v128 acc = vload(scratch + kMutableVecs + 1);

	uint32_t cost = 0;
	for (int i = 0; i < depth; ++i) {
		const uint64_t selector = vlow64(acc);
		cost += step_cost_score(selector);
		v128 *prand = scratch + ((selector >> 5) & 511);
		v128 *prandex = scratch + ((selector >> 32) & 511);
		switch ((selector >> 2) & 7) {
		case 0: detail::case0<false>(acc, selector, k, prand, prandex); break;
		case 1: detail::case1<false>(acc, selector, k, prand, prandex); break;
		case 2: detail::case2<false>(acc, selector, k, prand, prandex); break;
		case 3: detail::case3<false>(acc, selector, k, prand, prandex); break;
		case 4: detail::case4<false>(acc, selector, k, prand, prandex); break;
		case 5: detail::case5<false>(acc, selector, k, prand, prandex); break;
		case 6: detail::case6<false>(acc, selector, k, prand, prandex); break;
		default: detail::case7<false>(acc, selector, k, prand, prandex); break;
		}
	}
	return cost;
}

// Time the completion of an explicit nonce list through the wave kernel.
static double time_nonces(Hasher &h, const std::vector<uint32_t> &nonces, int passes)
{
	const int n = h.lanes();
	const size_t waves = nonces.size() / (size_t)n;
	const double t0 = now_seconds();
	for (int p = 0; p < passes; ++p)
		for (size_t w = 0; w < waves; ++w)
			h.run_wave_list(&nonces[w * (size_t)n], 0);
	const double dt = now_seconds() - t0;
	return (double)(waves * (size_t)n * (size_t)passes) / dt;
}

int main(int argc, char **argv)
{
	int depth = 4, lanes = 64, passes = 12;
	double keep = 0.30;
	size_t pool = 1u << 16;

	for (int i = 1; i < argc; ++i) {
		const char *a = argv[i];
		auto val = [&]() { return (i + 1 < argc) ? argv[++i] : "0"; };
		if (!strcmp(a, "--depth")) depth = atoi(val());
		else if (!strcmp(a, "--keep")) keep = atof(val());
		else if (!strcmp(a, "--lanes")) lanes = atoi(val());
		else if (!strcmp(a, "--pool")) pool = (size_t)atoll(val());
		else if (!strcmp(a, "--passes")) passes = atoi(val());
		else {
			printf("usage: vh22-sieve-oracle [--depth D] [--keep F] [--lanes N]\n"
			       "                         [--pool N] [--passes N]\n");
			return 2;
		}
	}
	if (depth < 1) depth = 1;
	if (depth > 32) depth = 32;

	uint8_t header[1487];
	for (size_t i = 0; i < sizeof(header); ++i)
		header[i] = (uint8_t)(i * 31 + 7);
	Template tpl;
	build_template(tpl, header, sizeof(header));

	Hasher h(lanes);
	if (!h.valid()) {
		printf("allocation failed\n");
		return 1;
	}
	h.reset(tpl);

	printf("cost-sieve ceiling: depth %d, keep %.2f, %d lanes, pool %zu nonces\n", depth,
	       keep, h.lanes(), pool);
	printf("(forecast is computed on the CPU and NOT timed -- an infinitely fast,\n"
	       " perfectly accurate GPU. No real sieve can beat this.)\n\n");

	// --- untimed forecast pass ------------------------------------------
	std::vector<v128> scratch(kKeyVecs);
	std::vector<std::pair<uint32_t, uint32_t>> scored;  // (cost, nonce)
	scored.reserve(pool);

	alignas(64) uint8_t buf[64];
	for (size_t i = 0; i < pool; ++i) {
		const uint32_t nonce = (uint32_t)i;
		memcpy(buf, tpl.half, 64);
		vstore(buf + 48, tpl.fill1);
		buf[47] = tpl.first_byte;
		memcpy(buf + 43, &nonce, 4);
		scored.push_back({forecast(scratch.data(), tpl.key, buf, depth), nonce});
	}

	std::sort(scored.begin(), scored.end());
	const size_t nkeep = (size_t)((double)pool * keep) / (size_t)h.lanes() * (size_t)h.lanes();

	// Cost spread is the whole source of leverage; report it.
	uint64_t sum = 0;
	for (auto &s : scored)
		sum += s.first;
	const double mean = (double)sum / (double)pool;
	uint64_t kept_sum = 0;
	for (size_t i = 0; i < nkeep; ++i)
		kept_sum += scored[i].first;
	const double kept_mean = nkeep ? (double)kept_sum / (double)nkeep : 0;

	printf("  forecast cost over %d steps : mean %.1f, p0 %u, p50 %u, p100 %u\n", depth, mean,
	       scored.front().first, scored[pool / 2].first, scored.back().first);
	printf("  cheapest %.0f%% mean cost    : %.1f  (%.1f%% below the pool mean)\n\n",
	       keep * 100, kept_mean, 100.0 * (mean - kept_mean) / mean);

	// --- timed completion -----------------------------------------------
	std::vector<uint32_t> all, cheap;
	all.reserve(pool);
	for (size_t i = 0; i < pool; ++i)
		all.push_back(scored[i].second);  // same set, order irrelevant
	for (size_t i = 0; i < nkeep; ++i)
		cheap.push_back(scored[i].second);

	// Interleaved, both orders, because this machine drifts within seconds.
	double base_r = 0, sieve_r = 0;
	for (int round = 0; round < 2; ++round) {
		if (round == 0) {
			base_r += time_nonces(h, all, passes);
			sieve_r += time_nonces(h, cheap, passes);
		} else {
			sieve_r += time_nonces(h, cheap, passes);
			base_r += time_nonces(h, all, passes);
		}
	}
	base_r /= 2;
	sieve_r /= 2;

	printf("  completion rate, all nonces     : %8.0f H/s\n", base_r);
	printf("  completion rate, cheapest %.0f%%   : %8.0f H/s\n", keep * 100, sieve_r);
	printf("  per-hash speedup from selection : %+.1f%%\n\n",
	       100.0 * (sieve_r - base_r) / base_r);

	// What a real sieve would have to supply to sustain that rate.
	printf("  a real sieve at this operating point would need the forecaster to\n"
	       "  supply %.1f Mcand/s per thread (%.1f Mcand/s at 10 threads)\n",
	       sieve_r / keep / 1e6, sieve_r / keep * 10 / 1e6);
	return 0;
}
