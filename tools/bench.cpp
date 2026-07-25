// Throughput benchmark and parameter sweep.
//
// §6 warns that stream interleaving and branch misprediction fight each other
// and that there is likely an optimum lane count well below the L1D capacity
// limit -- so lane count is measured, not assumed. §8 says the same about the
// per-stream key stride. Both are swept here.
#include "vh22/verushash.h"

#include <initializer_list>
#include <mach/mach_time.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sysctl.h>

#if defined(__APPLE__)
#include <pthread/qos.h>
#endif

using namespace vh22;

static double now_seconds()
{
	static mach_timebase_info_data_t tb;
	if (tb.denom == 0)
		mach_timebase_info(&tb);
	return (double)mach_absolute_time() * (double)tb.numer / (double)tb.denom / 1e9;
}

struct Job {
	const Template *tpl;
	int lanes;
	size_t pad;
	double seconds;
	uint32_t nonce_base;
	uint64_t hashes;
	bool ok;
};

static void *worker(void *arg)
{
#if defined(__APPLE__)
	// §10: macOS has no thread-to-core pinning API. This is the closest
	// lever for keeping work on performance cores.
	pthread_set_qos_class_self_np(QOS_CLASS_USER_INTERACTIVE, 0);
#endif
	Job *j = (Job *)arg;
	Hasher h(j->lanes ? j->lanes : 1, j->pad);
	if (!h.valid()) {
		j->ok = false;
		return nullptr;
	}
	h.reset(*j->tpl);

	const double t0 = now_seconds();
	const double deadline = t0 + j->seconds;
	uint64_t count = 0;
	uint32_t nonce = j->nonce_base;

	if (j->lanes) {
		const int n = h.lanes();
		do {
			for (int rep = 0; rep < 64; ++rep) {
				h.run_wave(nonce, 0);
				nonce += (uint32_t)n;
				count += (uint64_t)n;
			}
		} while (now_seconds() < deadline);
	} else {
		do {
			for (int rep = 0; rep < 512; ++rep) {
				h.run_one(nonce++, 0);
				++count;
			}
		} while (now_seconds() < deadline);
	}
	j->seconds = now_seconds() - t0;
	j->hashes = count;
	j->ok = true;
	return nullptr;
}

struct Result {
	double hashes_per_sec;
	double ns_per_hash;
};

static Result measure(const Template &tpl, int lanes, int threads, size_t pad,
                      double seconds)
{
	Job jobs[64];
	pthread_t tids[64];
	if (threads > 64)
		threads = 64;
	for (int i = 0; i < threads; ++i) {
		jobs[i] = Job{&tpl, lanes, pad, seconds, (uint32_t)(i * 0x01000000u), 0, false};
		pthread_create(&tids[i], nullptr, worker, &jobs[i]);
	}
	uint64_t total = 0;
	double elapsed = 0;
	for (int i = 0; i < threads; ++i) {
		pthread_join(tids[i], nullptr);
		total += jobs[i].hashes;
		if (jobs[i].seconds > elapsed)
			elapsed = jobs[i].seconds;
	}
	Result r;
	r.hashes_per_sec = elapsed > 0 ? (double)total / elapsed : 0;
	r.ns_per_hash = total ? elapsed * 1e9 / (double)total * threads : 0;
	return r;
}

static int sysctl_int(const char *name, int fallback)
{
	int v = 0;
	size_t len = sizeof(v);
	return sysctlbyname(name, &v, &len, nullptr, 0) == 0 ? v : fallback;
}

// Cross-check the wave kernel against the independent exact path before
// reporting any number -- a fast wrong miner is worth nothing.
static bool verify(const Template &tpl, int lanes)
{
	Hasher h(lanes);
	if (!h.valid())
		return false;
	h.reset(tpl);
	const uint64_t hit = h.run_wave(4242, 0xffffffff);
	for (int l = 0; l < h.lanes(); ++l) {
		if (!((hit >> l) & 1))
			return false;
		uint8_t want[32];
		h.hash_exact(4242 + (uint32_t)l, want);
		if (memcmp(h.hash_of(l), want, 32) != 0)
			return false;
	}
	return true;
}

int main(int argc, char **argv)
{
	int lanes = -1, threads = 1;
	size_t pad = 0;
	double seconds = 8.0;
	bool sweep_lanes = false, sweep_pad = false;

	for (int i = 1; i < argc; ++i) {
		const char *a = argv[i];
		auto val = [&]() { return (i + 1 < argc) ? argv[++i] : "0"; };
		if (!strcmp(a, "--lanes"))
			lanes = atoi(val());
		else if (!strcmp(a, "--threads"))
			threads = atoi(val());
		else if (!strcmp(a, "--pad"))
			pad = (size_t)atoll(val());
		else if (!strcmp(a, "--seconds"))
			seconds = atof(val());
		else if (!strcmp(a, "--sweep-lanes"))
			sweep_lanes = true;
		else if (!strcmp(a, "--sweep-pad"))
			sweep_pad = true;
		else {
			printf("usage: vh22-bench [--lanes N|0] [--threads N] [--pad BYTES]\n"
			       "                  [--seconds S] [--sweep-lanes] [--sweep-pad]\n"
			       "  --lanes 0 runs the single-stream kernel.\n");
			return 2;
		}
	}

	const int ncpu = sysctl_int("hw.logicalcpu", 1);
	const int nperf = sysctl_int("hw.nperflevels", 1);
	const int fast = nperf > 1 ? sysctl_int("hw.perflevel0.logicalcpu", ncpu) : ncpu;
	printf("machine: %d logical cores, %d performance, L1D %d B, L2 %d B\n\n", ncpu, fast,
	       sysctl_int("hw.perflevel0.l1dcachesize", 0),
	       sysctl_int("hw.perflevel0.l2cachesize", 0));

	uint8_t header[1487];
	for (size_t i = 0; i < sizeof(header); ++i)
		header[i] = (uint8_t)(i * 31 + 7);

	Template tpl;
	build_template(tpl, header, sizeof(header));

	if (!verify(tpl, 16)) {
		printf("ERROR: wave kernel disagrees with the exact path; refusing to benchmark\n");
		return 1;
	}
	printf("wave kernel verified against the exact path\n\n");

	if (sweep_lanes) {
		printf("lane sweep (%d thread%s, %.1fs each)\n", threads, threads > 1 ? "s" : "",
		       seconds);
		printf("  %-8s %14s %12s\n", "lanes", "H/s", "ns/hash");
		for (int n : {0, 1, 2, 4, 8, 12, 16, 24, 32, 48, 64}) {
			const Result r = measure(tpl, n, threads, pad, seconds);
			char label[16];
			if (n)
				snprintf(label, sizeof(label), "%d", n);
			else
				snprintf(label, sizeof(label), "scalar");
			printf("  %-8s %14.0f %12.1f\n", label, r.hashes_per_sec, r.ns_per_hash);
			fflush(stdout);
		}
		return 0;
	}

	if (sweep_pad) {
		const int n = lanes > 0 ? lanes : 32;
		printf("stride-pad sweep at %d lanes (%d thread%s, %.1fs each)\n", n, threads,
		       threads > 1 ? "s" : "", seconds);
		printf("  %-10s %14s %12s\n", "pad", "H/s", "ns/hash");
		for (size_t p : {0u, 64u, 128u, 192u, 256u, 384u, 512u, 1024u}) {
			const Result r = measure(tpl, n, threads, p, seconds);
			printf("  %-10zu %14.0f %12.1f\n", p, r.hashes_per_sec, r.ns_per_hash);
			fflush(stdout);
		}
		return 0;
	}

	if (lanes < 0)
		lanes = 32;
	const Result r = measure(tpl, lanes, threads, pad, seconds);
	char label[24];
	if (lanes)
		snprintf(label, sizeof(label), "%d lanes", lanes);
	else
		snprintf(label, sizeof(label), "scalar");
	printf("%s, %d thread%s, pad %zu: %.0f H/s (%.1f ns/hash/thread)\n", label, threads,
	       threads > 1 ? "s" : "", pad, r.hashes_per_sec, r.ns_per_hash);
	return 0;
}
