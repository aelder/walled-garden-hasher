// Throughput benchmark and parameter sweep.
//
// §6 warns that stream interleaving and branch misprediction fight each other
// and that there is likely an optimum lane count well below the L1D capacity
// limit -- so lane count is measured, not assumed. §8 says the same about the
// per-stream key stride. Both are swept here.
#include "vh22/verushash.h"

#include <atomic>
#include <initializer_list>
#include <mach/mach_time.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sysctl.h>
#include <unistd.h>
#include <vector>

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

// Peak mode. Workers publish progress into one counter and the main thread
// samples it, so the reported number is the best short window rather than the
// whole-run average. Setup (allocation, key copies, first touch of 565 KB per
// lane set) happens before the clock starts, or the first window would be
// measuring malloc.
static std::atomic<uint64_t> g_hashes{0};
static std::atomic<int> g_ready{0};
static std::atomic<bool> g_go{false};
static bool g_peak_mode = false;

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

	if (g_peak_mode) {
		// Everyone is warm and allocated before anyone starts counting.
		g_ready.fetch_add(1, std::memory_order_release);
		while (!g_go.load(std::memory_order_acquire))
			sched_yield();
	}

	const double t0 = now_seconds();
	const double deadline = t0 + j->seconds;
	uint64_t count = 0;
	uint64_t published = 0;
	uint32_t nonce = j->nonce_base;

	// Progress is published once per inner block, not per wave: at 64 lanes a
	// block is ~140 us of work, which is fine granularity against a 100 ms
	// sampling window and keeps 10 threads off one contended cache line.
	if (j->lanes) {
		const int n = h.lanes();
		do {
			for (int rep = 0; rep < 64; ++rep) {
				h.run_wave(nonce, 0);
				nonce += (uint32_t)n;
				count += (uint64_t)n;
			}
			if (g_peak_mode) {
				g_hashes.fetch_add(count - published, std::memory_order_relaxed);
				published = count;
			}
		} while (now_seconds() < deadline);
	} else {
		do {
			for (int rep = 0; rep < 512; ++rep) {
				h.run_one(nonce++, 0);
				++count;
			}
			if (g_peak_mode) {
				g_hashes.fetch_add(count - published, std::memory_order_relaxed);
				published = count;
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

// Best rate over any run of `span` consecutive windows.
static double best_span(const std::vector<double> &t, const std::vector<uint64_t> &c,
                        size_t span, double *at_when)
{
	double best = 0;
	if (t.size() <= span)
		return 0;
	for (size_t i = 0; i + span < t.size(); ++i) {
		const double dt = t[i + span] - t[i];
		if (dt <= 0)
			continue;
		const double r = (double)(c[i + span] - c[i]) / dt;
		if (r > best) {
			best = r;
			if (at_when)
				*at_when = t[i] - t[0];
		}
	}
	return best;
}

static void run_peak(const Template &tpl, int lanes, int threads, size_t pad,
                     double seconds, double window_ms)
{
	g_peak_mode = true;
	Job jobs[64];
	pthread_t tids[64];
	if (threads > 64)
		threads = 64;

	for (int i = 0; i < threads; ++i) {
		jobs[i] = Job{&tpl, lanes, pad, seconds, (uint32_t)(i * 0x01000000u), 0, false};
		pthread_create(&tids[i], nullptr, worker, &jobs[i]);
	}
	while (g_ready.load(std::memory_order_acquire) < threads)
		usleep(200);

	std::vector<double> ts;
	std::vector<uint64_t> cs;
	const double window_us = window_ms * 1000.0;

	g_go.store(true, std::memory_order_release);
	const double t0 = now_seconds();
	ts.push_back(t0);
	cs.push_back(0);
	while (now_seconds() - t0 < seconds) {
		usleep((useconds_t)window_us);
		ts.push_back(now_seconds());
		cs.push_back(g_hashes.load(std::memory_order_relaxed));
	}
	for (int i = 0; i < threads; ++i)
		pthread_join(tids[i], nullptr);

	const double total_t = ts.back() - ts.front();
	const double avg = total_t > 0 ? (double)cs.back() / total_t : 0;

	// Report the peak at three granularities. A single short window can catch
	// a scheduling burst; if the 1 s figure tracks the 100 ms one, the peak is
	// real rather than an artefact of the sampling rate.
	double when1 = 0, when5 = 0, when10 = 0;
	const double p1 = best_span(ts, cs, 1, &when1);
	const double p5 = best_span(ts, cs, 5, &when5);
	const double p10 = best_span(ts, cs, 10, &when10);

	printf("\n  PEAK  %.2f MH/s\n\n", p1 / 1e6);
	printf("  best %.0f ms window : %8.2f MH/s   (at t+%.1fs)\n", window_ms, p1 / 1e6, when1);
	printf("  best %.0f ms window : %8.2f MH/s   (at t+%.1fs)\n", window_ms * 5, p5 / 1e6,
	       when5);
	printf("  best %.0f ms window : %8.2f MH/s   (at t+%.1fs)\n", window_ms * 10, p10 / 1e6,
	       when10);
	printf("  whole-run average  : %8.2f MH/s   (%llu hashes in %.2fs)\n", avg / 1e6,
	       (unsigned long long)cs.back(), total_t);

	printf("\n  timeline (%.0f ms windows, MH/s):\n   ", window_ms);
	for (size_t i = 1; i < ts.size(); ++i) {
		const double dt = ts[i] - ts[i - 1];
		printf(" %.1f", dt > 0 ? (double)(cs[i] - cs[i - 1]) / dt / 1e6 : 0.0);
		if ((i % 10) == 0 && i + 1 < ts.size())
			printf("\n   ");
	}
	printf("\n");
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
	size_t pad = 64;
	double seconds = 8.0;
	bool sweep_lanes = false, sweep_pad = false, peak = false;
	double window_ms = 100.0;

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
		else if (!strcmp(a, "--peak"))
			peak = true;
		else if (!strcmp(a, "--window"))
			window_ms = atof(val());
		else {
			printf("usage: vh22-bench [--lanes N|0] [--threads N] [--pad BYTES]\n"
			       "                  [--seconds S] [--sweep-lanes] [--sweep-pad]\n"
			       "                  [--peak] [--window MS]\n"
			       "  --lanes 0 runs the single-stream kernel.\n"
			       "  --peak    reports the fastest sampled window, not the average.\n");
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

	if (peak) {
		printf("peak run: %d lanes, %d threads, pad %zu, %.1fs, %.0f ms windows\n", lanes,
		       threads, pad, seconds, window_ms);
		run_peak(tpl, lanes, threads, pad, seconds, window_ms);
		return 0;
	}

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
