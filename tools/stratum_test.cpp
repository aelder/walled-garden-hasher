// End-to-end stratum exercise against tools/mock_pool.py.
//
// Connects, takes a job, assembles the preimage, mines it with the engine
// until the pool's target is met, submits, and checks the accounting. The
// mock validates the submit framing from its side, so between them the whole
// path is covered without pointing anything at a real pool.
#include "stratum.h"
#include "vh22/verushash.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <string>

using namespace vh22;

static int fails = 0;
static void check(bool ok, const char *what)
{
	printf("  %-46s %s\n", what, ok ? "ok" : "FAIL");
	if (!ok)
		++fails;
}

int main(int argc, char **argv)
{
	stratum::Config cfg;
	cfg.host = "127.0.0.1";
	cfg.port = "13956";
	cfg.user = "RTestWorker.vh22";
	cfg.pass = "x";
	for (int i = 1; i < argc; ++i)
		if (!strcmp(argv[i], "--port") && i + 1 < argc)
			cfg.port = argv[++i];

	stratum::Client client;
	client.start(cfg);

	// Wait for a job with a target attached.
	stratum::Job job;
	bool got = false;
	for (int i = 0; i < 200 && !got; ++i) {
		if (client.current(job) && job.valid)
			got = true;
		else
			usleep(50000);
	}
	printf("stratum end-to-end\n");
	check(got, "received a job with a target");
	if (!got) {
		client.stop();
		return 1;
	}
	check(!job.id.empty(), "job id present");
	check(job.difficulty > 0, "difficulty derived from set_target");

	// The preimage must be exactly what VerusHashHalf consumes.
	uint8_t pre[stratum::kFullBytes];
	job.build_preimage(pre);
	check(pre[140] == 0xfd && pre[141] == 0x40 && pre[142] == 0x05,
	      "CompactSize prefix precedes the solution");

	const bool pbaas = job.solution[0] >= 7 && job.solution[5] > 0;
	if (pbaas) {
		bool zeroed = true;
		for (int i = 4; i < 100; ++i)
			if (pre[i])
				zeroed = false;
		for (int i = 104; i < 140; ++i)
			if (pre[i])
				zeroed = false;
		check(zeroed, "PBaaS v7: canonical header fields zeroed");
	} else {
		check(pre[4] != 0, "pre-v7: header fields retained");
	}

	// Mine it for real against the pool's target.
	Template tpl;
	build_template(tpl, pre, stratum::kFullBytes);
	set_nonce_space(tpl, job.nonce_space, sizeof(job.nonce_space));

	Hasher h(64);
	check(h.valid(), "hasher allocated");
	h.reset(tpl);

	bool found = false;
	uint32_t found_nonce = 0;
	for (uint32_t base = 0; base < 400000 && !found; base += (uint32_t)h.lanes()) {
		const uint64_t hit = h.run_wave(base, job.target[7]);
		if (!hit)
			continue;
		for (int l = 0; l < h.lanes(); ++l) {
			if (!((hit >> l) & 1))
				continue;
			if (!hash_meets_target(h.hash_of(l), job.target))
				continue;
			found = true;
			found_nonce = base + (uint32_t)l;

			// Independent confirmation on the exact path before submitting.
			uint8_t exact[32];
			h.hash_exact(found_nonce, exact);
			check(memcmp(exact, h.hash_of(l), 32) == 0,
			      "candidate confirmed on the exact path");
			break;
		}
	}
	check(found, "found a share at the pool's target");

	if (found) {
		client.submit(job.serial, found_nonce, 0);
		for (int i = 0; i < 100; ++i) {
			if (client.stats().submitted.load())
				break;
			usleep(50000);
		}
		check(client.stats().submitted.load() == 1, "share submitted");

		for (int i = 0; i < 100; ++i) {
			if (client.stats().accepted.load() || client.stats().rejected.load() ||
			    client.stats().stale.load())
				break;
			usleep(50000);
		}
		const uint64_t a = client.stats().accepted.load();
		const uint64_t r = client.stats().rejected.load();
		const uint64_t s = client.stats().stale.load();
		printf("  accounting: accepted %llu rejected %llu stale %llu\n",
		       (unsigned long long)a, (unsigned long long)r, (unsigned long long)s);
		check(a + r + s == 1, "exactly one share accounted");
	}

	client.stop();
	printf("\n%d failure(s)\n", fails);
	return fails ? 1 : 0;
}
