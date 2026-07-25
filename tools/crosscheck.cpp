// End-to-end cross-check against the deployed reference C.
//
// ref/ proves the engine matches the specification as this tree transcribes
// it. That leaves one gap: whether the transcription itself is faithful to the
// implementation that is actually mining. This closes it by linking the
// upstream sse2neon build directly and comparing every stage -- Haraka512, the
// key expansion, the clhash walk and its key mutation, and the final digest.
//
// Built only by `make crosscheck`, because it reaches outside the tree.
#include "vh22/verushash.h"

#include <stdio.h>
#include <string.h>

// The upstream side, compiled as its own translation unit against sse2neon.
namespace upstream {
extern "C" {
void load_constants();
void haraka256(unsigned char *out, const unsigned char *in);
void haraka512(unsigned char *out, const unsigned char *in);
void haraka512_keyed(unsigned char *out, const unsigned char *in, const void *rc);
unsigned long long verusclhashv2_2(void *random, const unsigned char buf[64],
                                   unsigned long long keyMask, unsigned *fixrand,
                                   unsigned *fixrandex, void *g_prand, void *g_prandex);
}
} // namespace upstream

using namespace vh22;

static int g_fail = 0, g_checks = 0;
static void check(bool ok, const char *what)
{
	++g_checks;
	if (!ok) {
		++g_fail;
		printf("  FAIL  %s\n", what);
	}
}

struct Rng {
	uint64_t s;
	explicit Rng(uint64_t seed) : s(seed) {}
	uint64_t next()
	{
		s += 0x9e3779b97f4a7c15ull;
		uint64_t z = s;
		z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ull;
		z = (z ^ (z >> 27)) * 0x94d049bb133111ebull;
		return z ^ (z >> 31);
	}
	void fill(void *p, size_t n)
	{
		uint8_t *q = (uint8_t *)p;
		for (size_t i = 0; i < n; ++i) {
			if ((i & 7) == 0)
				s = next();
			q[i] = (uint8_t)(s >> (8 * (i & 7)));
		}
	}
};

// Upstream VerusHashHalf, transcribed from verusscan.cpp so the comparison is
// against their control flow, not a re-derivation of it.
static void upstream_hash_half(uint8_t out[64], const uint8_t *data, int len)
{
	alignas(32) unsigned char buf1[64] = {0}, buf2[64];
	unsigned char *curBuf = buf1, *result = buf2;
	int curPos = 0;
	for (int pos = 0; pos < len;) {
		const int room = 32 - curPos;
		if (len - pos >= room) {
			memcpy(curBuf + 32 + curPos, data + pos, room);
			upstream::haraka512(result, curBuf);
			unsigned char *tmp = curBuf;
			curBuf = result;
			result = tmp;
			pos += room;
			curPos = 0;
		} else {
			memcpy(curBuf + 32 + curPos, data + pos, len - pos);
			curPos += len - pos;
			pos = len;
		}
	}
	memcpy(curBuf + 47, curBuf, 16);
	memcpy(curBuf + 63, curBuf, 1);
	memcpy(out, curBuf, 64);
}

static void upstream_gen_key(const uint8_t seed[32], uint8_t *key)
{
	const int blocks = 8832 >> 5;
	const int extra = 8832 & 0x1f;
	unsigned char *pkey = key;
	const unsigned char *psrc = seed;
	for (int i = 0; i < blocks; ++i) {
		upstream::haraka256(pkey, psrc);
		psrc = pkey;
		pkey += 32;
	}
	if (extra) {
		unsigned char tail[32];
		upstream::haraka256(tail, psrc);
		memcpy(pkey, tail, extra);
	}
}

int main()
{
	printf("vh22 cross-check against the upstream sse2neon build\n\n");
	upstream::load_constants();
	Rng rng(0x5eed);

	// Haraka512 with the fixed constants.
	for (int i = 0; i < 500; ++i) {
		alignas(64) uint8_t in[64], a[32], b[32];
		rng.fill(in, 64);
		haraka512(a, in);
		upstream::haraka512(b, in);
		check(memcmp(a, b, 32) == 0, "haraka512 == upstream");

		alignas(16) uint8_t rc[40 * 16];
		rng.fill(rc, sizeof(rc));
		haraka512_keyed(a, in, (const v128 *)rc);
		upstream::haraka512_keyed(b, in, rc);
		check(memcmp(a, b, 32) == 0, "haraka512_keyed == upstream");

		alignas(64) uint8_t in32[32];
		rng.fill(in32, 32);
		haraka256(a, in32);
		upstream::haraka256(b, in32);
		check(memcmp(a, b, 32) == 0, "haraka256 == upstream");
	}

	// The clhash walk, its intermediate, and the key it leaves behind.
	for (int i = 0; i < 300; ++i) {
		alignas(64) uint8_t k_mine[kKeyBytes], k_up[kKeyBytes], buf[64];
		rng.fill(k_mine, kKeyBytes);
		memcpy(k_up, k_mine, kKeyBytes);
		rng.fill(buf, 64);

		uint32_t t_mine[kSteps], t_up[kSteps];
		const uint64_t mine = clhash_scalar<true>((v128 *)k_mine, buf, t_mine);
		const uint64_t up = upstream::verusclhashv2_2(k_up, buf, 511, t_up, nullptr,
		                                              nullptr, nullptr);
		check(mine == up, "clhash intermediate == upstream");
		check(memcmp(k_mine, k_up, kKeyBytes) == 0, "clhash key mutation == upstream");
		check(memcmp(t_mine, t_up, sizeof(t_mine)) == 0, "touched slots == upstream");
	}

	// The whole pipeline, header to digest.
	for (int i = 0; i < 8; ++i) {
		uint8_t header[1487];
		rng.fill(header, sizeof(header));

		Template tpl;
		build_template(tpl, header, sizeof(header));

		alignas(64) uint8_t up_half[64];
		upstream_hash_half(up_half, header, sizeof(header));
		check(memcmp(tpl.half, up_half, 64) == 0, "hash_half == upstream");

		alignas(64) uint8_t up_key[kKeyBytes];
		upstream_gen_key(up_half, up_key);
		check(memcmp(tpl.key, up_key, kKeyBytes) == 0, "gen_key == upstream");

		Hasher h(16);
		h.reset(tpl);
		const uint64_t hit = h.run_wave(777, 0xffffffff);

		for (int lane = 0; lane < h.lanes(); ++lane) {
			const uint32_t nonce = 777 + (uint32_t)lane;
			check(((hit >> lane) & 1) != 0, "wide-open pre-filter accepts");

			// Upstream per-nonce path: fill the tail, walk, refill from the
			// intermediate, keyed Haraka512.
			alignas(64) uint8_t work[64], key[kKeyBytes];
			memcpy(work, up_half, 64);
			memcpy(key, up_key, kKeyBytes);
			work[47] = up_half[0];
			for (int j = 0; j < 15; ++j)
				work[48 + j] = up_half[1 + j];
			work[63] = up_half[0];
			memcpy(work + 43, &nonce, 4);

			uint32_t touched[kSteps];
			const uint64_t im = upstream::verusclhashv2_2(key, work, 511, touched,
			                                              nullptr, nullptr, nullptr);
			uint8_t im8[8];
			memcpy(im8, &im, 8);
			work[47] = im8[0];
			for (int j = 0; j < 16; ++j)
				work[48 + j] = im8[(j + 1) & 7];

			uint8_t want[32];
			upstream::haraka512_keyed(want, work, key + (im & 511) * 16);
			check(memcmp(h.hash_of(lane), want, 32) == 0,
			      "full VerusHash 2.2 digest == upstream");

			uint8_t exact[32];
			h.hash_exact(nonce, exact);
			check(memcmp(exact, want, 32) == 0, "exact path digest == upstream");
		}
	}

	printf("\n%d checks, %d failures\n", g_checks, g_fail);
	return g_fail ? 1 : 0;
}
