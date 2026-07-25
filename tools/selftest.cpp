// Differential test harness. Priority-list item #1: nothing else in this tree
// is safe without it.
//
// Every optimised path is diffed against ref/, which is intrinsic-free C++
// written straight from the definitions. The saturation test is constructed
// rather than sampled -- hoping to hit a = b = -32768 by chance would take
// ~10^7 hashes, so the key and accumulator are solved backwards to force it.
#include "vh22/verushash.h"
#include "ref.h"

#include <initializer_list>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>

using namespace vh22;

static int g_fail = 0;
static int g_checks = 0;

static void check(bool ok, const char *what)
{
	++g_checks;
	if (!ok) {
		++g_fail;
		printf("  FAIL  %s\n", what);
	}
}

static bool same(const void *a, const void *b, size_t n)
{
	return memcmp(a, b, n) == 0;
}

// --- deterministic PRNG ---------------------------------------------------

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
		while (n >= 8) {
			const uint64_t v = next();
			memcpy(q, &v, 8);
			q += 8;
			n -= 8;
		}
		if (n) {
			const uint64_t v = next();
			memcpy(q, &v, n);
		}
	}
};

// --- primitives -----------------------------------------------------------

static void test_primitives()
{
	printf("primitives\n");
	Rng rng(1);

	// §4: SQRDMULH against the exact definition, with the boundary forced.
	for (int trial = 0; trial < 20000; ++trial) {
		alignas(16) uint8_t a[16], b[16];
		rng.fill(a, 16);
		rng.fill(b, 16);
		if (trial < 8) {
			// Plant the one divergent input in every lane position.
			const uint16_t min16 = 0x8000;
			memcpy(a + 2 * trial, &min16, 2);
			memcpy(b + 2 * trial, &min16, 2);
		}
		ref::u128 ra, rb;
		memcpy(ra.b, a, 16);
		memcpy(rb.b, b, 16);
		const ref::u128 want = ref::mulhrs(ra, rb);

		alignas(16) uint8_t got[16];
		vstore(got, vmulhrs_exact(vload(a), vload(b)));
		check(same(got, want.b, 16), "mulhrs_exact == reference");

		alignas(16) uint8_t fast[16];
		vstore(fast, vmulhrs_fast(vload(a), vload(b)));
		if (trial < 8)
			check(!same(fast, want.b, 16),
			      "bare SQRDMULH does diverge at a=b=-32768");
		else
			check(same(fast, want.b, 16), "bare SQRDMULH matches elsewhere");
	}

	// mulhrs(x, 0) == 0 is what makes the case-6 restructure branchless.
	for (int trial = 0; trial < 256; ++trial) {
		alignas(16) uint8_t a[16], zero[16] = {0}, got[16];
		rng.fill(a, 16);
		vstore(got, vmulhrs_fast(vload(a), vload(zero)));
		check(same(got, zero, 16), "mulhrs(x, 0) == 0 (fast)");
		vstore(got, vmulhrs_exact(vload(a), vload(zero)));
		check(same(got, zero, 16), "mulhrs(x, 0) == 0 (exact)");
	}

	// Carry-less multiply and AES.
	for (int trial = 0; trial < 4096; ++trial) {
		alignas(16) uint8_t a[16], k[16], got[16];
		rng.fill(a, 16);
		rng.fill(k, 16);
		ref::u128 ra, rk;
		memcpy(ra.b, a, 16);
		memcpy(rk.b, k, 16);

		const ref::u128 wcl = ref::clmul_lo_hi(ra, ra);
		vstore(got, vclmul_self(vload(a)));
		check(same(got, wcl.b, 16), "CL(v) == reference");

		const ref::u128 waes = ref::aesenc(ra, rk);
		vstore(got, aesenc(vload(a), vload(k)));
		check(same(got, waes.b, 16), "aesenc == reference");

		// The fused two-round form must equal two chained x86 rounds.
		alignas(16) uint8_t k2[16];
		rng.fill(k2, 16);
		ref::u128 rk2;
		memcpy(rk2.b, k2, 16);
		const ref::u128 w2 = ref::aesenc(ref::aesenc(ra, rk), rk2);
		vstore(got, aes2_fused(vload(a), vload(k), vload(k2)));
		check(same(got, w2.b, 16), "aes2_fused == two chained aesencs");
	}
}

// --- Haraka ---------------------------------------------------------------

static void test_haraka()
{
	printf("haraka\n");

	// Known answer from the upstream test vector.
	static const uint8_t kExpect512[32] = {
		0xbe, 0x7f, 0x72, 0x3b, 0x4e, 0x80, 0xa9, 0x98, 0x13, 0xb2, 0x92,
		0x28, 0x7f, 0x30, 0x6f, 0x62, 0x5a, 0x6d, 0x57, 0x33, 0x1c, 0xae,
		0x5f, 0x34, 0xdd, 0x92, 0x77, 0xb0, 0x94, 0x5b, 0xe2, 0xaa};
	alignas(64) uint8_t in[64], out[32];
	for (int i = 0; i < 64; ++i)
		in[i] = (uint8_t)(i % 64);
	haraka512(out, in);
	check(same(out, kExpect512, 32), "haraka512 known-answer vector");

	Rng rng(2);
	for (int trial = 0; trial < 2000; ++trial) {
		alignas(64) uint8_t buf[64], got[32], want[32];
		rng.fill(buf, 64);

		haraka256(got, buf);
		ref::haraka256(want, buf);
		check(same(got, want, 32), "haraka256 == reference");

		alignas(16) uint8_t rcbytes[40 * 16];
		rng.fill(rcbytes, sizeof(rcbytes));
		haraka512_keyed(got, buf, (const v128 *)rcbytes);
		ref::haraka512_keyed(want, buf, (const ref::u128 *)rcbytes);
		check(same(got, want, 32), "haraka512_keyed == reference");

		uint32_t hw_full;
		memcpy(&hw_full, want + 28, 4);
		const uint32_t hw = haraka512_keyed_highword(buf, (const v128 *)rcbytes);
		check(hw == hw_full, "highword == bytes 28..31 of the full digest");
	}
}

// --- clhash ---------------------------------------------------------------

struct KeyPair {
	alignas(64) uint8_t opt[kKeyBytes];
	alignas(64) uint8_t reference[kKeyBytes];
	void randomize(Rng &rng)
	{
		rng.fill(opt, kKeyBytes);
		memcpy(reference, opt, kKeyBytes);
	}
};

static void test_clhash_scalar()
{
	printf("clhash (scalar)\n");
	Rng rng(3);
	for (int trial = 0; trial < 3000; ++trial) {
		KeyPair kp;
		kp.randomize(rng);
		alignas(64) uint8_t buf[64];
		rng.fill(buf, 64);

		uint32_t t_opt[kSteps], t_ref[kSteps];
		const uint64_t got = clhash_scalar<true>((v128 *)kp.opt, buf, t_opt);
		const uint64_t want = ref::clhash((ref::u128 *)kp.reference, buf, t_ref);

		check(got == want, "clhash intermediate == reference");
		check(same(kp.opt, kp.reference, kKeyBytes), "mutated key == reference");
		check(same(t_opt, t_ref, sizeof(t_opt)), "touched slots == reference");
	}
	check(!ref::g_reduction_index_overflow,
	      "reduction shuffle index stayed in [0,15] (justifies dropping AND #0x8F)");
}

static void test_clhash_wave()
{
	printf("clhash (wave)\n");
	Rng rng(4);
	for (int lanes : {1, 2, 3, 5, 8, 16, 31, 32, 64}) {
		KeyPair kp[kMaxLanes];
		alignas(64) uint8_t bufs[kMaxLanes][64];
		v128 *keyp[kMaxLanes];
		const uint8_t *bufp[kMaxLanes];
		uint32_t touched[kMaxLanes][kSteps];
		uint32_t *touchp[kMaxLanes];
		uint64_t out[kMaxLanes];

		for (int l = 0; l < lanes; ++l) {
			kp[l].randomize(rng);
			rng.fill(bufs[l], 64);
			keyp[l] = (v128 *)kp[l].opt;
			bufp[l] = bufs[l];
			touchp[l] = touched[l];
		}
		clhash_wave(keyp, bufp, touchp, out, lanes);

		for (int l = 0; l < lanes; ++l) {
			uint32_t t_ref[kSteps];
			const uint64_t want =
				ref::clhash((ref::u128 *)kp[l].reference, bufs[l], t_ref);
			check(out[l] == want, "wave lane intermediate == reference");
			check(same(kp[l].opt, kp[l].reference, kKeyBytes),
			      "wave lane key == reference");
			check(same(touched[l], t_ref, sizeof(t_ref)),
			      "wave lane touched == reference");
		}
	}
}

// --- §9: the constructed saturation case ----------------------------------
//
// Solved backwards through case 2, whose accumulator update happens before its
// first mulhrs and is a plain XOR of values we control:
//
//   acc_at_mulhrs = acc0 ^ key[prandex] ^ pbuf[selector & 3]
//
// Pick selector's low 16 bits X so the walk enters case 2 with base 2 (then
// pbuf[2] is buf[32..47] verbatim), set that buffer lane to X, set the key
// slot's lane to 0x8000, and the XOR leaves the accumulator lane at 0x8000
// against a key lane of 0x8000 -- the one input where PMULHRSW wraps and
// SQRDMULH saturates.
static void test_constructed_saturation()
{
	printf("constructed SQRDMULH saturation (§9)\n");

	// X: bits[1:0] = 2 selects pbuf[2]; bits[4:2] = 2 selects case 2.
	const uint16_t X = 0x000A;
	const uint32_t prandex_idx = 100;

	alignas(64) uint8_t key[kKeyBytes];
	Rng rng(5);
	rng.fill(key, kKeyBytes);

	// acc0 = key[513]: low 16 bits X, bits 32..40 the prandex slot.
	const uint64_t acc0_lo = (uint64_t)X | ((uint64_t)prandex_idx << 32);
	memcpy(key + 513 * 16, &acc0_lo, 8);

	const uint16_t min16 = 0x8000;
	memcpy(key + prandex_idx * 16, &min16, 2);

	alignas(64) uint8_t buf[64];
	rng.fill(buf, 64);
	memcpy(buf + 32, &X, 2);  // pbuf[2] lane 0 == X

	// Sanity-check the derivation before trusting the comparison.
	const uint64_t selector = acc0_lo;
	check(((selector >> 2) & 7) == 2, "constructed selector enters case 2");
	check((selector & 3) == 2, "constructed selector selects pbuf[2]");
	check(((selector >> 32) & 511) == prandex_idx, "constructed prandex index");

	alignas(64) uint8_t k_exact[kKeyBytes], k_fast[kKeyBytes], k_ref[kKeyBytes];
	memcpy(k_exact, key, kKeyBytes);
	memcpy(k_fast, key, kKeyBytes);
	memcpy(k_ref, key, kKeyBytes);

	uint32_t t[kSteps];
	const uint64_t want = ref::clhash((ref::u128 *)k_ref, buf, t);
	const uint64_t got_exact = clhash_scalar<true>((v128 *)k_exact, buf, t);
	const uint64_t got_fast = clhash_scalar<false>((v128 *)k_fast, buf, t);

	check(got_exact == want, "exact path matches reference at the boundary");
	check(same(k_exact, k_ref, kKeyBytes), "exact path key matches at the boundary");
	const bool key_diverged = !same(k_fast, k_ref, kKeyBytes);
	check(got_fast != want || key_diverged,
	      "bare SQRDMULH really is exercised by this input (test is not vacuous)");
	printf("    boundary reached: intermediate %s, key %s\n",
	       got_fast != want ? "diverged" : "matched",
	       key_diverged ? "diverged" : "matched");

	// The divergence must be exactly the saturating lane of the first mulhrs.
	uint16_t exact_lane, fast_lane;
	memcpy(&exact_lane, k_exact + 0 * 16, 2);
	memcpy(&fast_lane, k_fast + 0 * 16, 2);
	printf("    prand slot 0 lane 0: exact %04x, bare %04x\n", exact_lane, fast_lane);
	check(exact_lane != fast_lane, "the saturating lane is where the two differ");
}

// --- full pipeline --------------------------------------------------------

static void test_full_hash()
{
	printf("full VerusHash 2.2\n");
	Rng rng(6);

	for (int trial = 0; trial < 24; ++trial) {
		uint8_t header[1487];
		rng.fill(header, sizeof(header));

		Template tpl;
		build_template(tpl, header, sizeof(header));

		// The reference builds its own half and key from the same header.
		uint8_t ref_half[64];
		ref::hash_half(ref_half, header, sizeof(header));
		check(same(tpl.half, ref_half, 64), "hash_half == reference");

		ref::u128 ref_key[ref::KEY_VECS];
		ref::gen_key(ref_half, ref_key);
		check(same(tpl.key, ref_key, kKeyBytes), "gen_key == reference");

		Hasher h(8);
		check(h.valid(), "hasher allocated");
		h.reset(tpl);

		for (uint32_t nonce = 0; nonce < 12; ++nonce) {
			uint8_t got[32], want[32];
			h.hash_exact(nonce, got);
			ref::hash_nonce(want, ref_half, ref_key, nonce);
			check(same(got, want, 32), "hash_exact == reference");
		}

		// A wave with a wide-open target must produce the same digests, and
		// must leave every lane key back at pristine.
		const uint32_t open_target[8] = {0xffffffff, 0xffffffff, 0xffffffff,
		                                 0xffffffff, 0xffffffff, 0xffffffff,
		                                 0xffffffff, 0xffffffff};
		const uint64_t hit = h.run_wave(1000, 0xffffffff);
		check(hit == (h.lanes() == 64 ? ~0ull : ((1ull << h.lanes()) - 1)),
		      "wide-open pre-filter accepts every lane");
		for (int l = 0; l < h.lanes(); ++l) {
			uint8_t want[32];
			ref::hash_nonce(want, ref_half, ref_key, 1000 + (uint32_t)l);
			check(same(h.hash_of(l), want, 32), "wave digest == reference");
			check(hash_meets_target(h.hash_of(l), open_target),
			      "target comparison sanity");
		}

		// And the same through the single-stream path.
		for (uint32_t nonce = 2000; nonce < 2004; ++nonce) {
			uint8_t want[32];
			check(h.run_one(nonce, 0xffffffff), "run_one pre-filter accepts");
			ref::hash_nonce(want, ref_half, ref_key, nonce);
			check(same(h.hash_of(0), want, 32), "run_one digest == reference");
		}
	}
}

// The restore path is what makes 8 KB of mutable state per stream affordable;
// a leak there corrupts every subsequent nonce silently.
static void test_key_restore()
{
	printf("key restore\n");
	Rng rng(7);
	alignas(64) uint8_t pristine[kKeyBytes], live[kKeyBytes];
	rng.fill(pristine, kKeyBytes);

	for (int trial = 0; trial < 500; ++trial) {
		memcpy(live, pristine, kKeyBytes);
		alignas(64) uint8_t buf[64];
		rng.fill(buf, 64);
		uint32_t touched[kSteps];
		clhash_scalar<false>((v128 *)live, buf, touched);
		check(!same(live, pristine, kKeyBytes), "walk actually mutated the key");
		restore_key(touched, (v128 *)live, (const v128 *)pristine);
		check(same(live, pristine, kKeyBytes), "restore_key returns to pristine");
	}
}

int main()
{
	printf("vh22 differential self-test\n\n");
	test_primitives();
	test_haraka();
	test_clhash_scalar();
	test_clhash_wave();
	test_constructed_saturation();
	test_key_restore();
	test_full_hash();

	printf("\n%d checks, %d failures\n", g_checks, g_fail);
	return g_fail ? 1 : 0;
}
