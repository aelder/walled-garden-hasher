// VerusHash 2.2 — the whole thing, nonce in, 256-bit digest out.
#pragma once

#include "vh22/clhash.h"
#include "vh22/haraka.h"

#include <stddef.h>
#include <stdint.h>

namespace vh22 {

// Everything that does not depend on the nonce. Built once per block template;
// the 276 chained Haraka256 calls behind `key` are ~8300 serial cycles and must
// never land in the per-nonce path.
struct Template {
	alignas(64) uint8_t half[64];
	v128 *key = nullptr;  // kKeyVecs vectors, owned
	v128 fill1;
	uint8_t first_byte = 0;

	Template();
	~Template();
	Template(const Template &) = delete;
	Template &operator=(const Template &) = delete;
};

// Haraka512 chain over the header, then the 16-byte tail fill.
void hash_half(uint8_t out[64], const uint8_t *data, size_t len);
// 276 chained Haraka256 from a 32-byte seed.
void gen_key(const uint8_t seed[32], v128 *key_out);

void build_template(Template &t, const uint8_t *data, size_t len);
// Bytes 32..42 of the working buffer carry the pool's nonce space. Patching
// them does not disturb the key seed (bytes 0..31) or the tail fill.
void set_nonce_space(Template &t, const uint8_t *space, size_t len);

// ccminer target semantics: eight little-endian 32-bit words, most significant
// first.
bool hash_meets_target(const uint32_t hash[8], const uint32_t target[8]);

// A mining context. Owns `lanes` mutable key copies plus one pristine copy.
class Hasher {
public:
	// stride_pad shifts consecutive lane keys apart by extra bytes (§8).
	//
	// The notes expect this to matter a lot, reasoning from regions exactly
	// 8192 B apart, whose bases then differ only in high address bits. That is
	// not this allocation: VERUSKEYSIZE is 8832 = 138 cache lines, not a power
	// of two, so consecutive lane bases already walk through the sets. The
	// residual is small and real -- measured on M5 at 64 lanes, 1 thread,
	// interleaved 20 s runs: 4430 kH/s at 64 B against 4397 kH/s at 0, +0.75%,
	// with everything from 384 B up clearly worse (512 B costs 1.6%).
	//
	// Must be a multiple of 64; it is rounded down if not.
	explicit Hasher(int lanes, size_t stride_pad = 64);
	~Hasher();
	Hasher(const Hasher &) = delete;
	Hasher &operator=(const Hasher &) = delete;

	bool valid() const { return storage_ != nullptr; }
	int lanes() const { return lanes_; }

	void reset(const Template &t);

	// Evaluate `lanes()` consecutive nonces from `base`. Returns a bitmask of
	// lanes whose pre-filter word passed; hash_of(lane) then holds the digest.
	uint64_t run_wave(uint32_t base, uint32_t high_target);
	// Single stream, same semantics, one nonce.
	bool run_one(uint32_t nonce, uint32_t high_target);

	const uint32_t *hash_of(int lane) const { return hashes_ + 8 * lane; }

	// Independent recomputation with exact mulhrs and a fresh key copy. Shares
	// no state with the wave loops, so a wrong lane/nonce mapping or a
	// corrupted lane key shows up as a mismatch rather than a bad share.
	void hash_exact(uint32_t nonce, uint8_t out[32]) const;

private:
	void prepare(int lane, uint32_t nonce);
	bool finalize(int lane, uint32_t high_target);

	int lanes_;
	size_t stride_vecs_;
	uint8_t *storage_ = nullptr;
	v128 *keys_[kMaxLanes];
	v128 *pristine_ = nullptr;
	v128 *scratch_ = nullptr;
	alignas(64) uint8_t bufs_[kMaxLanes][64];
	alignas(64) uint32_t touched_[kMaxLanes][kSteps];
	alignas(16) uint32_t hashes_[kMaxLanes * 8];
	uint64_t intermediate_[kMaxLanes];
	alignas(64) uint8_t half_[64];
	v128 fill1_;
	uint8_t first_byte_ = 0;
};

} // namespace vh22
