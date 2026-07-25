// vh22 reference implementation — the specification, in portable C++.
//
// No intrinsics, no NEON, no assumptions about the host. Every primitive is
// spelled out from its definition: AES rounds from S-box/ShiftRows/MixColumns,
// carry-less multiply bit by bit, mulhrs as exact integer arithmetic. It is
// slow on purpose; its only job is to be obviously correct so the optimised
// engine can be diffed against it.
#pragma once

#include <stddef.h>
#include <stdint.h>

namespace vh22 {
namespace ref {

struct u128 {
	uint8_t b[16];
};

// --- primitives -----------------------------------------------------------

// x86 _mm_aesenc_si128: MixColumns(SubBytes(ShiftRows(x))) ^ k
u128 aesenc(u128 x, u128 k);
// x86 _mm_clmulepi64_si128(a, b, 0x10): a[63:0] carry-less times b[127:64]
u128 clmul_lo_hi(u128 a, u128 b);
// x86 _mm_mulhrs_epi16: per lane, (a*b + 2^14) >> 15, truncated to 16 bits
u128 mulhrs(u128 a, u128 b);

// Latches if the modulo-reduction shuffle ever sees an index above 15 -- the
// bound the optimised path relies on to drop sse2neon's defensive AND (§9).
extern bool g_reduction_index_overflow;

u128 vxor(u128 a, u128 b);
u128 unpacklo32(u128 a, u128 b);
u128 unpackhi32(u128 a, u128 b);
u128 unpacklo64(u128 a, u128 b);
u128 unpackhi64(u128 a, u128 b);
uint64_t low64(u128 a);

// --- Haraka ---------------------------------------------------------------

extern const u128 haraka_rc[40];

void haraka256(uint8_t out[32], const uint8_t in[32]);
// 32-byte truncated Haraka512 with caller-supplied round constants.
void haraka512_keyed(uint8_t out[32], const uint8_t in[64], const u128 *rc);
inline void haraka512(uint8_t out[32], const uint8_t in[64])
{
	haraka512_keyed(out, in, haraka_rc);
}

// --- VerusHash 2.2 --------------------------------------------------------

enum : size_t {
	KEY_BYTES = 8832,    // VERUSKEYSIZE: 8 KB mutable + 40 round constants
	KEY_VECS = 552,      // KEY_BYTES / 16
	MUTABLE_VECS = 512,  // the region the clhash walk mutates
	STEPS = 32,          // clhash iterations per hash
};

void gen_key(const uint8_t seed[32], u128 *key_out /* KEY_VECS entries */);

// The 32-iteration clhash walk. Mutates `key`; records the two touched slot
// indices per step into touched[32] as (prand | prandex << 16).
uint64_t clhash(u128 *key, const uint8_t buf[64], uint32_t touched[STEPS]);

// Everything before the nonce: Haraka512 chain over the header, then the
// 16-byte tail fill. Produces the 64-byte working buffer.
void hash_half(uint8_t out[64], const uint8_t *data, size_t len);

// One complete nonce evaluation, given a pristine key. Leaves `key` untouched.
void hash_nonce(uint8_t out[32], const uint8_t half[64], const u128 *pristine_key,
                uint32_t nonce);

} // namespace ref
} // namespace vh22
