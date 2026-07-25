#include "ref.h"

#include <string.h>

namespace vh22 {
namespace ref {

bool g_reduction_index_overflow = false;

// --- little helpers -------------------------------------------------------

static inline uint32_t get32(const u128 &v, int i)
{
	uint32_t x;
	memcpy(&x, v.b + 4 * i, 4);
	return x;
}
static inline void set32(u128 &v, int i, uint32_t x) { memcpy(v.b + 4 * i, &x, 4); }
static inline uint64_t get64(const u128 &v, int i)
{
	uint64_t x;
	memcpy(&x, v.b + 8 * i, 8);
	return x;
}
static inline void set64(u128 &v, int i, uint64_t x) { memcpy(v.b + 8 * i, &x, 8); }
static inline int16_t get16s(const u128 &v, int i)
{
	int16_t x;
	memcpy(&x, v.b + 2 * i, 2);
	return x;
}
static inline void set16(u128 &v, int i, uint16_t x) { memcpy(v.b + 2 * i, &x, 2); }

u128 vxor(u128 a, u128 b)
{
	u128 r;
	for (int i = 0; i < 16; ++i)
		r.b[i] = a.b[i] ^ b.b[i];
	return r;
}

uint64_t low64(u128 a) { return get64(a, 0); }

u128 unpacklo32(u128 a, u128 b)
{
	u128 r;
	set32(r, 0, get32(a, 0));
	set32(r, 1, get32(b, 0));
	set32(r, 2, get32(a, 1));
	set32(r, 3, get32(b, 1));
	return r;
}
u128 unpackhi32(u128 a, u128 b)
{
	u128 r;
	set32(r, 0, get32(a, 2));
	set32(r, 1, get32(b, 2));
	set32(r, 2, get32(a, 3));
	set32(r, 3, get32(b, 3));
	return r;
}
u128 unpacklo64(u128 a, u128 b)
{
	u128 r;
	set64(r, 0, get64(a, 0));
	set64(r, 1, get64(b, 0));
	return r;
}
u128 unpackhi64(u128 a, u128 b)
{
	u128 r;
	set64(r, 0, get64(a, 1));
	set64(r, 1, get64(b, 1));
	return r;
}

// --- AES ------------------------------------------------------------------

static const uint8_t kSbox[256] = {
	0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
	0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
	0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
	0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
	0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
	0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
	0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
	0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
	0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
	0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
	0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
	0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
	0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
	0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
	0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
	0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
};

static inline uint8_t xtime(uint8_t a)
{
	return (uint8_t)((a << 1) ^ ((a >> 7) * 0x1b));
}

u128 aesenc(u128 x, u128 k)
{
	// State byte i is (row = i % 4, column = i / 4). ShiftRows rotates row r
	// left by r columns, so output byte c*4+r comes from ((c+r) % 4)*4 + r.
	uint8_t s[16];
	for (int i = 0; i < 16; ++i) {
		const int r = i & 3, c = i >> 2;
		s[i] = kSbox[x.b[(((c + r) & 3) << 2) + r]];
	}

	u128 out;
	for (int c = 0; c < 4; ++c) {
		const uint8_t a0 = s[4 * c + 0], a1 = s[4 * c + 1];
		const uint8_t a2 = s[4 * c + 2], a3 = s[4 * c + 3];
		out.b[4 * c + 0] = (uint8_t)(xtime(a0) ^ (xtime(a1) ^ a1) ^ a2 ^ a3);
		out.b[4 * c + 1] = (uint8_t)(a0 ^ xtime(a1) ^ (xtime(a2) ^ a2) ^ a3);
		out.b[4 * c + 2] = (uint8_t)(a0 ^ a1 ^ xtime(a2) ^ (xtime(a3) ^ a3));
		out.b[4 * c + 3] = (uint8_t)((xtime(a0) ^ a0) ^ a1 ^ a2 ^ xtime(a3));
	}
	return vxor(out, k);
}

// --- carry-less multiply --------------------------------------------------

u128 clmul_lo_hi(u128 a, u128 b)
{
	const uint64_t x = get64(a, 0);  // imm bit 0 == 0: low half of a
	const uint64_t y = get64(b, 1);  // imm bit 4 == 1: high half of b
	uint64_t lo = 0, hi = 0;
	for (int i = 0; i < 64; ++i) {
		if ((y >> i) & 1) {
			lo ^= x << i;
			if (i)
				hi ^= x >> (64 - i);
		}
	}
	u128 r;
	set64(r, 0, lo);
	set64(r, 1, hi);
	return r;
}

// --- mulhrs ---------------------------------------------------------------

u128 mulhrs(u128 a, u128 b)
{
	u128 r;
	for (int i = 0; i < 8; ++i) {
		const int32_t p = (int32_t)get16s(a, i) * (int32_t)get16s(b, i);
		set16(r, i, (uint16_t)(((p + (1 << 14)) >> 15) & 0xffff));
	}
	return r;
}

// --- Haraka ---------------------------------------------------------------

static u128 rc_from_words(uint32_t w3, uint32_t w2, uint32_t w1, uint32_t w0)
{
	// _mm_set_epi32(e3, e2, e1, e0) places e0 in the low 32 bits.
	u128 v;
	set32(v, 0, w0);
	set32(v, 1, w1);
	set32(v, 2, w2);
	set32(v, 3, w3);
	return v;
}

#define RC(a, b, c, d) rc_from_words(0x##a, 0x##b, 0x##c, 0x##d)
const u128 haraka_rc[40] = {
	RC(0684704c, e620c00a, b2c5fef0, 75817b9d), RC(8b66b4e1, 88f3a06b, 640f6ba4, 2f08f717),
	RC(3402de2d, 53f28498, cf029d60, 9f029114), RC(0ed6eae6, 2e7b4f08, bbf3bcaf, fd5b4f79),
	RC(cbcfb0cb, 4872448b, 79eecd1c, be397044), RC(7eeacdee, 6e9032b7, 8d5335ed, 2b8a057b),
	RC(67c28f43, 5e2e7cd0, e2412761, da4fef1b), RC(2924d9b0, afcacc07, 675ffde2, 1fc70b3b),
	RC(ab4d63f1, e6867fe9, ecdb8fca, b9d465ee), RC(1c30bf84, d4b7cd64, 5b2a404f, ad037e33),
	RC(b2cc0bb9, 941723bf, 69028b2e, 8df69800), RC(fa0478a6, de6f5572, 4aaa9ec8, 5c9d2d8a),
	RC(dfb49f2b, 6b772a12, 0efa4f2e, 29129fd4), RC(1ea10344, f449a236, 32d611ae, bb6a12ee),
	RC(af044988, 4b050084, 5f9600c9, 9ca8eca6), RC(21025ed8, 9d199c4f, 78a2c7e3, 27e593ec),
	RC(bf3aaaf8, a759c9b7, b9282ecd, 82d40173), RC(6260700d, 6186b017, 37f2efd9, 10307d6b),
	RC(5aca45c2, 21300443, 81c29153, f6fc9ac6), RC(9223973c, 226b68bb, 2caf92e8, 36d1943a),
	RC(d3bf9238, 225886eb, 6cbab958, e51071b4), RC(db863ce5, aef0c677, 933dfddd, 24e1128d),
	RC(bb606268, ffeba09c, 83e48de3, cb2212b1), RC(734bd3dc, e2e4d19c, 2db91a4e, c72bf77d),
	RC(43bb47c3, 61301b43, 4b1415c4, 2cb3924e), RC(dba775a8, e707eff6, 03b231dd, 16eb6899),
	RC(6df3614b, 3c755977, 8e5e2302, 7eca472c), RC(cda75a17, d6de7d77, 6d1be5b9, b88617f9),
	RC(ec6b43f0, 6ba8e9aa, 9d6c069d, a946ee5d), RC(cb1e6950, f957332b, a2531159, 3bf327c1),
	RC(2cee0c75, 00da619c, e4ed0353, 600ed0d9), RC(f0b1a5a1, 96e90cab, 80bbbabc, 63a4a350),
	RC(ae3db102, 5e962988, ab0dde30, 938dca39), RC(17bb8f38, d554a40b, 8814f3a8, 2e75b442),
	RC(34bb8a5b, 5f427fd7, aeb6b779, 360a16f6), RC(26f65241, cbe55438, 43ce5918, ffbaafde),
	RC(4ce99a54, b9f3026a, a2ca9cf7, 839ec978), RC(ae51a51a, 1bdff7be, 40c06e28, 22901235),
	RC(a0c1613c, ba7ed22b, c173bc0f, 48a659cf), RC(756acc03, 02288288, 4ad6bdfd, e9c59da1),
};
#undef RC

static inline u128 load16(const uint8_t *p)
{
	u128 v;
	memcpy(v.b, p, 16);
	return v;
}

void haraka256(uint8_t out[32], const uint8_t in[32])
{
	u128 s0 = load16(in), s1 = load16(in + 16);
	for (int g = 0; g < 5; ++g) {
		const int rci = 4 * g;
		s0 = aesenc(s0, haraka_rc[rci + 0]);
		s1 = aesenc(s1, haraka_rc[rci + 1]);
		s0 = aesenc(s0, haraka_rc[rci + 2]);
		s1 = aesenc(s1, haraka_rc[rci + 3]);
		const u128 t = unpacklo32(s0, s1);
		s1 = unpackhi32(s0, s1);
		s0 = t;
	}
	s0 = vxor(s0, load16(in));
	s1 = vxor(s1, load16(in + 16));
	memcpy(out, s0.b, 16);
	memcpy(out + 16, s1.b, 16);
}

void haraka512_keyed(uint8_t out[32], const uint8_t in[64], const u128 *rc)
{
	u128 s[4] = {load16(in), load16(in + 16), load16(in + 32), load16(in + 48)};
	for (int g = 0; g < 5; ++g) {
		const int rci = 8 * g;
		for (int i = 0; i < 4; ++i)
			s[i] = aesenc(s[i], rc[rci + i]);
		for (int i = 0; i < 4; ++i)
			s[i] = aesenc(s[i], rc[rci + 4 + i]);

		const u128 tmp = unpacklo32(s[0], s[1]);
		s[0] = unpackhi32(s[0], s[1]);
		s[1] = unpacklo32(s[2], s[3]);
		s[2] = unpackhi32(s[2], s[3]);
		s[3] = unpacklo32(s[0], s[2]);
		s[0] = unpackhi32(s[0], s[2]);
		s[2] = unpackhi32(s[1], tmp);
		s[1] = unpacklo32(s[1], tmp);
	}
	for (int i = 0; i < 4; ++i)
		s[i] = vxor(s[i], load16(in + 16 * i));

	// Truncation: b[8:16] || b[24:32] || b[32:40] || b[48:56]
	const u128 t0 = unpackhi64(s[0], s[1]);
	const u128 t1 = unpacklo64(s[2], s[3]);
	memcpy(out, t0.b, 16);
	memcpy(out + 16, t1.b, 16);
}

// --- key expansion --------------------------------------------------------

void gen_key(const uint8_t seed[32], u128 *key_out)
{
	uint8_t *pkey = (uint8_t *)key_out;
	const uint8_t *psrc = seed;
	const size_t blocks = KEY_BYTES >> 5;
	const size_t extra = KEY_BYTES & 0x1f;
	for (size_t i = 0; i < blocks; ++i) {
		haraka256(pkey, psrc);
		psrc = pkey;
		pkey += 32;
	}
	if (extra) {
		uint8_t buf[32];
		haraka256(buf, psrc);
		memcpy(pkey, buf, extra);
	}
}

// --- clhash ---------------------------------------------------------------

static inline u128 CL(u128 v) { return clmul_lo_hi(v, v); }

// The eight step bodies, transcribed from the reference in their original
// serial form. Cases 5 and 6 in particular are kept exactly as written --
// the optimised engine restructures both, and this is what proves the
// restructuring bit-exact.
static void step(u128 *key, const u128 *pbuf_copy, u128 &acc, uint32_t *touched, int i)
{
	const uint64_t selector = low64(acc);
	const uint32_t prand_idx = (uint32_t)((selector >> 5) & 511);
	const uint32_t prandex_idx = (uint32_t)((selector >> 32) & 511);
	u128 *prand = key + prand_idx;
	u128 *prandex = key + prandex_idx;
	touched[i] = prand_idx | (prandex_idx << 16);

	const int base = (int)(selector & 3);
	const u128 *pbuf = pbuf_copy + base;
	// pbuf[-1] when selector is odd, pbuf[+1] when even -- always inside
	// pbuf_copy[0..3], and always equal to pbuf_copy[base ^ 1].
	const u128 *pbuf_alt = pbuf_copy + (base ^ 1);

	switch ((selector >> 2) & 7) {
	case 0: {
		const u128 temp1 = *prandex;
		const u128 temp2 = *pbuf_alt;
		acc = vxor(CL(vxor(temp1, temp2)), acc);

		const u128 tempa2 = vxor(mulhrs(acc, temp1), temp1);
		const u128 temp12 = *prand;
		*prand = tempa2;

		const u128 temp22 = *pbuf;
		acc = vxor(CL(vxor(temp12, temp22)), acc);
		*prandex = vxor(mulhrs(acc, temp12), temp12);
		break;
	}
	case 1: {
		const u128 temp1 = *prand;
		const u128 temp2 = *pbuf;
		acc = vxor(CL(vxor(temp1, temp2)), acc);
		acc = vxor(CL(temp2), acc);

		const u128 tempa2 = vxor(mulhrs(acc, temp1), temp1);
		const u128 temp12 = *prandex;
		*prandex = tempa2;

		const u128 temp22 = *pbuf_alt;
		acc = vxor(vxor(temp12, temp22), acc);
		*prand = vxor(mulhrs(acc, temp12), temp12);
		break;
	}
	case 2: {
		const u128 temp1 = *prandex;
		const u128 temp2 = *pbuf;
		acc = vxor(vxor(temp1, temp2), acc);

		const u128 tempa2 = vxor(mulhrs(acc, temp1), temp1);
		const u128 temp12 = *prand;
		*prand = tempa2;

		const u128 temp22 = *pbuf_alt;
		acc = vxor(CL(vxor(temp12, temp22)), acc);
		acc = vxor(CL(temp22), acc);
		*prandex = vxor(mulhrs(acc, temp12), temp12);
		break;
	}
	case 3: {
		const u128 temp1 = *prand;
		const u128 temp2 = *pbuf_alt;
		const u128 add1 = vxor(temp1, temp2);

		const int32_t divisor = (int32_t)(uint32_t)selector;  // cannot be zero
		acc = vxor(add1, acc);

		const int64_t dividend = (int64_t)low64(acc);
		u128 modulo = {};
		set32(modulo, 0, (uint32_t)(int32_t)(dividend % divisor));
		acc = vxor(modulo, acc);

		const u128 tempa2 = vxor(mulhrs(acc, temp1), temp1);

		if (dividend & 1) {
			const u128 temp12 = *prandex;
			*prandex = tempa2;

			const u128 temp22 = *pbuf;
			acc = vxor(CL(vxor(temp12, temp22)), acc);
			acc = vxor(CL(temp22), acc);
			*prand = vxor(mulhrs(acc, temp12), temp12);
		} else {
			*prand = *prandex;
			*prandex = tempa2;
			acc = vxor(*pbuf, acc);
		}
		break;
	}
	case 4: {
		u128 temp1 = *pbuf_alt;
		u128 temp2 = *pbuf;
		for (int g = 0; g < 3; ++g) {
			const int rci = 4 * g;
			temp1 = aesenc(temp1, haraka_rc[rci + 0]);
			temp2 = aesenc(temp2, haraka_rc[rci + 1]);
			temp1 = aesenc(temp1, haraka_rc[rci + 2]);
			temp2 = aesenc(temp2, haraka_rc[rci + 3]);
			const u128 t = unpacklo32(temp1, temp2);
			temp2 = unpackhi32(temp1, temp2);
			temp1 = t;
		}
		acc = vxor(temp2, vxor(temp1, acc));

		const u128 tempa1 = *prand;
		const u128 tempa2 = mulhrs(acc, tempa1);
		*prand = *prandex;
		*prandex = vxor(tempa1, tempa2);
		break;
	}
	case 5: {
		uint64_t rounds = selector >> 61;  // 1..8 iterations
		const u128 *rc = prand;
		uint64_t aesroundoffset = 0;
		do {
			u128 onekey = *rc++;
			if (selector & (((uint64_t)0x10000000) << rounds)) {
				const u128 temp2 = (rounds & 1) ? *pbuf : *pbuf_alt;
				acc = vxor(CL(vxor(onekey, temp2)), acc);
			} else {
				u128 temp2 = (rounds & 1) ? *pbuf_alt : *pbuf;
				const uint64_t ri = aesroundoffset++ << 2;
				onekey = aesenc(onekey, rc[ri + 0]);
				temp2 = aesenc(temp2, rc[ri + 1]);
				onekey = aesenc(onekey, rc[ri + 2]);
				temp2 = aesenc(temp2, rc[ri + 3]);
				const u128 t = unpacklo32(onekey, temp2);
				temp2 = unpackhi32(onekey, temp2);
				onekey = t;
				acc = vxor(onekey, acc);
				acc = vxor(temp2, acc);
			}
		} while (rounds--);

		const u128 tempa1 = *prand;
		const u128 tempa3 = vxor(tempa1, mulhrs(acc, tempa1));
		const u128 tempa4 = *prandex;
		*prandex = tempa3;
		*prand = tempa4;
		break;
	}
	case 6: {
		uint64_t rounds = selector >> 61;  // 1..8 iterations
		const u128 *rc = prand;
		u128 onekey = {};
		do {
			if (selector & (((uint64_t)0x10000000) << rounds)) {
				const u128 temp2 = (rounds & 1) ? *pbuf : *pbuf_alt;
				onekey = vxor(rc[0], temp2);
				++rc;
				const int32_t divisor = (int32_t)(uint32_t)selector;
				const int64_t dividend = (int64_t)low64(onekey);
				u128 modulo = {};
				set32(modulo, 0, (uint32_t)(int32_t)(dividend % divisor));
				acc = vxor(modulo, acc);
			} else {
				const u128 temp2 = (rounds & 1) ? *pbuf_alt : *pbuf;
				const u128 add1 = vxor(rc[0], temp2);
				++rc;
				onekey = CL(add1);
				acc = vxor(mulhrs(acc, onekey), acc);
			}
		} while (rounds--);

		const u128 tempa3 = *prandex;
		*prandex = onekey;
		*prand = vxor(tempa3, acc);
		break;
	}
	case 7: {
		const u128 temp1 = *pbuf;
		const u128 temp2 = *prandex;
		acc = vxor(CL(vxor(temp1, temp2)), acc);

		const u128 tempa2 = vxor(mulhrs(acc, temp2), temp2);
		const u128 tempa3 = *prand;
		*prand = tempa2;

		acc = vxor(tempa3, acc);
		acc = vxor(*pbuf_alt, acc);
		*prandex = vxor(mulhrs(acc, tempa3), tempa3);
		break;
	}
	}
}

// Modulo reduction to 64 bits over the (64,4,3,1,0) polynomial.
static uint64_t precomp_reduction64(u128 A)
{
	static const uint8_t table[16] = {0,   27,  54,  45,  108, 119, 90,  65,
	                                  216, 195, 238, 245, 180, 175, 130, 153};
	u128 C = {};
	set64(C, 0, (1U << 4) + (1U << 3) + (1U << 1) + (1U << 0));

	// _mm_clmulepi64_si128(A, C, 0x01): A[127:64] times C[63:0]
	const uint64_t x = get64(A, 1);
	const uint64_t y = get64(C, 0);
	uint64_t lo = 0, hi = 0;
	for (int i = 0; i < 64; ++i) {
		if ((y >> i) & 1) {
			lo ^= x << i;
			if (i)
				hi ^= x >> (64 - i);
		}
	}
	u128 Q2 = {};
	set64(Q2, 0, lo);
	set64(Q2, 1, hi);

	// Q2 >> 64 bits, then a byte shuffle. C has degree 4 and A's high half is
	// 64 bits, so the product is at most 68 bits: Q2's high half is 4 bits
	// wide, every shuffle index lands in [0,15], and TBL == PSHUFB here.
	// g_reduction_index_overflow latches if that reasoning is ever wrong.
	u128 Q3 = {};
	for (int i = 8; i < 16; ++i)
		if (Q2.b[i] > 15)
			g_reduction_index_overflow = true;
	Q3.b[0] = table[Q2.b[8] & 0x0f];

	const u128 Q4 = vxor(Q2, A);
	return low64(vxor(Q3, Q4));
}

uint64_t clhash(u128 *key, const uint8_t buf[64], uint32_t touched[STEPS])
{
	const u128 b0 = load16(buf), b1 = load16(buf + 16);
	const u128 b2 = load16(buf + 32), b3 = load16(buf + 48);
	const u128 pbuf_copy[4] = {vxor(b0, b2), vxor(b1, b3), b2, b3};

	u128 acc = key[MUTABLE_VECS + 1];  // keyMask + 2 == 513
	for (int i = 0; i < (int)STEPS; ++i)
		step(key, pbuf_copy, acc, touched, i);

	// lazyLengthHash(1024, 64) = clmul(x^6, x^10) = x^16 = 0x10000.
	u128 lh = {};
	set64(lh, 0, 0x10000);
	return precomp_reduction64(vxor(acc, lh));
}

// --- full hash ------------------------------------------------------------

void hash_half(uint8_t out[64], const uint8_t *data, size_t len)
{
	uint8_t buf1[64] = {0}, buf2[64] = {0};
	uint8_t *curBuf = buf1, *result = buf2;
	size_t curPos = 0;

	for (size_t pos = 0; pos < len;) {
		const size_t room = 32 - curPos;
		if (len - pos >= room) {
			memcpy(curBuf + 32 + curPos, data + pos, room);
			haraka512(result, curBuf);
			uint8_t *tmp = curBuf;
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

void hash_nonce(uint8_t out[32], const uint8_t half[64], const u128 *pristine_key,
                uint32_t nonce)
{
	u128 key[KEY_VECS];
	memcpy(key, pristine_key, KEY_BYTES);

	uint8_t buf[64];
	memcpy(buf, half, 64);
	// The nonce region: byte 47 and 48..63 are refilled from the 16 bytes at
	// offset 0, rotated by one, and the nonce itself sits at 43..46.
	buf[47] = half[0];
	for (int i = 0; i < 15; ++i)
		buf[48 + i] = half[1 + i];
	buf[63] = half[0];
	memcpy(buf + 43, &nonce, 4);

	uint32_t touched[STEPS];
	const uint64_t intermediate = clhash(key, buf, touched);

	// Refill the tail from the 64-bit intermediate, rotated one byte left.
	uint8_t im[8];
	memcpy(im, &intermediate, 8);
	buf[47] = im[0];
	for (int i = 0; i < 16; ++i)
		buf[48 + i] = im[(i + 1) & 7];

	haraka512_keyed(out, buf, key + (intermediate & 511));
}

} // namespace ref
} // namespace vh22
