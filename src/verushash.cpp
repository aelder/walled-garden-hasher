#include "vh22/verushash.h"

#include <stdlib.h>
#include <string.h>

namespace vh22 {

Template::Template()
{
	key = (v128 *)aligned_alloc(64, kKeyVecs * sizeof(v128));
	fill1 = vzero();
}
Template::~Template() { free(key); }

void hash_half(uint8_t out[64], const uint8_t *data, size_t len)
{
	alignas(64) uint8_t buf1[64] = {0}, buf2[64] = {0};
	uint8_t *cur = buf1, *res = buf2;
	size_t curPos = 0;

	for (size_t pos = 0; pos < len;) {
		const size_t room = 32 - curPos;
		if (len - pos >= room) {
			memcpy(cur + 32 + curPos, data + pos, room);
			haraka512(res, cur);
			uint8_t *tmp = cur;
			cur = res;
			res = tmp;
			pos += room;
			curPos = 0;
		} else {
			memcpy(cur + 32 + curPos, data + pos, len - pos);
			curPos += len - pos;
			pos = len;
		}
	}
	memcpy(cur + 47, cur, 16);
	memcpy(cur + 63, cur, 1);
	memcpy(out, cur, 64);
}

void gen_key(const uint8_t seed[32], v128 *key_out)
{
	uint8_t *pkey = (uint8_t *)key_out;
	const uint8_t *psrc = seed;
	const size_t blocks = kKeyBytes >> 5;
	const size_t extra = kKeyBytes & 0x1f;
	for (size_t i = 0; i < blocks; ++i) {
		haraka256(pkey, psrc);
		psrc = pkey;
		pkey += 32;
	}
	if (extra) {
		alignas(16) uint8_t tail[32];
		haraka256(tail, psrc);
		memcpy(pkey, tail, extra);
	}
}

void build_template(Template &t, const uint8_t *data, size_t len)
{
	hash_half(t.half, data, len);
	gen_key(t.half, t.key);
	const v128 first = vload(t.half);
	t.fill1 = vextq_u8(first, first, 1);  // bytes 1..15 then byte 0
	t.first_byte = t.half[0];
}

void set_nonce_space(Template &t, const uint8_t *space, size_t len)
{
	if (len > 11)
		len = 11;
	memcpy(t.half + 32, space, len);
}

bool hash_meets_target(const uint32_t hash[8], const uint32_t target[8])
{
	for (int i = 7; i >= 0; --i) {
		if (hash[i] > target[i])
			return false;
		if (hash[i] < target[i])
			return true;
	}
	return true;
}

// --- Hasher ---------------------------------------------------------------

Hasher::Hasher(int lanes, size_t stride_pad) : lanes_(lanes)
{
	if (lanes_ < 1)
		lanes_ = 1;
	if (lanes_ > kMaxLanes)
		lanes_ = kMaxLanes;
	stride_pad &= ~(size_t)63;
	stride_vecs_ = (kKeyBytes + stride_pad) / sizeof(v128);

	// 16 KB alignment gives explicit control over set mapping (§8).
	const size_t bytes = stride_vecs_ * sizeof(v128) * (size_t)(lanes_ + 2);
	const size_t align = 16384;
	storage_ = (uint8_t *)aligned_alloc(align, (bytes + align - 1) & ~(align - 1));
	if (!storage_)
		return;

	for (int l = 0; l < lanes_; ++l)
		keys_[l] = (v128 *)storage_ + (size_t)l * stride_vecs_;
	pristine_ = (v128 *)storage_ + (size_t)lanes_ * stride_vecs_;
	scratch_ = (v128 *)storage_ + (size_t)(lanes_ + 1) * stride_vecs_;
	memset(bufs_, 0, sizeof(bufs_));
	memset(hashes_, 0, sizeof(hashes_));
	fill1_ = vzero();
}

Hasher::~Hasher() { free(storage_); }

void Hasher::reset(const Template &t)
{
	memcpy(half_, t.half, 64);
	fill1_ = t.fill1;
	first_byte_ = t.first_byte;
	memcpy(pristine_, t.key, kKeyBytes);
	for (int l = 0; l < lanes_; ++l) {
		memcpy(keys_[l], pristine_, kKeyBytes);
		memcpy(bufs_[l], half_, 64);
	}
}

void Hasher::prepare(int lane, uint32_t nonce)
{
	uint8_t *buf = bufs_[lane];
	vstore(buf + 48, fill1_);
	buf[47] = first_byte_;
	memcpy(buf + 43, &nonce, sizeof(nonce));
}

// The tail refill plus the truncated Haraka512. The key read here is the one
// the walk just mutated, so this must run before restore_key.
bool Hasher::finalize(int lane, uint32_t high_target)
{
	uint8_t *buf = bufs_[lane];
	uint64_t intermediate = intermediate_[lane];

	const uint8x16_t repeated = vreinterpretq_u8_u64(vdupq_n_u64(intermediate));
	vstore(buf + 48, vextq_u8(repeated, repeated, 1));
	buf[47] = (uint8_t)intermediate;

	const v128 *rc = keys_[lane] + (intermediate & 511);
	if (haraka512_keyed_highword(buf, rc) > high_target)
		return false;
	haraka512_keyed((uint8_t *)(hashes_ + 8 * lane), buf, rc);
	return true;
}

uint64_t Hasher::run_wave(uint32_t base, uint32_t high_target)
{
	v128 *keys[kMaxLanes];
	const uint8_t *bufs[kMaxLanes];
	uint32_t *touched[kMaxLanes];
	for (int l = 0; l < lanes_; ++l) {
		prepare(l, base + (uint32_t)l);
		keys[l] = keys_[l];
		bufs[l] = bufs_[l];
		touched[l] = touched_[l];
	}

	clhash_wave(keys, bufs, touched, intermediate_, lanes_);

	uint64_t hit = 0;
	for (int l = 0; l < lanes_; ++l)
		if (finalize(l, high_target))
			hit |= (uint64_t)1 << l;
	for (int l = 0; l < lanes_; ++l)
		restore_key(touched_[l], keys_[l], pristine_);
	return hit;
}

bool Hasher::run_one(uint32_t nonce, uint32_t high_target)
{
	prepare(0, nonce);
	intermediate_[0] = clhash_scalar<false>(keys_[0], bufs_[0], touched_[0]);
	const bool hit = finalize(0, high_target);
	restore_key(touched_[0], keys_[0], pristine_);
	return hit;
}

void Hasher::hash_exact(uint32_t nonce, uint8_t out[32]) const
{
	Hasher *self = const_cast<Hasher *>(this);
	memcpy(self->scratch_, pristine_, kKeyBytes);

	alignas(64) uint8_t buf[64];
	memcpy(buf, half_, 64);
	vstore(buf + 48, fill1_);
	buf[47] = first_byte_;
	memcpy(buf + 43, &nonce, sizeof(nonce));

	uint32_t touched[kSteps];
	const uint64_t intermediate = clhash_scalar<true>(self->scratch_, buf, touched);

	const uint8x16_t repeated = vreinterpretq_u8_u64(vdupq_n_u64(intermediate));
	vstore(buf + 48, vextq_u8(repeated, repeated, 1));
	buf[47] = (uint8_t)intermediate;

	haraka512_keyed(out, buf, self->scratch_ + (intermediate & 511));
}

} // namespace vh22
