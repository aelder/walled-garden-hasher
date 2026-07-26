#include "stratum.h"

#include "json.h"

#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

namespace vh22 {
namespace stratum {
namespace {

double now_wall()
{
	struct timeval tv;
	gettimeofday(&tv, nullptr);
	return (double)tv.tv_sec + (double)tv.tv_usec / 1e6;
}

int hexval(char c)
{
	if (c >= '0' && c <= '9') return c - '0';
	if (c >= 'a' && c <= 'f') return c - 'a' + 10;
	if (c >= 'A' && c <= 'F') return c - 'A' + 10;
	return -1;
}

// Returns bytes decoded; stops at the first non-hex pair.
size_t unhex(const std::string &h, uint8_t *out, size_t cap)
{
	size_t n = 0;
	for (size_t i = 0; i + 1 < h.size() && n < cap; i += 2) {
		const int hi = hexval(h[i]), lo = hexval(h[i + 1]);
		if (hi < 0 || lo < 0)
			break;
		out[n++] = (uint8_t)((hi << 4) | lo);
	}
	return n;
}

std::string tohex(const uint8_t *p, size_t n)
{
	static const char *d = "0123456789abcdef";
	std::string s;
	s.reserve(n * 2);
	for (size_t i = 0; i < n; ++i) {
		s.push_back(d[p[i] >> 4]);
		s.push_back(d[p[i] & 15]);
	}
	return s;
}

uint32_t le32(const uint8_t *p)
{
	return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
	       ((uint32_t)p[3] << 24);
}

// The pool sends the share target as 32 hex bytes; ccminer stores it reversed
// so the low-order word lands first, which is the order fulltest compares in.
void target_from_hex(const std::string &hex, uint8_t be[32], uint32_t words[8])
{
	uint8_t bin[32] = {0};
	unhex(hex, bin, 32);
	for (int i = 0; i < 32; ++i)
		be[31 - i] = bin[i];
	for (int i = 0; i < 8; ++i)
		words[i] = le32(be + 4 * i);
}

// Difficulty from the compact form the pool's target implies. Mirrors
// target_to_diff_verus so the number shown matches what the pool reports.
double target_to_diff(const uint8_t be[32])
{
	int msb = 31;
	while (msb > 0 && be[msb] == 0)
		--msb;
	const int exponent = msb + 1;
	if (exponent < 3)
		return 0;
	const uint32_t significand = ((uint32_t)be[msb] << 16) | ((uint32_t)be[msb - 1] << 8) |
	                             (uint32_t)be[msb - 2];
	if (!significand)
		return 0;
	return ldexp((double)0x0f0f0f / (double)significand, 8 * (0x20 - exponent));
}

} // namespace

void Job::build_preimage(uint8_t out[kFullBytes]) const
{
	memcpy(out, header, kHeaderBytes);
	// CompactSize prefix for 1344 bytes.
	out[kHeaderBytes + 0] = 0xfd;
	out[kHeaderBytes + 1] = 0x40;
	out[kHeaderBytes + 2] = 0x05;
	memcpy(out + kHeaderBytes + 3, solution, kSolutionBytes);

	// PBaaS merged mining: from solution version 7 with a descriptor present,
	// the canonical header fields are not part of the hashed preimage -- they
	// are zeroed and the identifying data rides in the solution's nonce space
	// instead. Getting this wrong produces shares the pool silently rejects.
	if (solution[0] >= 7 && solution[5] > 0) {
		memset(out + 4, 0, 96);    // prevhash, merkle root, sapling root
		memset(out + 104, 0, 4);   // nBits
		memset(out + 108, 0, 32);  // nNonce
		memset(out + kHeaderBytes + 3 + 8, 0, 64);  // prev/block MMR roots
	}
}

Client::Client() {}
Client::~Client() { stop(); }

void Client::set_state(State s, const std::string &note)
{
	state_.store(s);
	std::lock_guard<std::mutex> g(mu_);
	note_ = note;
}

std::string Client::status_text() const
{
	std::lock_guard<std::mutex> g(mu_);
	return note_;
}

bool Client::current(Job &out) const
{
	std::lock_guard<std::mutex> g(mu_);
	if (!job_.valid)
		return false;
	out = job_;
	return true;
}

void Client::submit(uint64_t job_serial, uint32_t nonce, uint32_t tag)
{
	std::lock_guard<std::mutex> g(mu_);
	outbox_.push_back(Pending{0, job_serial, nonce, tag});
}

void Client::start(const Config &cfg)
{
	stop();
	cfg_ = cfg;
	run_.store(true);
	th_ = std::thread([this, cfg] { run(cfg); });
}

void Client::stop()
{
	run_.store(false);
	if (fd_ >= 0)
		shutdown(fd_, SHUT_RDWR);
	if (th_.joinable())
		th_.join();
	if (fd_ >= 0) {
		close(fd_);
		fd_ = -1;
	}
	set_state(State::Disconnected, "");
}

bool Client::dial(const Config &cfg)
{
	struct addrinfo hints;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	struct addrinfo *res = nullptr;
	if (getaddrinfo(cfg.host.c_str(), cfg.port.c_str(), &hints, &res) != 0 || !res) {
		set_state(State::Failed, "cannot resolve " + cfg.host);
		return false;
	}
	int fd = -1;
	for (struct addrinfo *a = res; a; a = a->ai_next) {
		fd = socket(a->ai_family, a->ai_socktype, a->ai_protocol);
		if (fd < 0)
			continue;
		if (connect(fd, a->ai_addr, a->ai_addrlen) == 0)
			break;
		close(fd);
		fd = -1;
	}
	freeaddrinfo(res);
	if (fd < 0) {
		set_state(State::Failed, "connection refused");
		return false;
	}
	int one = 1;
	setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
	fd_ = fd;
	return true;
}

bool Client::send_line(const std::string &s)
{
	if (fd_ < 0)
		return false;
	const std::string line = s + "\n";
	size_t off = 0;
	while (off < line.size()) {
		const ssize_t n = ::send(fd_, line.data() + off, line.size() - off, 0);
		if (n <= 0) {
			if (errno == EINTR)
				continue;
			return false;
		}
		off += (size_t)n;
	}
	return true;
}

bool Client::pump_lines(std::string &carry)
{
	char buf[8192];
	const ssize_t n = ::recv(fd_, buf, sizeof(buf), 0);
	if (n == 0)
		return false;
	if (n < 0)
		return errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR;
	carry.append(buf, (size_t)n);
	for (;;) {
		const size_t nl = carry.find('\n');
		if (nl == std::string::npos)
			break;
		std::string line = carry.substr(0, nl);
		carry.erase(0, nl + 1);
		while (!line.empty() && (line.back() == '\r'))
			line.pop_back();
		if (!line.empty())
			handle_line(line);
	}
	// A pool that never sends newlines would otherwise grow this forever.
	return carry.size() < (1u << 20);
}

void Client::handle_line(const std::string &line)
{
	json::Value v;
	if (!json::parse(line, v) || v.type != json::Type::Object)
		return;

	const std::string method = v["method"].as_string();

	if (method == "mining.notify") {
		const json::Value &p = v["params"];
		// [job_id, version, prevhash, merkleroot, reserved, time, bits, clean, solution]
		if (p.arr.size() < 9)
			return;
		Job j;
		j.id = p.at(0).as_string();
		uint8_t ver[4] = {0}, prev[32] = {0}, merkle[32] = {0}, reserved[32] = {0};
		uint8_t tm[4] = {0}, bits[4] = {0};
		unhex(p.at(1).as_string(), ver, 4);
		unhex(p.at(2).as_string(), prev, 32);
		unhex(p.at(3).as_string(), merkle, 32);
		unhex(p.at(4).as_string(), reserved, 32);
		unhex(p.at(5).as_string(), tm, 4);
		unhex(p.at(6).as_string(), bits, 4);
		j.clean = p.at(7).truthy();
		unhex(p.at(8).as_string(), j.solution, kSolutionBytes);

		uint8_t *h = (uint8_t *)j.header;
		memcpy(h + 0, ver, 4);
		memcpy(h + 4, prev, 32);
		memcpy(h + 36, merkle, 32);
		memcpy(h + 68, reserved, 32);
		memcpy(h + 100, tm, 4);
		memcpy(h + 104, bits, 4);
		memset(h + 108, 0, 32);
		// The pool owns the front of the 32-byte nonce; we own the rest.
		if (!xnonce1_.empty())
			memcpy(h + 108, xnonce1_.data(),
			       xnonce1_.size() > 31 ? 31 : xnonce1_.size());
		j.ntime = le32(tm);
		// The 11 bytes that ride in the hashed tail: the front of the nonce
		// field (which carries the pool's extranonce) plus the per-thread tag
		// word. Workers overwrite bytes 7..10 with their own tag.
		memcpy(j.nonce_space, h + 108, 7);
		memcpy(j.nonce_space + 7, h + 128, 4);

		{
			std::lock_guard<std::mutex> g(mu_);
			j.serial = ++serial_;
			memcpy(j.target, job_.target, sizeof(j.target));
			j.difficulty = job_.difficulty;
			j.valid = have_target_;
			job_ = j;
		}
		set_state(State::Ready, "mining");
		return;
	}

	if (method == "mining.set_target") {
		const std::string hex = v["params"].at(0).as_string();
		if (hex.size() < 64)
			return;
		uint32_t words[8];
		uint8_t be[32];
		target_from_hex(hex, be, words);
		const double d = target_to_diff(be);
		std::lock_guard<std::mutex> g(mu_);
		memcpy(target_be_, be, 32);
		memcpy(job_.target, words, sizeof(words));
		job_.difficulty = d;
		have_target_ = true;
		if (job_.serial)
			job_.valid = true;
		stats_.difficulty.store(d);
		return;
	}

	if (method == "client.show_message")
		return;
	if (method == "client.reconnect") {
		// The pool is telling us to go away and come back.
		reconnect_requested_ = true;
		return;
	}

	// Otherwise a response to one of ours.
	if (v["id"].type == json::Type::Number) {
		const uint64_t id = (uint64_t)v["id"].as_number();
		if (id == 1) {  // mining.subscribe
			const json::Value &r = v["result"];
			// [[...subscriptions...], xnonce1, xnonce2_size]
			const std::string x1 = r.at(1).as_string();
			uint8_t raw[32];
			const size_t n = unhex(x1, raw, 32);
			xnonce1_.assign((const char *)raw, n);
			set_state(State::Authorizing, "authorizing");
			send_line("{\"id\":2,\"method\":\"mining.authorize\",\"params\":[" +
			          json::quote(cfg_.user) + "," + json::quote(cfg_.pass) + "]}");
			return;
		}
		if (id == 2) {  // mining.authorize
			if (v["result"].truthy())
				set_state(State::Ready, "waiting for work");
			else
				set_state(State::Failed, "authorize rejected");
			return;
		}
		// A share result. Stale and reject are different outcomes and the
		// pool distinguishes them only in the error text.
		std::lock_guard<std::mutex> g(mu_);
		for (size_t i = 0; i < pending_.size(); ++i) {
			if (pending_[i].id != id)
				continue;
			if (v["result"].truthy()) {
				stats_.accepted.fetch_add(1);
				stats_.last_share_time.store(now_wall());
			} else {
				std::string err;
				const json::Value &e = v["error"];
				if (e.type == json::Type::Array)
					err = e.at(1).as_string();
				else if (e.type == json::Type::String)
					err = e.str;
				for (auto &c : err)
					c = (char)tolower((unsigned char)c);
				if (err.find("stale") != std::string::npos ||
				    err.find("job not found") != std::string::npos ||
				    err.find("duplicate") != std::string::npos)
					stats_.stale.fetch_add(1);
				else
					stats_.rejected.fetch_add(1);
			}
			pending_.erase(pending_.begin() + (long)i);
			return;
		}
	}
}

void Client::run(Config cfg)
{
	// A miner has to survive the pool going away: pools restart, drop idle
	// connections and hand out client.reconnect. Backoff doubles from one
	// second to thirty, and resets whenever a session actually reached Ready
	// so a stable pool that blips does not inherit a long delay.
	int backoff = 1;
	while (run_.load()) {
		const bool reached_ready = session(cfg);
		if (!run_.load())
			break;

		if (reached_ready) {
			backoff = 1;
			stats_.reconnects.fetch_add(1);
		}

		// Keep why it failed. Overwriting it with a bare countdown leaves the
		// user staring at "reconnecting" with nothing to act on -- a wrong
		// port and a dead pool look identical, and one of them is their typo.
		const std::string why = status_text();
		char note[192];
		if (reached_ready)
			snprintf(note, sizeof(note), "connection lost — retry in %ds", backoff);
		else if (!why.empty() && why.find("retry in") == std::string::npos)
			snprintf(note, sizeof(note), "%s — retry in %ds", why.c_str(), backoff);
		else
			snprintf(note, sizeof(note), "reconnecting in %ds", backoff);
		// Red while it has never worked; grey once it has and merely dropped.
		set_state(reached_ready ? State::Disconnected : State::Failed, note);

		for (int i = 0; i < backoff * 10 && run_.load(); ++i)
			usleep(100000);
		backoff = backoff < 30 ? backoff * 2 : 30;
	}
	set_state(State::Disconnected, "");
}

bool Client::session(const Config &cfg)
{
	bool reached_ready = false;

	// Nothing survives a reconnect: the pool issues a new extranonce, so the
	// old job and target are not just stale but wrong to mine.
	{
		std::lock_guard<std::mutex> g(mu_);
		job_ = Job();
		have_target_ = false;
		xnonce1_.clear();
		// Shares we sent but never heard back about are unknowable now.
		stats_.stale.fetch_add(pending_.size());
		pending_.clear();
		outbox_.clear();
	}

	set_state(State::Resolving, "resolving " + cfg.host);
	if (!dial(cfg))
		return false;
	set_state(State::Subscribing, "subscribing");
	stats_.connected_since.store(now_wall());

	if (!send_line("{\"id\":1,\"method\":\"mining.subscribe\",\"params\":[\"vh22/1.0\"]}")) {
		set_state(State::Failed, "subscribe failed");
		close(fd_);
		fd_ = -1;
		return false;
	}

	std::string carry;
	while (run_.load() && !reconnect_requested_) {
		if (state_.load() == State::Ready)
			reached_ready = true;
		struct pollfd p = {fd_, POLLIN, 0};
		const int rc = ::poll(&p, 1, 200);
		if (rc < 0 && errno != EINTR)
			break;
		if (rc > 0 && (p.revents & (POLLIN | POLLHUP | POLLERR))) {
			if (!pump_lines(carry))
				break;
		}

		// Drain queued shares on this thread so the socket has one writer.
		std::vector<Pending> go;
		{
			std::lock_guard<std::mutex> g(mu_);
			go.swap(outbox_);
		}
		for (auto &s : go) {
			Job j;
			if (!current(j) || j.serial != s.job_serial) {
				stats_.stale.fetch_add(1);   // job moved on before we sent it
				continue;
			}
			uint8_t hdr[kHeaderBytes];
			memcpy(hdr, j.header, kHeaderBytes);
			memcpy(hdr + 4 * kNonceOffsetWord, &s.nonce, 4);
			memcpy(hdr + 4 * 32, &s.tag, 4);

			// The pool re-derives its own extranonce prefix, so only the
			// portion after it is submitted.
			const size_t x1 = xnonce1_.size() > 31 ? 31 : xnonce1_.size();
			const std::string noncestr = tohex(hdr + 108 + x1, 32 - x1);

			char timehex[16];
			snprintf(timehex, sizeof(timehex), "%08x",
			         __builtin_bswap32(le32((const uint8_t *)&j.header[25])));

			// solution: 3-byte CompactSize + the 1344 bytes, as the pool
			// expects to splice it back into the block.
			std::string sol = "fd4005" + tohex(j.solution, kSolutionBytes);

			const uint64_t id = next_id_++;
			{
				std::lock_guard<std::mutex> g(mu_);
				pending_.push_back(Pending{id, s.job_serial, s.nonce, s.tag});
			}
			stats_.submitted.fetch_add(1);
			char idbuf[32];
			snprintf(idbuf, sizeof(idbuf), "%llu", (unsigned long long)id);
			send_line(std::string("{\"id\":") + idbuf +
			          ",\"method\":\"mining.submit\",\"params\":[" +
			          json::quote(cfg_.user) + "," + json::quote(j.id) + ",\"" +
			          timehex + "\",\"" + noncestr + "\",\"" + sol + "\"]}");
		}
	}

	if (fd_ >= 0) {
		close(fd_);
		fd_ = -1;
	}
	reconnect_requested_ = false;
	return reached_ready;
}

} // namespace stratum
} // namespace vh22
