#include "stratum.h"

#include "json.h"

#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include <chrono>

namespace vh22 {
namespace stratum {
namespace {

double now_wall()
{
	struct timeval tv;
	gettimeofday(&tv, nullptr);
	return (double)tv.tv_sec + (double)tv.tv_usec / 1e6;
}

// Monotonic, for timeouts. Wall clock would let an NTP step fire a watchdog.
int64_t now_ms()
{
	using namespace std::chrono;
	return duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count();
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

// --- Conn -----------------------------------------------------------------

Conn::Conn()
{
	int p[2] = {-1, -1};
	if (pipe(p) == 0) {
		// Non-blocking both ways: wake() must never block a miner thread, and
		// drain_wake() must never block the client thread.
		for (int i = 0; i < 2; ++i)
			fcntl(p[i], F_SETFL, fcntl(p[i], F_GETFL, 0) | O_NONBLOCK);
		wake_r_ = p[0];
		wake_w_ = p[1];
	}
}

Conn::~Conn()
{
	const int f = fd.exchange(-1);
	if (f >= 0)
		close(f);
	if (wake_r_ >= 0) close(wake_r_);
	if (wake_w_ >= 0) close(wake_w_);
}

void Conn::wake()
{
	if (wake_w_ < 0)
		return;
	const char b = 1;
	ssize_t rc = write(wake_w_, &b, 1);
	(void)rc;   // a full pipe already means "wake up"
}

void Conn::drain_wake()
{
	if (wake_r_ < 0)
		return;
	char buf[256];
	while (read(wake_r_, buf, sizeof(buf)) > 0) {
	}
}

bool Conn::nap(int ms)
{
	if (!run.load())
		return false;
	if (wake_r_ < 0) {
		usleep((useconds_t)ms * 1000);
		return run.load();
	}
	struct pollfd p = {wake_r_, POLLIN, 0};
	if (::poll(&p, 1, ms) > 0)
		drain_wake();
	return run.load();
}

void Conn::set_state(State s, const std::string &n)
{
	state.store(s);
	std::lock_guard<std::mutex> g(mu);
	note_ = n;
	// Every failure records itself, so no path can forget to. The countdown
	// notes are not diagnoses, so they do not overwrite one.
	if (s == State::Failed && !n.empty() && n.find(" — retry in ") == std::string::npos)
		error_ = n;
	else if (s == State::Ready)
		error_.clear();
}

std::string Conn::note() const
{
	std::lock_guard<std::mutex> g(mu);
	return note_;
}

void Conn::set_error(const std::string &e)
{
	std::lock_guard<std::mutex> g(mu);
	error_ = e;
}

std::string Conn::error() const
{
	std::lock_guard<std::mutex> g(mu);
	return error_;
}

namespace {

// --- one session ----------------------------------------------------------

bool send_line(Conn &c, const std::string &s)
{
	const int fd = c.fd.load();
	if (fd < 0)
		return false;
	const std::string line = s + "\n";
	size_t off = 0;
	const int64_t end = now_ms() + 10000;
	while (off < line.size()) {
		const ssize_t n = ::send(fd, line.data() + off, line.size() - off, 0);
		if (n > 0) {
			off += (size_t)n;
			continue;
		}
		if (n < 0 && errno == EINTR)
			continue;
		if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
			// The socket is non-blocking, so a pool that stops reading stalls
			// us here rather than in the kernel. Bounded, and interruptible.
			if (now_ms() > end)
				return false;
			struct pollfd p[2] = {{fd, POLLOUT, 0}, {c.wake_fd(), POLLIN, 0}};
			if (::poll(p, 2, 200) < 0 && errno != EINTR)
				return false;
			if (!c.run.load())
				return false;
			continue;
		}
		return false;
	}
	return true;
}

void handle_line(Conn &c, const std::string &line)
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
		if (!c.xnonce1.empty())
			memcpy(h + 108, c.xnonce1.data(),
			       c.xnonce1.size() > 31 ? 31 : c.xnonce1.size());
		j.ntime = le32(tm);
		// The 11 bytes that ride in the hashed tail: the front of the nonce
		// field (which carries the pool's extranonce) plus the per-thread tag
		// word. Workers overwrite bytes 7..10 with their own tag.
		memcpy(j.nonce_space, h + 108, 7);
		memcpy(j.nonce_space + 7, h + 128, 4);

		bool minable = false;
		{
			std::lock_guard<std::mutex> g(c.mu);
			j.serial = ++c.serial;
			memcpy(j.target, c.job.target, sizeof(j.target));
			j.difficulty = c.job.difficulty;
			j.valid = c.have_target;
			c.job = j;
			minable = j.valid;
		}
		c.job_serial.store(minable ? j.serial : 0, std::memory_order_release);
		// Work without a target is not yet minable: saying Ready here is what
		// let the UI offer a MINE button that could only ever produce zero.
		if (minable)
			c.set_state(State::Ready, "");
		else
			c.set_state(State::Waiting, "job received, waiting for a target");
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
		bool minable = false;
		uint64_t serial = 0;
		{
			std::lock_guard<std::mutex> g(c.mu);
			memcpy(c.target_be, be, 32);
			memcpy(c.job.target, words, sizeof(words));
			c.job.difficulty = d;
			c.have_target = true;
			if (c.job.serial)
				c.job.valid = true;
			minable = c.job.valid;
			serial = c.job.serial;
			c.stats.difficulty.store(d);
		}
		if (minable) {
			c.job_serial.store(serial, std::memory_order_release);
			c.set_state(State::Ready, "");
		}
		return;
	}

	if (method == "client.show_message")
		return;
	if (method == "client.reconnect") {
		// The pool is telling us to go away and come back.
		c.reconnect_requested = true;
		return;
	}

	// Otherwise a response to one of ours.
	if (v["id"].type == json::Type::Number) {
		const uint64_t id = (uint64_t)v["id"].as_number();
		if (id == 1) {  // mining.subscribe
			const json::Value &r = v["result"];
			if (r.type != json::Type::Array) {
				std::string err;
				const json::Value &e = v["error"];
				if (e.type == json::Type::Array)
					err = e.at(1).as_string();
				else if (e.type == json::Type::String)
					err = e.str;
				c.set_state(State::Failed,
				            err.empty() ? "pool refused the subscription"
				                        : "pool refused the subscription: " + err);
				return;
			}
			// [[...subscriptions...], xnonce1, xnonce2_size]
			const std::string x1 = r.at(1).as_string();
			uint8_t raw[32];
			const size_t n = unhex(x1, raw, 32);
			c.xnonce1.assign((const char *)raw, n);
			c.set_state(State::Authorizing, "authorizing");
			send_line(c, "{\"id\":2,\"method\":\"mining.authorize\",\"params\":[" +
			                 json::quote(c.cfg.user) + "," + json::quote(c.cfg.pass) + "]}");
			return;
		}
		if (id == 2) {  // mining.authorize
			if (v["result"].truthy()) {
				c.authorized = true;
				c.set_state(State::Waiting, "authorized, waiting for work");
			} else {
				// Terminal until the user changes something, so say what.
				std::string err;
				const json::Value &e = v["error"];
				if (e.type == json::Type::Array)
					err = e.at(1).as_string();
				else if (e.type == json::Type::String)
					err = e.str;
				c.fatal = true;
				c.set_state(State::Failed,
				            err.empty()
				                ? "pool rejected this address"
				                : "pool rejected this address: " + err);
			}
			return;
		}
		// A share result. Stale and reject are different outcomes and the
		// pool distinguishes them only in the error text.
		std::lock_guard<std::mutex> g(c.mu);
		for (size_t i = 0; i < c.pending.size(); ++i) {
			if (c.pending[i].id != id)
				continue;
			if (v["result"].truthy()) {
				c.stats.accepted.fetch_add(1);
				c.stats.last_share_time.store(now_wall());
			} else {
				std::string err;
				const json::Value &e = v["error"];
				if (e.type == json::Type::Array)
					err = e.at(1).as_string();
				else if (e.type == json::Type::String)
					err = e.str;
				for (auto &ch : err)
					ch = (char)tolower((unsigned char)ch);
				if (err.find("stale") != std::string::npos ||
				    err.find("job not found") != std::string::npos ||
				    err.find("duplicate") != std::string::npos)
					c.stats.stale.fetch_add(1);
				else
					c.stats.rejected.fetch_add(1);
			}
			c.pending.erase(c.pending.begin() + (long)i);
			return;
		}
	}
}

// Returns false when the connection should end. `carry` accumulates a partial
// line across reads.
bool pump_lines(Conn &c, std::string &carry)
{
	const int fd = c.fd.load();
	char buf[8192];
	for (;;) {
		const ssize_t n = ::recv(fd, buf, sizeof(buf), 0);
		if (n == 0) {
			c.set_state(State::Failed, "pool closed the connection");
			return false;
		}
		if (n < 0) {
			if (errno == EINTR)
				continue;
			if (errno == EAGAIN || errno == EWOULDBLOCK)
				break;
			c.set_state(State::Failed, "connection error");
			return false;
		}
		carry.append(buf, (size_t)n);
		if ((size_t)n < sizeof(buf))
			break;
	}
	for (;;) {
		const size_t nl = carry.find('\n');
		if (nl == std::string::npos)
			break;
		std::string line = carry.substr(0, nl);
		carry.erase(0, nl + 1);
		while (!line.empty() && (line.back() == '\r'))
			line.pop_back();
		if (!line.empty())
			handle_line(c, line);
	}
	// A pool that never sends newlines would otherwise grow this forever.
	if (carry.size() >= (1u << 20)) {
		c.set_state(State::Failed, "pool sent a malformed stream");
		return false;
	}
	return true;
}

// Resolve, telling the two failure modes apart. "cannot resolve <host>" for a
// bad port sends the user to check the one field that is correct.
bool resolve(Conn &c, struct addrinfo **res)
{
	struct addrinfo hints;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	*res = nullptr;
	if (getaddrinfo(c.cfg.host.c_str(), c.cfg.port.c_str(), &hints, res) == 0 && *res)
		return true;
	if (*res) {
		freeaddrinfo(*res);
		*res = nullptr;
	}
	struct addrinfo *probe = nullptr;
	const bool host_ok =
		getaddrinfo(c.cfg.host.c_str(), nullptr, &hints, &probe) == 0 && probe;
	if (probe)
		freeaddrinfo(probe);
	if (host_ok)
		c.set_state(State::Failed, "\"" + c.cfg.port + "\" is not a valid port");
	else
		c.set_state(State::Failed, "cannot resolve " + c.cfg.host);
	return false;
}

// Non-blocking connect with a deadline, interruptible by stop(). The OS
// default is around 75 seconds per address, which is where the UI used to go
// to die.
int connect_one(Conn &c, struct addrinfo *a, int64_t deadline)
{
	const int fd = socket(a->ai_family, a->ai_socktype, a->ai_protocol);
	if (fd < 0)
		return -1;
	const int flags = fcntl(fd, F_GETFL, 0);
	fcntl(fd, F_SETFL, flags | O_NONBLOCK);

	int rc = ::connect(fd, a->ai_addr, a->ai_addrlen);
	if (rc != 0 && errno != EINPROGRESS) {
		close(fd);
		return -1;
	}
	while (rc != 0) {
		const int64_t left = deadline - now_ms();
		if (left <= 0) {
			close(fd);
			return -1;
		}
		struct pollfd p[2] = {{fd, POLLOUT, 0}, {c.wake_fd(), POLLIN, 0}};
		const int n = ::poll(p, 2, left > 200 ? 200 : (int)left);
		if (!c.run.load()) {
			close(fd);
			return -1;
		}
		if (n < 0) {
			if (errno == EINTR)
				continue;
			close(fd);
			return -1;
		}
		if (p[1].revents) {   // asked to stop
			c.drain_wake();
			close(fd);
			return -1;
		}
		if (p[0].revents)
			break;
	}
	int err = 0;
	socklen_t len = sizeof(err);
	if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len) != 0 || err) {
		close(fd);
		errno = err;
		return -1;
	}
	// Record who we are actually talking to, not who we meant to.
	{
		struct sockaddr_storage ss;
		socklen_t sl = sizeof(ss);
		char host[NI_MAXHOST] = {0};
		if (getpeername(fd, (struct sockaddr *)&ss, &sl) == 0 &&
		    getnameinfo((struct sockaddr *)&ss, sl, host, sizeof(host), nullptr, 0,
		                NI_NUMERICHOST) == 0) {
			std::lock_guard<std::mutex> g(c.mu);
			c.peer_ = host;
		}
	}
	int one = 1;
	setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
	// A pool that vanishes without a FIN -- a laptop lid, a NAT timeout --
	// otherwise leaves us polling a socket that will never speak again.
	setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &one, sizeof(one));
	return fd;   // stays non-blocking for the session
}

bool dial(Conn &c)
{
	struct addrinfo *res = nullptr;
	if (!resolve(c, &res))
		return false;
	if (!c.run.load()) {
		freeaddrinfo(res);
		return false;
	}

	c.set_state(State::Connecting, "connecting to " + c.cfg.host);
	const int64_t deadline = now_ms() + kConnectTimeoutMs;
	int fd = -1;
	int last_errno = 0;
	for (struct addrinfo *a = res; a && fd < 0 && c.run.load(); a = a->ai_next) {
		fd = connect_one(c, a, deadline);
		if (fd < 0)
			last_errno = errno;
	}
	freeaddrinfo(res);
	if (fd < 0) {
		if (!c.run.load())
			return false;
		if (now_ms() >= deadline)
			c.set_state(State::Failed,
			            "no answer — check the port, or a firewall");
		else if (last_errno == ECONNREFUSED)
			c.set_state(State::Failed, "connection refused on port " + c.cfg.port);
		else
			c.set_state(State::Failed,
			            std::string("cannot reach the pool: ") + strerror(last_errno));
		return false;
	}
	c.fd.store(fd);
	return true;
}

void close_fd(Conn &c)
{
	const int fd = c.fd.exchange(-1);
	if (fd >= 0)
		close(fd);
}

// One connection. True if it ever reached a minable state.
bool session(Conn &c)
{
	bool reached_ready = false;

	// Nothing survives a reconnect: the pool issues a new extranonce, so the
	// old job and target are not just stale but wrong to mine.
	{
		std::lock_guard<std::mutex> g(c.mu);
		c.job = Job();
		c.have_target = false;
		c.xnonce1.clear();
		// Shares we sent but never heard back about are unknowable now.
		c.stats.stale.fetch_add(c.pending.size());
		c.pending.clear();
		c.outbox.clear();
		c.peer_.clear();   // a peer from the last session is not this one
	}
	c.job_serial.store(0, std::memory_order_release);
	c.authorized = false;

	c.set_state(State::Resolving, "resolving " + c.cfg.host);
	if (!dial(c))
		return false;

	c.set_state(State::Subscribing, "subscribing");
	c.stats.connected_since.store(now_wall());
	const int64_t t_connected = now_ms();
	int64_t t_authorized = 0, t_last_job = 0;

	if (!send_line(c, "{\"id\":1,\"method\":\"mining.subscribe\",\"params\":[\"vh22/1.0\"]}")) {
		c.set_state(State::Failed, "could not send to the pool");
		close_fd(c);
		return false;
	}

	std::string carry;
	while (c.run.load() && !c.reconnect_requested && !c.fatal) {
		const State st = c.state.load();
		if (st == State::Ready) {
			reached_ready = true;
			if (!t_last_job)
				t_last_job = now_ms();
		}
		if (c.authorized && !t_authorized)
			t_authorized = now_ms();

		// Watchdogs. Every one of these is a state a pool can park us in for
		// ever by simply not replying.
		const int64_t now = now_ms();
		if (!c.authorized && now - t_connected > kHandshakeTimeoutMs) {
			c.set_state(State::Failed,
			            "connected, but the pool never replied — wrong port?");
			break;
		}
		if (c.authorized && !reached_ready && t_authorized &&
		    now - t_authorized > kFirstJobTimeoutMs) {
			c.set_state(State::Failed, "authorized, but the pool sent no work");
			break;
		}
		if (reached_ready && t_last_job && now - t_last_job > kIdleJobTimeoutMs) {
			char b[96];
			snprintf(b, sizeof(b), "no work from the pool for %llds",
			         (long long)((now - t_last_job) / 1000));
			c.set_state(State::Failed, b);
			break;
		}

		struct pollfd p[2] = {{c.fd.load(), POLLIN, 0}, {c.wake_fd(), POLLIN, 0}};
		const int rc = ::poll(p, 2, 200);
		if (rc < 0 && errno != EINTR)
			break;
		if (!c.run.load())
			break;
		if (p[1].revents)
			c.drain_wake();
		if (rc > 0 && (p[0].revents & (POLLIN | POLLHUP | POLLERR))) {
			const uint64_t before = c.serial;
			if (!pump_lines(c, carry))
				break;
			if (c.serial != before)
				t_last_job = now_ms();
		}

		// Drain queued shares on this thread so the socket has one writer.
		std::vector<Conn::Pending> go;
		{
			std::lock_guard<std::mutex> g(c.mu);
			go.swap(c.outbox);
		}
		for (auto &s : go) {
			Job j;
			{
				std::lock_guard<std::mutex> g(c.mu);
				j = c.job;
			}
			if (!j.valid || j.serial != s.job_serial) {
				c.stats.stale.fetch_add(1);   // job moved on before we sent it
				continue;
			}
			uint8_t hdr[kHeaderBytes];
			memcpy(hdr, j.header, kHeaderBytes);
			memcpy(hdr + 4 * kNonceOffsetWord, &s.nonce, 4);
			memcpy(hdr + 4 * 32, &s.tag, 4);

			// The pool re-derives its own extranonce prefix, so only the
			// portion after it is submitted.
			const size_t x1 = c.xnonce1.size() > 31 ? 31 : c.xnonce1.size();
			const std::string noncestr = tohex(hdr + 108 + x1, 32 - x1);

			char timehex[16];
			snprintf(timehex, sizeof(timehex), "%08x",
			         __builtin_bswap32(le32((const uint8_t *)&j.header[25])));

			// The solution has to go back carrying the nonce we mined with.
			//
			// Sending it exactly as the pool issued it -- which is what this
			// did -- asks the pool to re-derive the hash from a preimage we
			// never hashed, because the bytes the engine varies are the last
			// fifteen of the solution, not the header's nonce field. The
			// framing was correct, every field was well formed, and every
			// share was rejected. The specification is record_solution in
			// the deployed miner's verusscan.cpp: work->extra + 1332, three
			// bytes of CompactSize past solution byte 1329.
			uint8_t sol_bytes[kSolutionBytes];
			memcpy(sol_bytes, j.solution, kSolutionBytes);
			uint8_t space[kNonceSpaceBytes];
			memcpy(space, j.nonce_space, 7);   // header words 27..28, the pool's
			memcpy(space + 7, &s.tag, 4);      // header word 32, this worker's
			memcpy(space + 11, &s.nonce, 4);   // the counting nonce
			memcpy(sol_bytes + kNonceSpaceOffset, space, sizeof(space));

			// 3-byte CompactSize + the 1344 bytes, as the pool expects to
			// splice it back into the block. Solution bytes 8..71 are the MMR
			// roots, zeroed for hashing by build_preimage but not here: this
			// copy is the pristine one, so they are already what the pool
			// needs back.
			std::string sol = "fd4005" + tohex(sol_bytes, kSolutionBytes);

			const uint64_t id = c.next_id++;
			{
				std::lock_guard<std::mutex> g(c.mu);
				c.pending.push_back(Conn::Pending{id, s.job_serial, s.nonce, s.tag});
			}
			c.stats.submitted.fetch_add(1);
			char idbuf[32];
			snprintf(idbuf, sizeof(idbuf), "%llu", (unsigned long long)id);
			if (!send_line(c, std::string("{\"id\":") + idbuf +
			                      ",\"method\":\"mining.submit\",\"params\":[" +
			                      json::quote(c.cfg.user) + "," + json::quote(j.id) +
			                      ",\"" + timehex + "\",\"" + noncestr + "\",\"" + sol +
			                      "\"]}")) {
				c.set_state(State::Failed, "could not send to the pool");
				close_fd(c);
				return reached_ready;
			}
		}
	}

	close_fd(c);
	c.reconnect_requested = false;
	c.job_serial.store(0, std::memory_order_release);
	return reached_ready;
}

// The retry loop. A miner has to survive the pool going away: pools restart,
// drop idle connections and hand out client.reconnect. Backoff doubles from
// one second to thirty, and resets whenever a session actually reached a
// minable state so a stable pool that blips does not inherit a long delay.
void run_thread(std::shared_ptr<Conn> c)
{
	int backoff = 1;
	while (c->run.load()) {
		const bool reached_ready = session(*c);
		if (!c->run.load())
			break;

		if (reached_ready) {
			backoff = 1;
			c->stats.reconnects.fetch_add(1);
		}

		// An authorize rejection will be rejected identically forever. Retrying
		// on a loop hides that from the user; stopping with the reason on
		// screen is what lets them fix it.
		if (c->fatal) {
			c->state.store(State::Failed);
			break;
		}

		// Keep why it failed. Overwriting it with a bare countdown leaves the
		// user staring at "reconnecting" with nothing to act on -- a wrong
		// port and a dead pool look identical, and one of them is their typo.
		std::string why = c->note();
		const size_t dash = why.find(" — retry in ");
		if (dash != std::string::npos)
			why.erase(dash);
		if (why.empty())
			why = reached_ready ? "connection lost" : "not connected";

		// Count the wait down rather than showing a frozen number: a static
		// "retry in 30s" is indistinguishable from a hang.
		for (int left = backoff; left > 0 && c->run.load(); --left) {
			char note[256];
			snprintf(note, sizeof(note), "%s — retry in %ds", why.c_str(), left);
			// Red while it has never worked; grey once it has and merely dropped.
			c->set_state(reached_ready ? State::Disconnected : State::Failed, note);
			if (!c->nap(1000))
				break;
		}
		backoff = backoff < 30 ? backoff * 2 : 30;
	}
	if (!c->fatal)
		c->set_state(State::Disconnected, "");
}

} // namespace

// --- Client ---------------------------------------------------------------

Client::Client() {}
Client::~Client() { stop(); }

std::shared_ptr<Conn> Client::conn() const
{
	std::lock_guard<std::mutex> g(mu_);
	return conn_;
}

void Client::start(const Config &cfg)
{
	stop();
	auto c = std::make_shared<Conn>();
	c->cfg = cfg;
	{
		std::lock_guard<std::mutex> g(mu_);
		conn_ = c;
	}
	// Detached, not joined. getaddrinfo cannot be interrupted, so stop() must
	// be free to walk away from a thread that is stuck in it -- the Conn is
	// reference counted precisely so that thread has something valid to finish
	// writing to.
	std::thread(run_thread, c).detach();
}

void Client::stop()
{
	std::shared_ptr<Conn> c;
	{
		std::lock_guard<std::mutex> g(mu_);
		c.swap(conn_);
	}
	if (!c)
		return;
	c->run.store(false);
	c->job_serial.store(0, std::memory_order_release);
	c->wake();
}

bool Client::running() const { return conn() != nullptr; }

State Client::state() const
{
	const auto c = conn();
	return c ? c->state.load() : State::Disconnected;
}

std::string Client::status_text() const
{
	const auto c = conn();
	return c ? c->note() : std::string();
}

std::string Client::last_error() const
{
	const auto c = conn();
	return c ? c->error() : std::string();
}

std::string Client::endpoint() const
{
	const auto c = conn();
	if (!c)
		return std::string();
	std::string s = c->cfg.host + ":" + c->cfg.port;
	std::lock_guard<std::mutex> g(c->mu);
	if (!c->peer_.empty() && c->peer_ != c->cfg.host)
		s += " · " + c->peer_;
	return s;
}

Config Client::config() const
{
	const auto c = conn();
	return c ? c->cfg : Config();
}

StatsView Client::stats() const
{
	StatsView v;
	const auto c = conn();
	if (!c)
		return v;
	v.accepted = c->stats.accepted.load();
	v.rejected = c->stats.rejected.load();
	v.stale = c->stats.stale.load();
	v.submitted = c->stats.submitted.load();
	v.reconnects = c->stats.reconnects.load();
	v.difficulty = c->stats.difficulty.load();
	v.last_share_time = c->stats.last_share_time.load();
	v.connected_since = c->stats.connected_since.load();
	return v;
}

uint64_t Client::job_serial() const
{
	const auto c = conn();
	return c ? c->job_serial.load(std::memory_order_acquire) : 0;
}

bool Client::current(Job &out) const
{
	const auto c = conn();
	if (!c)
		return false;
	std::lock_guard<std::mutex> g(c->mu);
	if (!c->job.valid)
		return false;
	out = c->job;
	return true;
}

void Client::submit(uint64_t job_serial, uint32_t nonce, uint32_t tag)
{
	const auto c = conn();
	if (!c)
		return;
	{
		std::lock_guard<std::mutex> g(c->mu);
		// A pool that stops answering must not let this grow without bound.
		if (c->outbox.size() >= 4096)
			return;
		c->outbox.push_back(Conn::Pending{0, job_serial, nonce, tag});
	}
	c->wake();   // out on this tick, not up to 200 ms later
}

} // namespace stratum
} // namespace vh22
