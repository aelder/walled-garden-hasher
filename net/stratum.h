// Verus PBaaS stratum client.
//
// Runs on its own thread and hands the miner an immutable Job. The wire format
// is transcribed from the deployed implementation in ../verus/stratum.cpp and
// the work assembly in ../ccminer.cpp, which is the only specification that
// exists for this dialect.
#pragma once

#include <stdint.h>

#include <atomic>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace vh22 {
namespace stratum {

enum : size_t {
	kHeaderBytes = 140,   // version|prevhash|merkle|sapling|ntime|nbits|nonce
	kSolutionBytes = 1344,
	kFullBytes = kHeaderBytes + 3 + kSolutionBytes,  // 1487, the hashed preimage
	kNonceOffsetWord = 30,                           // VERUS_NONCE_OFFSET
	// The nonce is not hashed where it sits in the header. VerusHashHalf's
	// last partial block is the final 15 bytes of the preimage, which is the
	// tail of the solution -- so that is where the miner's nonce space and
	// counting nonce actually live, and what a pool re-derives the hash from.
	// 1487 = 46*32 + 15, and 1487 - 15 - (140 + 3) = 1329.
	kNonceSpaceOffset = 1329,   // within the solution
	kNonceSpaceBytes = 15,      // 11 of nonce space, then the counting nonce
};

// Nothing here may wait forever. Every one of these bounds a state that a pool
// can leave us in by simply not answering: a firewall that drops SYN, a load
// balancer that accepts and then forgets us, a pool that authorizes and never
// sends work. Without them the UI has nothing truthful to say.
enum : int {
	kConnectTimeoutMs = 10000,     // TCP handshake; the OS default is ~75 s
	kHandshakeTimeoutMs = 15000,   // connected -> authorized
	kFirstJobTimeoutMs = 30000,    // authorized -> first job with a target
	kIdleJobTimeoutMs = 180000,    // had work, then silence
};

// A unit of work. Everything the miner needs, already assembled.
struct Job {
	uint64_t serial = 0;              // bumps on every new job; miners watch it
	std::string id;
	uint32_t header[35] = {0};        // the 140-byte header as LE words
	uint8_t solution[kSolutionBytes] = {0};
	uint32_t target[8] = {0};         // LE words, most significant last
	double difficulty = 0;
	uint8_t nonce_space[11] = {0};    // rides in the hashed tail for v7+
	uint32_t ntime = 0;
	bool clean = false;
	bool valid = false;

	// The 1487-byte preimage VerusHashHalf consumes.
	void build_preimage(uint8_t out[kFullBytes]) const;
};

// Counters, as the client thread keeps them.
struct Stats {
	std::atomic<uint64_t> accepted{0};
	std::atomic<uint64_t> rejected{0};
	std::atomic<uint64_t> stale{0};
	std::atomic<uint64_t> submitted{0};
	std::atomic<double> difficulty{0};
	std::atomic<double> last_share_time{0};   // wall clock, 0 = never
	std::atomic<double> connected_since{0};
	std::atomic<uint64_t> reconnects{0};
};

// What a reader gets: a value, not a reference into a connection that may be
// replaced underneath it.
struct StatsView {
	uint64_t accepted = 0, rejected = 0, stale = 0, submitted = 0, reconnects = 0;
	double difficulty = 0, last_share_time = 0, connected_since = 0;
};

// Ready means minable: authorized, targeted, and holding work. Waiting is the
// state that used to hide inside Ready and let the UI offer a MINE button that
// could only produce zero.
enum class State {
	Disconnected, Resolving, Connecting, Subscribing, Authorizing, Waiting, Ready, Failed
};

struct Config {
	std::string host, port = "3956", user, pass = "x";
};

// Everything the client thread touches. It is reference counted and separate
// from Client because getaddrinfo cannot be interrupted: stop() has to be able
// to walk away from a thread stuck in it without the UI freezing and without
// that thread later writing through a dangling this.
class Conn {
public:
	Conn();
	~Conn();

	std::atomic<bool> run{true};
	std::atomic<State> state{State::Disconnected};
	std::atomic<int> fd{-1};
	// The serial of the job currently worth mining, or 0 when there is none.
	// Miners poll this instead of copying the 1.5 KB Job every wave.
	std::atomic<uint64_t> job_serial{0};
	Stats stats;
	Config cfg;

	// Client thread only.
	bool authorized = false;
	// Set when retrying cannot help -- a rejected address will be rejected
	// identically for ever, and looping on it hides the reason from the user.
	bool fatal = false;

	// Wakes the thread out of any poll it is sitting in, from any thread.
	void wake();
	// Sleeps up to ms, returning early if woken. False if we were asked to stop.
	bool nap(int ms);
	int wake_fd() const { return wake_r_; }
	void drain_wake();

	void set_state(State s, const std::string &note);
	std::string note() const;
	// The last thing that actually went wrong, kept across the retry that
	// follows it. The live note spends most of a retry cycle saying
	// "connecting", so without this the diagnosis is on screen for about a
	// second out of every ten and the user never sees it.
	void set_error(const std::string &e);
	std::string error() const;

	mutable std::mutex mu;
	std::string note_;
	std::string error_;
	Job job;
	uint64_t serial = 0;
	std::string xnonce1;
	uint8_t target_be[32] = {0};
	bool have_target = false;
	bool reconnect_requested = false;

	struct Pending {
		uint64_t id;
		uint64_t job_serial;
		uint32_t nonce;
		uint32_t tag;
	};
	std::vector<Pending> pending;
	std::vector<Pending> outbox;
	uint64_t next_id = 4;

private:
	int wake_r_ = -1, wake_w_ = -1;
};

class Client {
public:
	Client();
	~Client();

	// Replaces any running connection. Never blocks on the network.
	void start(const Config &cfg);
	// Signals the current connection to end and detaches from it. Returns
	// immediately -- there is no syscall it has to wait out.
	void stop();

	// True once start() has been called and stop() has not.
	bool running() const;

	State state() const;
	std::string status_text() const;
	// The last failure, still true until something works. Empty once minable.
	std::string last_error() const;
	StatsView stats() const;
	Config config() const;

	// Serial of the job worth mining, 0 when there is none. Cheap enough to
	// call every wave; current() is not.
	uint64_t job_serial() const;

	// Snapshot of the current job. Returns false when there is none yet.
	bool current(Job &out) const;

	// A found share, queued for submission on the client thread. `nonce` is
	// the counting word at header word 30; `tag` is the per-thread word at
	// header word 32 that separates concurrent workers in the nonce space.
	// Both must go back exactly where the miner had them or the pool
	// re-derives a different hash.
	void submit(uint64_t job_serial, uint32_t nonce, uint32_t tag);

private:
	std::shared_ptr<Conn> conn() const;

	mutable std::mutex mu_;
	std::shared_ptr<Conn> conn_;
};

} // namespace stratum
} // namespace vh22
