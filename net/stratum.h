// Verus PBaaS stratum client.
//
// Runs on its own thread and hands the miner an immutable Job. The wire format
// is transcribed from the deployed implementation in ../verus/stratum.cpp and
// the work assembly in ../ccminer.cpp, which is the only specification that
// exists for this dialect.
#pragma once

#include <stdint.h>

#include <atomic>
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

struct Stats {
	std::atomic<uint64_t> accepted{0};
	std::atomic<uint64_t> rejected{0};
	std::atomic<uint64_t> stale{0};
	std::atomic<uint64_t> submitted{0};
	std::atomic<double> difficulty{0};
	std::atomic<double> last_share_time{0};   // wall clock, 0 = never
	std::atomic<double> connected_since{0};
};

enum class State { Disconnected, Resolving, Connecting, Subscribing, Authorizing, Ready, Failed };

struct Config {
	std::string host, port = "3956", user, pass = "x";
};

class Client {
public:
	Client();
	~Client();

	void start(const Config &cfg);
	void stop();

	State state() const { return state_.load(); }
	std::string status_text() const;
	Stats &stats() { return stats_; }

	// Snapshot of the current job. Returns false when there is none yet.
	bool current(Job &out) const;

	// A found share, queued for submission on the client thread. `nonce` is
	// the counting word at header word 30; `tag` is the per-thread word at
	// header word 32 that separates concurrent workers in the nonce space.
	// Both must go back exactly where the miner had them or the pool
	// re-derives a different hash.
	void submit(uint64_t job_serial, uint32_t nonce, uint32_t tag);

private:
	void run(Config cfg);
	bool dial(const Config &cfg);
	bool send_line(const std::string &s);
	bool pump_lines(std::string &carry);
	void handle_line(const std::string &line);
	void set_state(State s, const std::string &note);

	int fd_ = -1;
	std::atomic<State> state_{State::Disconnected};
	mutable std::mutex mu_;
	std::string note_;
	Job job_;
	uint64_t serial_ = 0;

	std::string xnonce1_;      // raw bytes from mining.subscribe
	std::string session_;
	uint8_t target_be_[32] = {0};
	bool have_target_ = false;

	struct Pending {
		uint64_t id;
		uint64_t job_serial;
		uint32_t nonce;
		uint32_t tag;
	};
	std::vector<Pending> pending_;
	std::vector<Pending> outbox_;
	uint64_t next_id_ = 4;

	Stats stats_;
	std::thread th_;
	std::atomic<bool> run_{false};
	Config cfg_;
};

} // namespace stratum
} // namespace vh22
