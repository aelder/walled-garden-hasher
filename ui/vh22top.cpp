// vh22-top — a terminal front end for the vh22 engine.
//
// Layout is System 7: stacked windows with pinstriped title bars, the focused
// one striped and the rest blank, which is how Platinum signalled activation
// and happens to be exactly the affordance keyboard navigation wants.
// The hashrate plot is btop-density braille, coloured by height through the
// 1977 logo stripes.
#include "tui.h"
#include "stratum.h"
#include "vh22/verushash.h"

#include <mach/mach.h>
#include <mach/mach_host.h>
#include <mach/processor_info.h>
#include <mach/mach_time.h>
#include <pthread.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/time.h>
#include <unistd.h>

#include <atomic>
#include <string>
#include <thread>
#include <vector>

#if defined(__APPLE__)
#include <pthread/qos.h>
#endif

using namespace vh22;
using namespace vh22::tui;

static double now_wall()
{
	struct timeval tv;
	gettimeofday(&tv, nullptr);
	return (double)tv.tv_sec + (double)tv.tv_usec / 1e6;
}

static double now_s()
{
	static mach_timebase_info_data_t tb;
	if (tb.denom == 0)
		mach_timebase_info(&tb);
	return (double)mach_absolute_time() * tb.numer / tb.denom / 1e9;
}

// --- machine --------------------------------------------------------------

struct SysInfo {
	int ncpu = 1, nperf = 0, neff = 0, pbase = 0;
	std::string model = "Apple silicon";
	double mem_gb = 0;

	void probe()
	{
		int v = 0;
		size_t len = sizeof(v);
		if (sysctlbyname("hw.logicalcpu", &v, &len, nullptr, 0) == 0) ncpu = v;
		int levels = 1;
		len = sizeof(levels);
		sysctlbyname("hw.nperflevels", &levels, &len, nullptr, 0);
		if (levels > 1) {
			len = sizeof(v);
			if (sysctlbyname("hw.perflevel0.logicalcpu", &v, &len, nullptr, 0) == 0)
				nperf = v;
			len = sizeof(v);
			if (sysctlbyname("hw.perflevel1.logicalcpu", &v, &len, nullptr, 0) == 0)
				neff = v;
			// Apple numbers the efficiency cluster first, so the performance
			// cores occupy the top ids. Inference, not a documented contract,
			// so it is only used for labelling.
			pbase = ncpu - nperf;
		} else {
			nperf = ncpu;
		}
		char buf[128] = {0};
		len = sizeof(buf);
		if (sysctlbyname("machdep.cpu.brand_string", buf, &len, nullptr, 0) == 0)
			model = buf;
		uint64_t mem = 0;
		len = sizeof(mem);
		if (sysctlbyname("hw.memsize", &mem, &len, nullptr, 0) == 0)
			mem_gb = (double)mem / (1024.0 * 1024.0 * 1024.0);
	}
	bool is_perf(int cpu) const { return nperf > 0 && cpu >= pbase; }
};

// Per-core utilisation from the same source btop uses.
struct CoreLoad {
	std::vector<uint64_t> prev_busy, prev_total;
	std::vector<double> pct;
	std::vector<std::vector<double>> hist;   // one trace per core
	static constexpr size_t kHist = 96;

	void sample(int ncpu)
	{
		processor_cpu_load_info_t info = nullptr;
		mach_msg_type_number_t cnt = 0;
		natural_t n = 0;
		if (host_processor_info(mach_host_self(), PROCESSOR_CPU_LOAD_INFO, &n,
		                        (processor_info_array_t *)&info, &cnt) != KERN_SUCCESS)
			return;
		if ((int)n > ncpu)
			n = (natural_t)ncpu;
		pct.resize(n);
		prev_busy.resize(n, 0);
		prev_total.resize(n, 0);
		for (natural_t i = 0; i < n; ++i) {
			uint64_t busy = info[i].cpu_ticks[CPU_STATE_USER] +
			                info[i].cpu_ticks[CPU_STATE_SYSTEM] +
			                info[i].cpu_ticks[CPU_STATE_NICE];
			uint64_t total = busy + info[i].cpu_ticks[CPU_STATE_IDLE];
			const uint64_t db = busy - prev_busy[i];
			const uint64_t dt = total - prev_total[i];
			pct[i] = dt ? (double)db / (double)dt : 0.0;
			prev_busy[i] = busy;
			prev_total[i] = total;
			if (hist.size() <= i)
				hist.resize(i + 1);
			if (hist[i].empty())
				hist[i].assign(kHist, 0.0);
			hist[i].erase(hist[i].begin());
			hist[i].push_back(pct[i]);
		}
		vm_deallocate(mach_task_self(), (vm_address_t)info, cnt * sizeof(int));
	}
};

// --- engine driver --------------------------------------------------------

static std::atomic<uint64_t> g_hashes{0};
static std::atomic<bool> g_running{false};

struct Worker {
	std::thread th;
};

class Engine {
public:
	void configure(const uint8_t *header, size_t len) { build_template(tpl_, header, len); }
	void set_pool(stratum::Client *c) { pool_ = c; }

	void start(int threads, int lanes)
	{
		stop();
		g_running.store(true);
		for (int i = 0; i < threads; ++i) {
			workers_.emplace_back();
			workers_.back().th = std::thread([this, i, lanes] { loop(i, lanes); });
		}
	}

	void stop()
	{
		g_running.store(false);
		for (auto &w : workers_)
			if (w.th.joinable())
				w.th.join();
		workers_.clear();
	}

	bool active() const { return !workers_.empty(); }
	~Engine() { stop(); }

private:
	void loop(int idx, int lanes)
	{
#if defined(__APPLE__)
		pthread_set_qos_class_self_np(QOS_CLASS_USER_INTERACTIVE, 0);
#endif
		Hasher h(lanes);
		if (!h.valid())
			return;
		const int n = h.lanes();

		// Separates this worker in the nonce space. It lands at header word
		// 32 and must travel back with any share, or the pool re-derives a
		// different hash from the one we solved.
		const uint32_t tag =
			(uint32_t)(idx * 0x9E3779B1u) ^ (uint32_t)(now_s() * 1000.0);

		if (!pool_) {
			h.reset(tpl_);
			uint32_t nonce = (uint32_t)idx * 0x01000000u;
			while (g_running.load(std::memory_order_relaxed)) {
				for (int r = 0; r < 32; ++r) {
					h.run_wave(nonce, 0);
					nonce += (uint32_t)n;
				}
				g_hashes.fetch_add((uint64_t)n * 32, std::memory_order_relaxed);
			}
			return;
		}

		Template tpl;
		uint64_t serial = 0;
		uint32_t nonce = 0, high = 0;
		uint32_t target[8] = {0};
		while (g_running.load(std::memory_order_relaxed)) {
			// One relaxed load per wave. current() takes a lock and copies the
			// 1.5 KB Job, which at ~400k waves/s is not something to do on the
			// hot path just to ask whether anything changed.
			const uint64_t live = pool_->job_serial();
			if (!live) {
				// No minable work: the pool is down, reconnecting, or has not
				// sent any. Idle rather than grinding a job we know is dead.
				serial = 0;
				usleep(50000);
				continue;
			}
			if (live != serial) {
				// New job: rebuild the per-template state. The 276 chained
				// Haraka256 of key expansion happen here, once, not per nonce.
				stratum::Job j;
				if (!pool_->current(j) || !j.valid) {
					usleep(20000);
					continue;
				}
				serial = j.serial;
				uint8_t pre[stratum::kFullBytes];
				j.build_preimage(pre);
				build_template(tpl, pre, stratum::kFullBytes);
				uint8_t ns[11];
				memcpy(ns, j.nonce_space, sizeof(ns));
				memcpy(ns + 7, &tag, 4);
				set_nonce_space(tpl, ns, sizeof(ns));
				h.reset(tpl);
				memcpy(target, j.target, sizeof(target));
				high = target[7];
				nonce = 0;
			}

			const uint64_t hit = h.run_wave(nonce, high);
			if (hit) {
				for (int l = 0; l < n; ++l) {
					if (!((hit >> l) & 1))
						continue;
					if (!hash_meets_target(h.hash_of(l), target))
						continue;
					pool_->submit(serial, nonce + (uint32_t)l, tag);
				}
			}
			nonce += (uint32_t)n;
			g_hashes.fetch_add((uint64_t)n, std::memory_order_relaxed);
		}
	}

	Template tpl_;
	stratum::Client *pool_ = nullptr;
	std::vector<Worker> workers_;
};

// --- identity and pools ---------------------------------------------------
//
// Most miners make you retype your wallet address into every pool entry. It is
// the same address every time, so it is asked once and composed with the rig
// name into the stratum user: <address>.<rig>. Switching pools then costs one
// keystroke instead of a re-entry.

struct Identity {
	std::string address;   // Verus R-address
	std::string rig;       // worker name

	bool complete() const { return !address.empty(); }
	std::string user() const
	{
		return rig.empty() ? address : address + "." + rig;
	}
	// Pools pay to a transparent R-address, to a VerusID (i-address), or to an
	// identity name ending in @. Anything else is almost certainly a paste
	// accident, and the pool's only answer is a flat authorize rejection --
	// which arrives long after the moment the user could have spotted it.
	const char *shape() const
	{
		if (address.empty())
			return nullptr;
		if (address.find_first_of(" \t") != std::string::npos)
			return "an address cannot contain spaces";
		if (address.back() == '@')
			return nullptr;
		if (address[0] == 'R' && address.size() == 34)
			return nullptr;
		if (address[0] == 'i' && address.size() == 34)
			return nullptr;
		return "expected R…, i… (34 characters) or a name@";
	}
	// Addresses are 34 characters and do not fit next to anything.
	std::string shortened() const
	{
		if (address.size() < 14)
			return user();
		return address.substr(0, 6) + "…" + address.substr(address.size() - 4) +
		       (rig.empty() ? "" : "." + rig);
	}
};

struct Pool {
	std::string label;
	std::string host;
	std::string port = "3956";
	// True while the row still matches what this build ships. Corrections to
	// an endpoint then reach existing installs on next launch, which matters
	// because pools move and the seeds here started out as guesses. Editing a
	// row clears it and the user's value wins permanently.
	bool builtin = false;
};

// Seeds for the pool list. Ports are not uniform across these -- LuckPool is
// on the conventional VerusHash 3956, Vipor on 5040, and both Verus.farm and
// Verus.io on 9999 -- which is exactly why every row shows host:port in the
// UI rather than hiding it.
static const Pool kPresets[] = {
	{"LuckPool NA", "na.luckpool.net", "3956", true},
	{"LuckPool EU", "eu.luckpool.net", "3956", true},
	{"LuckPool AP", "ap.luckpool.net", "3956", true},
	{"Vipor US West", "usw.vipor.net", "5040", true},
	{"Verus.farm", "verus.farm", "9999", true},
	{"Verus.io", "pool.verus.io", "9999", true},
};

// Presets that have been renamed, so a row written by an older build still
// matches its successor and picks up the corrected endpoint.
static const struct {
	const char *from;
	const char *to;
} kRenames[] = {
	{"Vipor", "Vipor US West"},
};

// The shipped row with this label, if any, following renames.
static const Pool *preset_for(std::string label)
{
	for (const auto &r : kRenames)
		if (label == r.from)
			label = r.to;
	for (const auto &p : kPresets)
		if (p.label == label)
			return &p;
	return nullptr;
}

static std::string config_dir()
{
	const char *home = getenv("HOME");
	return std::string(home ? home : ".") + "/.config/vh22";
}
static std::string config_path() { return config_dir() + "/config"; }

struct Settings {
	Identity id;
	std::vector<Pool> pools;
	int selected = 0;
	// Whether the user has actually picked a pool. The list is seeded on
	// first run, so `selected` always points at something -- showing that as
	// a live selection while nothing is connected is a lie, and it was one.
	bool chosen = false;
};

static bool load_settings(Settings &out)
{
	FILE *f = fopen(config_path().c_str(), "r");
	if (!f)
		return false;
	bool seen_builtin_key = false;
	char line[512];
	while (fgets(line, sizeof(line), f)) {
		std::string s(line);
		while (!s.empty() && (s.back() == '\n' || s.back() == '\r'))
			s.pop_back();
		const size_t eq = s.find('=');
		if (eq == std::string::npos || s[0] == '#')
			continue;
		const std::string k = s.substr(0, eq), v = s.substr(eq + 1);
		if (k == "address") out.id.address = v;
		else if (k == "rig") out.id.rig = v;
		else if (k == "selected") out.selected = atoi(v.c_str());
		else if (k == "chosen") out.chosen = (v == "1");
		else if (k == "pool") { out.pools.push_back(Pool()); out.pools.back().label = v; }
		else if (!out.pools.empty() && k == "host") out.pools.back().host = v;
		else if (!out.pools.empty() && k == "port") out.pools.back().port = v;
		else if (!out.pools.empty() && k == "builtin") {
			out.pools.back().builtin = (v == "1");
			seen_builtin_key = true;
		}
		else if (!out.pools.empty() && k == "edited")
			out.pools.back().builtin = false;
	}
	fclose(f);

	// A row written before this key existed is treated as shipped if its
	// label is one of ours, so endpoint corrections land on next launch.
	// Anything the user edited carries builtin=0 and is left alone.
	for (auto &p : out.pools) {
		if (!p.builtin && preset_for(p.label) == nullptr)
			continue;
		if (const Pool *seed = preset_for(p.label)) {
			if (p.builtin || !seen_builtin_key) {
				p.label = seed->label;   // carry renames through
				p.host = seed->host;
				p.port = seed->port;
				p.builtin = true;
			}
		}
	}
	if (out.selected >= (int)out.pools.size())
		out.selected = 0;
	return true;
}

static bool save_settings(const Settings &st)
{
	mkdir(config_dir().c_str(), 0700);
	FILE *f = fopen(config_path().c_str(), "w");
	if (!f)
		return false;
	fprintf(f, "# vh22 configuration\n");
	fprintf(f, "address=%s\nrig=%s\nselected=%d\nchosen=%d\n\n",
	        st.id.address.c_str(), st.id.rig.c_str(), st.selected, st.chosen ? 1 : 0);
	for (const auto &p : st.pools)
		fprintf(f, "pool=%s\nhost=%s\nport=%s\nbuiltin=%d\n", p.label.c_str(),
		        p.host.c_str(), p.port.c_str(), p.builtin ? 1 : 0);
	fclose(f);
	chmod(config_path().c_str(), 0600);  // it names the wallet being mined to
	return true;
}

// --- ticker copy ----------------------------------------------------------
//
// Read at runtime rather than compiled in, so the copy can be edited and
// reread without a rebuild -- it is prose, and prose wants a fast loop. The
// single line below is the fallback for a binary that ships without the file.
static const char *kNewsFallback =
	"Walled Garden Hasher released, bringing Verus mining to Apple Silicon — "
	"at least one person reportedly extremely excited.";

// Headlines are the bullets under the `## live` heading. Scoping them to a
// section rather than taking every bullet in the file is what lets the file
// carry its own house style notes and a graveyard of spiked drafts -- both of
// which want to be bullet lists too, and neither of which wants to be on
// screen. A file with no `## live` heading is read as a plain list.
static std::vector<std::string> load_news()
{
	std::vector<std::string> paths;
	if (const char *env = getenv("VH22_NEWS"))
		paths.push_back(env);
	paths.push_back(config_dir() + "/news.md");
	paths.push_back("ui/news.md");   // running from vh22/, as `make top` does
	paths.push_back("news.md");

	for (const auto &path : paths) {
		FILE *f = fopen(path.c_str(), "r");
		if (!f)
			continue;
		std::vector<std::string> live, all;
		bool in_live = false, seen_live = false;
		char line[1024];
		while (fgets(line, sizeof(line), f)) {
			std::string s(line);
			while (!s.empty() && (s.back() == '\n' || s.back() == '\r' || s.back() == ' '))
				s.pop_back();
			const size_t i = s.find_first_not_of(" \t");
			if (i == std::string::npos)
				continue;
			if (s[i] == '#') {
				std::string h = s.substr(i);
				for (auto &ch : h)
					ch = (char)tolower((unsigned char)ch);
				in_live = h.find("live") != std::string::npos;
				seen_live = seen_live || in_live;
				continue;
			}
			if (s.compare(i, 2, "- ") != 0 && s.compare(i, 2, "* ") != 0)
				continue;
			const std::string item = s.substr(i + 2);
			all.push_back(item);
			if (in_live)
				live.push_back(item);
		}
		fclose(f);
		if (seen_live && !live.empty())
			return live;
		if (!seen_live && !all.empty())
			return all;
	}
	return {kNewsFallback};
}

// --- app ------------------------------------------------------------------

// Two Apple logos. The watermark takes the largest that fits the plot; the
// header always uses the small one.
struct LogoArt {
	int rows;
	const char *const *line;
};

static const char *const kLogoSmallRows[] = {
	"       .:'   ",
	"    _ :'_    ",
	" .'`_`-'_``. ",
	":________.-' ",
	":_______:    ",
	" :_______`-; ",
	"  `._.-._.'  ",
};

// The full neofetch apple. Denser, so it occludes more of the stream -- which
// is the point.
static const char *const kLogoLargeRows[] = {
	"                    ..'        ",
	"                 ,xNMM.        ",
	"               .OMMMMo         ",
	"               lMM\"           ",
	"     .;loddo:.   .olloddol;.   ",
	"   cKMMMMMMMMMMNWMMMMMMMMMM0:  ",
	" .KMMMMMMMMMMMMMMMMMMMMMMMWd.  ",
	" XMMMMMMMMMMMMMMMMMMMMMMMMX.   ",
	";MMMMMMMMMMMMMMMMMMMMMMMMMM:   ",
	":MMMMMMMMMMMMMMMMMMMMMMMMMM:   ",
	".MMMMMMMMMMMMMMMMMMMMMMMMMX.   ",
	" kMMMMMMMMMMMMMMMMMMMMMMMMWd.  ",
	" 'XMMMMMMMMMMMMMMMMMMMMMMMMMMk ",
	"  'XMMMMMMMMMMMMMMMMMMMMMMMMK. ",
	"    kMMMMMMMMMMMMMMMMMMMMMMd   ",
	"     ;KMMMMMMMWXXWMMMMMMMk.    ",
	"       \"cooc*\"    \"*coo'\"    ",
};

static const LogoArt kLogoSmall = {7, kLogoSmallRows};
static const LogoArt kLogoLarge = {17, kLogoLargeRows};

// Where the dashboard stops being drawable: header 4 + graph 5 + panels 9 +
// help 1. Below the panel floor the controls leave the screen while focus can
// still reach them, which is worse than refusing to draw.
enum : int { kMinW = 60, kMinH = 19 };

enum class Screen { Dashboard, Pools, EditPool, Setup };
enum Focus { F_THREADS = 0, F_LANES, F_BENCH, F_MINE, F_POOLS, F_COUNT };
enum class Mode { Idle, Mining, Benchmark };

// Three braille cells of falling material beside the MINING label. Dust is a
// single dot, clumps are short vertical runs; both fall through the 6x4 dot
// grid the cells provide and respawn at the top. It is the only part of the
// UI that says "work is happening" without reporting a number.
struct Dust {
	enum : int { kCells = 3, kCols = kCells * 2, kRows = 4, kMax = 16 };
	struct P {
		int col;
		double y, v;
		int len;
	};
	P p[kMax];
	double last = 0;
	uint64_t seed = 0x9E3779B97F4A7C15ull;
	bool live = false;

	double rnd()
	{
		seed ^= seed << 13;
		seed ^= seed >> 7;
		seed ^= seed << 17;
		return (double)(seed >> 11) / (double)(1ull << 53);
	}
	void spawn(P &q, bool anywhere)
	{
		q.col = (int)(rnd() * kCols) % kCols;
		q.y = anywhere ? rnd() * kRows : -rnd() * 2.0;
		q.v = 3.0 + rnd() * 9.0;              // dust falls fast, clumps slow
		q.len = rnd() < 0.25 ? 2 + (int)(rnd() * 2) : 1;
		if (q.len > 1)
			q.v *= 0.55;
	}
	void begin(double now)
	{
		for (auto &q : p)
			spawn(q, true);
		last = now;
		live = true;
	}
	void step(double now)
	{
		if (!live) { begin(now); return; }
		double dt = now - last;
		last = now;
		if (dt > 0.25) dt = 0.25;             // a stall must not teleport it
		for (auto &q : p) {
			q.y += q.v * dt;
			if (q.y - q.len > kRows)
				spawn(q, false);
		}
	}
	// Braille dot bits: column 0 rows 0-3, then column 1.
	void render(Frame &f, int x, int y, Rgb col) const
	{
		static const uint8_t kBit[2][4] = {{0x01, 0x02, 0x04, 0x40},
		                                   {0x08, 0x10, 0x20, 0x80}};
		uint8_t mask[kCells] = {0, 0, 0};
		for (const auto &q : p)
			for (int k = 0; k < q.len; ++k) {
				const int row = (int)(q.y) - k;
				if (row < 0 || row >= kRows)
					continue;
				mask[q.col / 2] |= kBit[q.col % 2][row];
			}
		for (int c = 0; c < kCells; ++c) {
			if (!mask[c])
				continue;
			const unsigned cp = 0x2800u + mask[c];
			char g[4] = {(char)(0xE0 | (cp >> 12)), (char)(0x80 | ((cp >> 6) & 0x3F)),
			             (char)(0x80 | (cp & 0x3F)), 0};
			f.put(x + c, y, g, col);
		}
	}
};

// The run label animates when mining. Each glyph flips from >START< to
// !ACTIVE! at its own moment rather than the whole word switching at once,
// then keeps its own brightness phase so the word never sits still.
struct GlyphKinetics {
	static constexpr int kMax = 12;
	double flip[kMax] = {0};
	double phase[kMax] = {0};
	double rate[kMax] = {0};
	uint64_t seed = 0x2545F4914F6CDD1Dull;

	double next()
	{
		seed ^= seed << 13;
		seed ^= seed >> 7;
		seed ^= seed << 17;
		return (double)(seed >> 11) / (double)(1ull << 53);
	}
	void begin(double now)
	{
		for (int i = 0; i < kMax; ++i) {
			flip[i] = now + next() * 0.75;     // stagger the flip
			phase[i] = next() * 6.28318;       // and the shimmer
			rate[i] = 3.0 + next() * 3.5;
		}
	}
};

struct App {
	SysInfo sys;
	CoreLoad load;
	Engine engine;
	Terminal term;
	Frame frame;

	Screen screen = Screen::Dashboard;
	int focus = F_THREADS;
	int threads = 0;
	int lanes = 64;

	std::vector<double> hist;
	double rate = 0, peak = 0, avg_acc = 0;
	uint64_t avg_n = 0;
	uint64_t last_hashes = 0;
	double last_t = 0;

	stratum::Client client;
	Mode mode = Mode::Idle;
	GlyphKinetics kin;
	Dust dust;
	Settings cfg;
	int pool_cursor = 0, field = 0, pool_scroll = 0;
	Pool draft;
	Identity id_draft;
	// A row being added does not exist in the list yet, so the cursor must not
	// be parked past the end to represent it. That is what let Escape leave an
	// out-of-range cursor that the next keystroke read straight off the end.
	bool editing_new = false;
	int pending_pool = -1;   // pool to select once an address is finally set
	std::string form_err;    // inline, on the form that caused it

	// The ticker. Rebuilt only on a width change, and scrolled from elapsed
	// time rather than accumulated per frame, so a stall cannot make it drift.
	std::vector<std::string> news_items;
	Ticker news;
	int news_w = -1;
	double news_t0 = 0;

	void draw_marquee(int x, int y, int w)
	{
		if (news_items.empty() || w <= 0)
			return;
		if (w != news_w) {
			news.build(news_items, w);
			news_w = w;
		}
		marquee(frame, x, y, w, news, now_s() - news_t0);
	}

	// The transient line in the bottom bar. It expires, because a message that
	// never clears stops being about now.
	std::string status;
	Rgb status_col = pal::kGreen;
	double status_until = 0;

	void note(const std::string &s, bool err = false)
	{
		status = s;
		status_col = err ? pal::kRed : pal::kGreen;
		status_until = now_s() + (err ? 10.0 : 4.0);
	}

	// Every path that can move or delete a row goes through this. The indices
	// are used to subscript the vector on the very next frame.
	void clamp_pools()
	{
		const int n = (int)cfg.pools.size();
		if (n <= 0) {
			cfg.selected = pool_cursor = pool_scroll = 0;
			cfg.chosen = false;
			return;
		}
		if (cfg.selected < 0 || cfg.selected >= n) cfg.selected = 0;
		if (pool_cursor < 0) pool_cursor = 0;
		if (pool_cursor >= n) pool_cursor = n - 1;
		if (pool_scroll < 0) pool_scroll = 0;
		if (pool_scroll >= n) pool_scroll = n - 1;
	}

	bool pool_ready() const { return client.state() == stratum::State::Ready; }

	// When the logo's gloss sweep started, or negative for still. It runs while
	// work is actually being done rather than merely while the user has asked
	// for it, so it goes dead the moment the pool does -- the same rule the
	// status line and the run label follow.
	double gloss_t0 = -1;

	// The single source of truth for "what is going on with the pool". The bug
	// this replaces was a status line that reported the user's *intent*
	// (mode == Mining) as though it were the pool's state, so a pool that had
	// been dead for half an hour still rendered as a healthy green "mining".
	struct StatusLine {
		const char *glyph;
		std::string text;
		Rgb col;
	};
	StatusLine pool_status() const
	{
		if (!cfg.chosen || cfg.pools.empty())
			return {"○ ", "no pool selected", pal::kDim};
		if (!cfg.id.complete())
			return {"! ", "no payout address — press i", pal::kRed};
		if (!client.running())
			return {"○ ", "not connected", pal::kRed};

		const stratum::State st = client.state();
		if (st == stratum::State::Ready)
			return {"● ", mode == Mode::Mining ? "mining" : "verified", pal::kGreen};

		// Short, and about now. The diagnosis is a separate line with the whole
		// panel width, so repeating it here only costs the room that would have
		// shown what the client is doing this second.
		const char *word;
		switch (st) {
		case stratum::State::Resolving:   word = "resolving"; break;
		case stratum::State::Connecting:  word = "connecting"; break;
		case stratum::State::Subscribing: word = "subscribing"; break;
		case stratum::State::Authorizing: word = "authorizing"; break;
		case stratum::State::Waiting:     word = "waiting for work"; break;
		case stratum::State::Failed:      word = "not connected"; break;
		default:                          word = "connecting"; break;
		}
		std::string text = word;
		// A countdown belongs inline: it is the one part of the note that
		// answers "is it doing anything, or is it stuck?".
		const std::string n = client.status_text();
		const size_t r = n.find("retry in ");
		if (r != std::string::npos)
			text = "retrying in " + n.substr(r + 9);
		if (mode == Mode::Mining || st == stratum::State::Failed)
			return {"! ", text, pal::kRed};
		return {"◐ ", text, pal::kLabel};
	}

	void init()
	{
		sys.probe();
		threads = sys.ncpu;
		if (!load_settings(cfg) || cfg.pools.empty()) {
			// First run: seed the pool list so there is nothing to type but
			// the two things only the user knows.
			for (const auto &p : kPresets)
				cfg.pools.push_back(p);
			cfg.selected = 0;
		}
		clamp_pools();
		if (!cfg.id.complete()) {
			id_draft = cfg.id;
			screen = Screen::Setup;
			field = 0;
		}
		news_items = load_news();
		news_t0 = now_s();
		hist.assign(400, 0.0);
		uint8_t header[1487];
		for (size_t i = 0; i < sizeof(header); ++i)
			header[i] = (uint8_t)(i * 31 + 7);
		engine.configure(header, sizeof(header));
		last_t = now_s();
		load.sample(sys.ncpu);
		connect_selected();
	}

	// A chosen pool is tested, always. Nothing else explains a status line.
	// stop() no longer waits on the network, so calling this from a keystroke
	// cannot stall the UI even if the previous pool is a black hole.
	void connect_selected()
	{
		client.stop();
		clamp_pools();
		if (!cfg.chosen || cfg.pools.empty())
			return;
		if (!cfg.id.complete()) {
			note("set your payout address first — press i", true);
			return;
		}
		const Pool &p = cfg.pools[(size_t)cfg.selected];
		if (p.host.empty()) {
			note("\"" + p.label + "\" has no host — press e to set one", true);
			return;
		}
		stratum::Config sc;
		sc.host = p.host;
		sc.port = p.port;
		sc.user = cfg.id.user();
		sc.pass = "x";
		client.start(sc);
		note("testing " + p.label);
	}

	// Mining and a pool connection are separate things; stopping one has to
	// stop the other cleanly wherever the pool identity changes underneath.
	void stop_mining()
	{
		if (mode != Mode::Mining)
			return;
		engine.stop();
		engine.set_pool(nullptr);
		mode = Mode::Idle;
	}

	void tick()
	{
		const double t = now_s();
		const uint64_t h = g_hashes.load(std::memory_order_relaxed);
		const double dt = t - last_t;
		if (dt > 0.05) {
			rate = (double)(h - last_hashes) / dt;
			last_hashes = h;
			last_t = t;
			if (engine.active()) {
				// The plot always tells the truth, including the drop to zero
				// when the pool goes away -- that dip is the signal.
				hist.erase(hist.begin());
				hist.push_back(rate);
				if (rate > peak)
					peak = rate;
				// The average describes how fast this machine hashes, so only
				// sample it while there is work. Averaging in the zeros of an
				// outage decays it towards nothing and describes neither.
				if (mode == Mode::Benchmark || pool_ready()) {
					avg_acc += rate;
					++avg_n;
				}
			}
		}
		load.sample(sys.ncpu);

		// Restarting the clock rather than merely gating it means the burst
		// replays every time work resumes, so a pool that drops and comes back
		// is visible in the logo as well as in the status line.
		if (mode == Mode::Mining && pool_ready()) {
			if (gloss_t0 < 0)
				gloss_t0 = t;
		} else {
			gloss_t0 = -1;
		}
	}

	// --- drawing ---------------------------------------------------------

	static std::string mhs(double v)
	{
		char b[32];
		snprintf(b, sizeof(b), "%.2f", v / 1e6);
		return b;
	}

	void draw_header(int x, int y, int w, int h)
	{
		window(frame, x, y, w, h, "The Walled Garden Hasher", false, pal::kChrome);

		// The machine is the headline, in the block face. Read from sysctl
		// rather than hard-coded, so it says whatever silicon it is running on.
		//
		// `last` is the final row inside the border. Every write is bounded by
		// it: three lines were being written into a four-row window, so the
		// machine summary landed on top of the bottom border.
		const int last = y + h - 2;
		const int tw = w - 6;
		int ty = y + 1;
		auto line = [&](const std::string &s, Rgb col, bool bold) {
			if (ty <= last)
				frame.text(x + 3, ty++, ellipsize(s, tw), col, pal::kPanel, bold);
		};

		const int bw = block_text_width(sys.model);
		if (h >= 8 && bw <= w - 6) {
			block_text(frame, x + 3, ty, sys.model, pal::kInk);
			ty += kBlockRows;
		} else {
			line(sys.model, pal::kInk, true);
		}

		char b[160];
		snprintf(b, sizeof(b), "%d cores  ·  %dP + %dE  ·  %.0f GB", sys.ncpu, sys.nperf,
		         sys.neff, sys.mem_gb);
		if (last - ty >= 1) {
			line("VerusHash 2.2  ·  AArch64", pal::kLabel, false);
			line(b, pal::kLabel, false);
		} else {
			// One row left: fold the two lines into the one that identifies
			// both the algorithm and the machine.
			char c[200];
			snprintf(c, sizeof(c), "VerusHash 2.2  ·  %d cores  ·  %dP + %dE", sys.ncpu,
			         sys.nperf, sys.neff);
			line(c, pal::kLabel, false);
		}
		// Only if a row is genuinely spare, for the same reason.
		if (h >= 6 && ty <= last)
			rainbow_rule(frame, x + 2, last, w - 4);
	}

	// The logo stands in the plot rather than under it: its glyphs occlude the
	// braille, its negative space lets the stream through, and whatever the
	// waterline has reached lights up in that row's fastfetch stripe colour.
	// Rock in a stream.
	void draw_watermark(int gx, int gy, int gw, int gh, const std::vector<int> &fill,
	                    PlotMask &occlude)
	{
		const LogoArt *art = nullptr;
		int lw = 0;
		for (const LogoArt *cand : {&kLogoLarge, &kLogoSmall}) {
			int wmax = 0;
			for (int r = 0; r < cand->rows; ++r) {
				const int n = (int)strlen(cand->line[r]);
				if (n > wmax)
					wmax = n;
			}
			if (gw >= wmax + 4 && gh >= cand->rows) {
				art = cand;
				lw = wmax;
				break;
			}
		}
		if (!art)
			return;

		const int ox = gx + (gw - lw) / 2;
		const int oy = gy + (gh - art->rows) / 2;
		const int dots_h = gh * 4;

		// A specular highlight travelling across the logo while work is being
		// done. The band is measured as c + 2*r because a cell is about twice
		// as tall as it is wide -- the same anisotropy the feathering below has
		// to cancel. Using c + r instead lays the band over at roughly 27
		// degrees on screen, which reads as horizontal drift rather than as a
		// glint travelling across a surface.
		const bool gloss = gloss_t0 >= 0;
		const double span = (double)lw + 2.0 * (double)art->rows;
		const double gwidth = 4.0 + span * 0.10;
		double head = 0;
		if (gloss) {
			const double age = now_s() - gloss_t0;
			// Quick sweeps to begin with, settling into a slower idle. The
			// burst is what makes pressing MINE feel like it did something;
			// holding that rate for an eight-hour run would be exhausting.
			const double ramp = age > 7.0 ? 1.0 : age / 7.0;
			const double period = 0.85 + 2.9 * ramp;
			const double travel = span + 2.0 * gwidth;
			head = fmod(age, period) / period * travel - gwidth;
		}

		for (int r = 0; r < art->rows; ++r) {
			const char *row = art->line[r];
			// Six stripes spread across the logo's height, green at the crown.
			const int band = (r * 6) / art->rows;
			const Rgb bright = pal::kRainbow[band < 6 ? band : 5];
			for (int c = 0; row[c]; ++c) {
				if (row[c] == ' ')
					continue;   // water flows through the gaps
				const int cx = ox + c - gx, cy = oy + r - gy;
				if (cx < 0 || cx >= gw || cy < 0 || cy >= gh)
					continue;
				occlude.hide[(size_t)cy * (size_t)gw + (size_t)cx] = kDotsAll;

				// Submerged when the fill at this column reaches into this
				// cell's four dot rows.
				const int top_dot = dots_h - fill[(size_t)cx];
				const bool wet = top_dot <= cy * 4 + 3;
				Rgb col = wet ? bright : lerp(pal::kPanel, pal::kChrome, 0.55);

				bool hot = false;
				if (gloss) {
					double v = 1.0 - fabs((double)c + 2.0 * (double)r - head) / gwidth;
					if (v > 0) {
						v *= v;   // tighten the core, so it is a highlight and
						          // not a wash across half the logo
						// The dry metal above the waterline takes more of the
						// light than the lit water below it does; an equal
						// blend washes the stripes out where they are the
						// whole point.
						col = lerp(col, pal::kGloss, v * (wet ? 0.5 : 0.85));
						hot = v > 0.55;
					}
				}
				const char g[2] = {row[c], 0};
				frame.put(ox + c, oy + r, g, col, pal::kPanel, hot);
			}
		}

		// Feather the approach. A cell can hold one glyph, so the logo and the
		// stream can never blend inside the same cell -- but the cells around
		// the logo are pure braille, and braille has 2x4 subpixels. Dropping
		// the dot column or row that faces the logo thins the water as it
		// reaches the rock instead of ending it on a cell boundary.
		const std::vector<uint8_t> solid = occlude.hide;
		auto solid_at = [&](int cx, int cy) {
			return cx >= 0 && cx < gw && cy >= 0 && cy < gh &&
			       solid[(size_t)cy * (size_t)gw + (size_t)cx] == kDotsAll;
		};
		for (int cy = 0; cy < gh; ++cy)
			for (int cx = 0; cx < gw; ++cx) {
				const size_t at = (size_t)cy * (size_t)gw + (size_t)cx;
				if (solid[at])
					continue;

				// Dot removal: one row or one column from the facing edge.
				// Dots are ~square, so this is the same physical step in
				// either direction.
				uint8_t f = 0;
				if (solid_at(cx + 1, cy)) f |= kDotsRight;
				if (solid_at(cx - 1, cy)) f |= kDotsLeft;
				if (solid_at(cx, cy + 1)) f |= kDotsBottom;
				if (solid_at(cx, cy - 1)) f |= kDotsTop;
				occlude.hide[at] = f;

				// Fade radius: one cell above and below, two to each side.
				// A cell is about twice as tall as it is wide, so equal cell
				// counts would put a band twice as thick top and bottom.
				uint8_t fade = 0;
				if (f)
					fade = 140;
				else if (solid_at(cx + 2, cy) || solid_at(cx - 2, cy))
					fade = 70;
				occlude.fade[at] = fade;
			}
	}

	void draw_graph(int x, int y, int w, int h)
	{
		const bool foc = false;
		window(frame, x, y, w, h, "Hashrate", foc, pal::kGreen);
		const int gx = x + 9, gy = y + 1, gw = w - 11, gh = h - 3;
		if (gw < 4 || gh < 2)
			return;

		double vmax = 1;
		for (double v : hist)
			if (v > vmax)
				vmax = v;
		vmax *= 1.15;

		// Scale ticks, top and bottom. With no data the top of the scale is an
		// artefact of the floor, and printing it as 0.00 above a 0.00 baseline
		// reads as a broken axis rather than an empty one.
		bool any = false;
		for (double v : hist)
			if (v > 0) { any = true; break; }
		frame.text(x + 2, gy, any ? mhs(vmax) : "—", pal::kDim);
		frame.text(x + 2, gy + gh - 1, "0.00", pal::kDim);
		for (int j = 0; j < gh; ++j)
			frame.put(gx - 1, gy + j, "│", pal::kDim);

		const std::vector<int> fill = plot_fill_dots(gw, gh, hist, vmax);
		PlotMask occlude;
		occlude.resize((size_t)gw * (size_t)gh);
		draw_watermark(gx, gy, gw, gh, fill, occlude);
		braille_plot(frame, gx, gy, gw, gh, hist, vmax, &occlude);

		// Readout row.
		int rx = x + 3;
		const int ry = y + h - 2;
		rx = frame.text(rx, ry, "now ", pal::kLabel);
		rx = frame.text(rx, ry, mhs(rate) + " MH/s", pal::kGreen, pal::kPanel, true);
		rx = frame.text(rx + 3, ry, "peak ", pal::kLabel);
		rx = frame.text(rx, ry, mhs(peak), pal::kYellow, pal::kPanel, true);
		rx = frame.text(rx + 3, ry, "avg ", pal::kLabel);
		rx = frame.text(rx, ry, avg_n ? mhs(avg_acc / (double)avg_n) : "0.00", pal::kInk);
		// Intent is not state. "mining" here has to mean hashes are being
		// produced against real work, or the readout is decoration.
		const bool stalled = mode == Mode::Mining && !pool_ready();
		const char *what = stalled                  ? "◌ stalled"
		                 : mode == Mode::Mining     ? "● mining"
		                 : mode == Mode::Benchmark ? "● benchmark"
		                                           : "○ idle";
		rx = frame.text(rx + 3, ry, what,
		                stalled ? pal::kRed
		                        : (mode == Mode::Idle ? pal::kDim : pal::kGreen));
	}

	void draw_cores(int x, int y, int w, int h)
	{
		const bool foc = (screen == Screen::Dashboard) &&
		                 (focus == F_THREADS || focus == F_LANES || focus == F_BENCH);
		window(frame, x, y, w, h, "Cores", foc, pal::kBlue);

		// Two cores per line, each a braille trace of its own recent load --
		// the same plotting language as the hashrate graph, which solid bars
		// were not. Colour ramps within the cluster's family so P and E stay
		// distinguishable while magnitude reads off the ramp.
		// pad + cores + gap + (control, gap, control, gap, control) + pad
		const int rows = h - 10;
		const int cols = 2;
		const int per = (sys.ncpu + cols - 1) / cols;
		const int top_pad = (rows > per) ? (rows - per) / 2 : 0;
		const int cw = (w - 6) / cols;
		const int mw = cw - 10;
		int hidden = 0;
		for (int i = 0; i < sys.ncpu; ++i) {
			// Centre the block between the title and the controls, so the
			// slack on a machine with few cores reads as symmetric padding
			// rather than a gap above the controls.
			const int cx = x + 3 + (i / per) * cw;
			const int cy = y + 2 + top_pad + (i % per);
			if (i % per >= rows || rows <= 0) {
				++hidden;
				continue;
			}
			// Performance cores are listed first even though Apple numbers
			// them last.
			const int cpu = sys.nperf ? ((i < sys.nperf) ? sys.pbase + i : i - sys.nperf)
			                          : i;
			const bool p = sys.is_perf(cpu);
			char lbl[16];
			snprintf(lbl, sizeof(lbl), "%s%d", p ? "P" : "E", p ? i : i - sys.nperf);
			const double u = (cpu < (int)load.pct.size()) ? load.pct[cpu] : 0.0;
			const Rgb hi = p ? pal::kGreen : pal::kBlue;
			const Rgb lo = lerp(pal::kDim, hi, 0.25);
			frame.text(cx, cy, lbl, p ? pal::kInk : pal::kLabel);
			if (mw > 2 && cpu < (int)load.hist.size())
				braille_spark(frame, cx + 3, cy, mw, 1, load.hist[cpu], lo, hi);
			char pc[8];
			snprintf(pc, sizeof(pc), "%3d%%", (int)(u * 100));
			frame.text(cx + 4 + (mw > 2 ? mw : 0), cy, pc, lerp(pal::kDim, hi, 0.4 + u * 0.6));
		}

		// Silently dropping cores makes a short window look like a machine
		// with fewer cores than it has.
		if (hidden > 0 && rows > 0) {
			char more[48];
			snprintf(more, sizeof(more), "+%d more — taller window to see them", hidden);
			frame.text(x + 3, y + 2 + (rows > 0 ? rows - 1 : 0),
			           ellipsize(more, w - 6), pal::kDim);
		}

		// Three controls, one per row, each on its own line with a gap either
		// side so the focus ring has somewhere to go.
		const int bx = x + 2, bw = w - 4;
		const int ix = bx + 3, iw = bw - 6;
		int cy = y + h - 7;
		draw_spin(ix, cy, iw, "threads", std::to_string(threads), focus == F_THREADS);
		if (focus == F_THREADS)
			focus_box(bx, cy, bw, pal::kYellow);

		cy += 2;
		draw_spin(ix, cy, iw, "lanes", std::to_string(lanes), focus == F_LANES);
		if (focus == F_LANES)
			focus_box(bx, cy, bw, pal::kYellow);

		// Benchmark belongs with the cores: it is the synthetic run, nothing
		// to do with a pool.
		cy += 2;
		const bool is_bench = mode == Mode::Benchmark;
		draw_button(ix, cy, iw, is_bench ? "Stop benchmark" : "Benchmark",
		            focus == F_BENCH, is_bench ? pal::kRed : pal::kYellow);
		if (focus == F_BENCH)
			focus_box(bx, cy, bw, is_bench ? pal::kRed : pal::kYellow);
	}

	// System 7 signalled the active control with a ring around it. One row is
	// too short to box, so controls are spaced and the gaps carry the ring --
	// only one control is focused at a time, so adjacent rings never collide.
	void focus_box(int x, int y, int w, Rgb col)
	{
		frame.put(x, y - 1, "╭", col);
		frame.hline(x + 1, y - 1, w - 2, "─", col);
		frame.put(x + w - 1, y - 1, "╮", col);
		frame.put(x, y, "│", col);
		frame.put(x + w - 1, y, "│", col);
		frame.put(x, y + 1, "╰", col);
		frame.hline(x + 1, y + 1, w - 2, "─", col);
		frame.put(x + w - 1, y + 1, "╯", col);
	}

	// >START< while the pool is ready, !ACTIVE! once mining -- flipped one
	// glyph at a time on staggered timers, each then shimmering on its own
	// phase so the word reads as working rather than as a static label.
	// `w` is the room from x to the panel border. The trailing note used to be
	// written unbounded and ran straight through the right-hand border on a
	// narrow panel.
	void draw_run_label(int x, int y, int w, bool ready, bool mining, bool foc)
	{
		static const char *kReady = ">MINE<";
		static const char *kActive = "!MINING!";
		if (foc)
			frame.text(x - 2, y, "▸", mining || ready ? pal::kGreen : pal::kDim);
		if (mining && !ready) {
			// The workers are up but there is no work to give them. An
			// animated !MINING! here is the difference between noticing a dead
			// pool and leaving the machine running all night for nothing.
			frame.text(x, y, "STALLED", pal::kRed, pal::kPanel, true);
			if (w > 18)
				frame.text(x + 9, y, ellipsize("⏎ to stop", w - 9), pal::kDim);
			return;
		}
		if (!ready && !mining) {
			frame.text(x, y, "mine", pal::kDim);
			if (w > 10)
				frame.text(x + 6, y,
				           ellipsize(cfg.chosen ? "(waiting for the pool)"
				                                : "(select a pool)",
				                     w - 6),
				           pal::kDim);
			return;
		}
		if (!mining) {
			frame.text(x, y, kReady, pal::kGreen, pal::kPanel, true);
			return;
		}
		const double t = now_s();
		const int n = (int)strlen(kActive);
		for (int i = 0; i < n; ++i) {
			const bool flipped = t >= kin.flip[i];
			const char c = flipped ? kActive[i]
			                       : (i < (int)strlen(kReady) ? kReady[i] : ' ');
			const double s = 0.55 + 0.45 * sin(t * kin.rate[i] + kin.phase[i]);
			const char g[2] = {c, 0};
			frame.put(x + i, y, g, lerp(lerp(pal::kPanel, pal::kGreen, 0.45),
			                            pal::kGreen, s), pal::kPanel, true);
		}
		dust.step(t);
		dust.render(frame, x + n + 1, y, lerp(pal::kPanel, pal::kGreen, 0.75));
	}

	void draw_spin(int x, int y, int w, const std::string &label, const std::string &val,
	               bool foc)
	{
		const Rgb fg = foc ? pal::kInk : pal::kLabel;
		if (foc)
			frame.text(x - 2, y, "▸", pal::kYellow);
		frame.text(x, y, label, fg, pal::kPanel, foc);
		const std::string v = "◀ " + val + " ▶";
		int vx = x + w - disp_len(v) - 2;
		const int after_label = x + disp_len(label) + 1;
		if (vx < after_label)
			vx = after_label;
		frame.text(vx, y, v, foc ? pal::kYellow : pal::kDim, pal::kPanel, foc);
	}

	void draw_button(int x, int y, int w, const std::string &label, bool foc, Rgb col)
	{
		(void)w;
		if (foc)
			frame.text(x - 2, y, "▸", col);
		frame.text(x, y, label, foc ? col : pal::kLabel, pal::kPanel, foc);
	}

	// A dash reads as "no value yet" without pretending the field is absent.
	static std::string dash(bool have, const std::string &v) { return have ? v : "—"; }

	// `w` is the width available from x, so a long value stops at the panel
	// border instead of eating it.
	void stat(int x, int y, int w, const std::string &k, const std::string &v, Rgb col)
	{
		frame.text(x, y, k, pal::kLabel);
		frame.text(x + 12, y, ellipsize(v, w - 12), col);
	}

	void draw_pool_panel(int x, int y, int w, int h)
	{
		clamp_pools();
		const bool foc_pools = (screen == Screen::Dashboard) && focus == F_POOLS;
		const bool foc_mine = (screen == Screen::Dashboard) && focus == F_MINE;
		const bool foc = foc_pools || foc_mine;
		window(frame, x, y, w, h, "Pool", foc, pal::kPurple);
		const int c = x + 3;
		const int cw = w - 5;                 // room from c to the border
		const int btn = y + h - 3;
		const int mine_row = y + h - 5;
		int ty = y + 2;
		// The mine control's focus ring occupies mine_row +/- 1, so the last
		// row content may use is mine_row - 2. Writing to mine_row - 1 does not
		// overflow the panel -- it gets quietly painted over by the ring, which
		// is worse, because the row simply vanishes when the control is focused.
		auto fits = [&](int need) { return ty + need - 1 <= mine_row - 2; };

		// Blank separators are the first thing to go when the window is short:
		// they are the only rows here carrying no information, and dropping
		// them is what keeps the share counters on screen at 24 rows. Below
		// that, the pool's *name* goes before its *state* -- a panel with room
		// for one line has to spend it on whether anything is working.
		const int budget = (mine_row - 2) - ty + 1;
		const bool roomy = budget >= 10;
		auto sep = [&]() { if (roomy) ++ty; };

		if (budget >= 4) {
			if (!cfg.chosen || cfg.pools.empty()) {
				if (fits(1)) frame.text(c, ty++, "no pool selected", pal::kDim);
				if (fits(2)) { ++ty; frame.text(c, ty++, "choose one below", pal::kDim); }
			} else {
				const Pool &p = cfg.pools[(size_t)cfg.selected];
				if (fits(1))
					frame.text(c, ty++, ellipsize("● " + p.label, cw), pal::kPurple,
					           pal::kPanel, true);
				// From the client when there is one, so this row reports the
				// socket rather than the selection. Drawing p.host here means
				// drawing what we intended to connect to, which is the same
				// thing right up until the moment it is not.
				if (fits(1)) {
					const std::string live = client.endpoint();
					frame.text(c + 2, ty++,
					           ellipsize(live.empty() ? p.host + ":" + p.port : live,
					                     cw - 2),
					           live.empty() ? pal::kDim : pal::kInk);
				}
				// The address yields before the share counters do: it is also
				// on the Pools screen and in the config, whereas whether
				// shares are landing is only ever here. An address that is
				// *missing* still gets the row, because that is a fault.
				if (fits(1) && (budget >= 6 || !cfg.id.complete()))
					frame.text(c + 2, ty++,
					           cfg.id.complete() ? ellipsize(cfg.id.shortened(), cw - 2)
					                             : "(no payout address)",
					           cfg.id.complete() ? pal::kLabel : pal::kRed);
			}
		}

		const stratum::StatsView sx = client.stats();
		sep();
		if (fits(1)) {
			// The pool's actual state, never the user's intention. See
			// pool_status(): this line is the one that used to say "mining"
			// for half an hour after the pool had gone.
			const StatusLine s = pool_status();
			stat(c, ty++, cw, "status", s.glyph + s.text, s.col);
		}
		if (fits(1)) {
			// While a retry is in flight the live note reads "connecting", so
			// the reason it is retrying has to persist somewhere. It takes the
			// difficulty row, which reads "—" for exactly as long as there is
			// something wrong.
			const std::string why = client.last_error();
			if (!pool_ready() && !why.empty())
				// Full width, no key column: the actionable half of these
				// messages is at the end, and it is the half that a 12-column
				// indent would cut off.
				frame.text(c, ty++, ellipsize("⚠ " + why, cw), pal::kRed);
			else
				stat(c, ty++, cw, "difficulty",
				     sx.difficulty > 0 ? std::to_string((long)sx.difficulty) : "—",
				     sx.difficulty > 0 ? pal::kInk : pal::kDim);
		}

		// Whether shares are landing is the single most important thing this
		// panel reports, so it degrades to one line rather than disappearing.
		char age[32] = "—";
		if (sx.last_share_time > 0)
			snprintf(age, sizeof(age), "%.0fs ago", now_wall() - sx.last_share_time);
		const Rgb acc_col = sx.accepted ? pal::kGreen : pal::kDim;
		const Rgb bad_col = sx.rejected ? pal::kRed : (sx.stale ? pal::kYellow : pal::kDim);
		sep();
		if (fits(3)) {
			char line[96];
			snprintf(line, sizeof(line), "%llu accepted", (unsigned long long)sx.accepted);
			stat(c, ty++, cw, "shares", line, acc_col);
			snprintf(line, sizeof(line), "%llu stale · %llu rejected",
			         (unsigned long long)sx.stale, (unsigned long long)sx.rejected);
			stat(c, ty++, cw, "", line, bad_col);
			stat(c, ty++, cw, "last share", age,
			     sx.last_share_time > 0 ? pal::kInk : pal::kDim);
		} else if (fits(2)) {
			char line[96];
			snprintf(line, sizeof(line), "%llu accepted · %llu stale · %llu rej",
			         (unsigned long long)sx.accepted, (unsigned long long)sx.stale,
			         (unsigned long long)sx.rejected);
			stat(c, ty++, cw, "shares", line, acc_col);
			stat(c, ty++, cw, "last share", age,
			     sx.last_share_time > 0 ? pal::kInk : pal::kDim);
		} else if (fits(1)) {
			char line[96];
			snprintf(line, sizeof(line), "%llu ok·%llu stale·%llu rej",
			         (unsigned long long)sx.accepted, (unsigned long long)sx.stale,
			         (unsigned long long)sx.rejected);
			stat(c, ty++, cw, "shares", line, acc_col);
		}

		const int bx = x + 2, bw = w - 4;
		const int ix = bx + 3;
		const bool verified = pool_ready();
		draw_run_label(ix, mine_row, bw - 6, verified, mode == Mode::Mining, foc_mine);
		if (foc_mine)
			focus_box(bx, mine_row, bw,
			          mode == Mode::Mining && !verified ? pal::kRed
			          : (mode == Mode::Mining || verified) ? pal::kGreen
			                                               : pal::kDim);
		draw_button(ix, btn, bw - 6, cfg.chosen ? "Change pool…" : "Select pool…",
		            foc_pools, pal::kPurple);
		if (foc_pools)
			focus_box(bx, btn, bw, pal::kPurple);
	}

	void draw_dashboard()
	{
		const int W = frame.width(), H = frame.height();
		int y = 0;
		const int hh = (H >= 32) ? 9 : (H >= 26 ? 7 : 4);
		draw_header(0, y, W, hh);
		y += hh;
		// Side by side, so both panels take the taller requirement: cores need
		// pad + rows + pad + spinners + button + pad; the pool panel needs
		// identity, status, the share block and its controls.
		//
		// pool_need was 15 against a panel that needs 18, so the share block
		// never fitted -- and because `bot` is only ever clamped downwards, a
		// bigger terminal did not help. On a ten-core machine the counters were
		// unreachable at every size.
		const int cores_need = (sys.ncpu + 1) / 2 + 10;
		const int pool_need = 18;
		int bot = cores_need > pool_need ? cores_need : pool_need;
		// Reserve a readable graph rather than splitting the remainder evenly:
		// the bottom panels have a fixed content budget, the graph just wants
		// whatever is left. The floor is where both panels' controls are still
		// on screen -- below that they were drawn past the bottom of the
		// terminal and the user was pressing Enter on things they could not see.
		const int bot_min = 9;
		// The ticker is chrome, so it is the first thing dropped: it gets its
		// row only once the graph and both panels have theirs.
		const bool news_row = !news_items.empty() && (H - y) >= 5 + bot_min + 2;
		const int reserved = news_row ? 1 : 0;
		const int bot_max = (H - y) - 6 - reserved;
		if (bot > bot_max) bot = bot_max;
		if (bot < bot_min) bot = bot_min;
		int gh = H - y - bot - 1 - reserved;
		if (gh < 5) gh = 5;
		if (news_row) {
			draw_marquee(0, y, W);
			++y;
		}
		draw_graph(0, y, W, gh);
		y += gh;
		const int lw = W / 2;
		draw_cores(0, y, lw, bot);
		draw_pool_panel(lw, y, W - lw, bot);
		help(" ↑↓ move   ←→ adjust   ⏎ select   i address   q quit ");
	}

	// Pick a pool. That is the whole screen: the wallet is already known, so
	// selecting costs one keystroke and nothing has to be retyped.
	void draw_pools()
	{
		clamp_pools();
		const int W = frame.width(), H = frame.height();
		window(frame, 0, 0, W, H - 1, "Pools", true, pal::kPurple);

		int ty = 2;
		frame.text(4, ty++, "mining as", pal::kLabel);
		frame.text(15, ty - 1,
		           ellipsize(cfg.id.complete() ? cfg.id.user() : "(not set — press i)",
		                     W - 19),
		           cfg.id.complete() ? pal::kInk : pal::kRed, pal::kPanel, true);
		++ty;

		// Rows are two apart because each carries a focus ring. Without a
		// window they ran off the bottom: over the hint, over the border and
		// then off screen entirely, with the cursor still live on a row nobody
		// could see.
		const int first = ty;
		const int last = H - 5;
		int visible = (last - first) / 2 + 1;
		if (visible < 1) visible = 1;
		const int n = (int)cfg.pools.size();
		if (pool_cursor < pool_scroll)
			pool_scroll = pool_cursor;
		if (pool_cursor >= pool_scroll + visible)
			pool_scroll = pool_cursor - visible + 1;
		if (pool_scroll > n - visible)
			pool_scroll = n - visible;
		if (pool_scroll < 0)
			pool_scroll = 0;

		const int hostcol = W > 56 ? 30 : 8 + (W - 16) / 2;
		for (int i = pool_scroll; i < n && i < pool_scroll + visible; ++i) {
			const bool cur = i == pool_cursor;
			const bool sel = i == cfg.selected && cfg.chosen;
			if (cur) {
				frame.text(2, ty, "▸", pal::kYellow);
				focus_box(3, ty, W - 6, pal::kYellow);
			}
			frame.text(6, ty, sel ? "●" : "○", sel ? pal::kPurple : pal::kDim);
			frame.text(8, ty, ellipsize(cfg.pools[(size_t)i].label, hostcol - 9),
			           cur ? pal::kInk : pal::kLabel, pal::kPanel, cur);
			frame.text(hostcol, ty,
			           ellipsize(cfg.pools[(size_t)i].host + ":" +
			                         cfg.pools[(size_t)i].port,
			                     W - hostcol - 4),
			           cur ? pal::kPurple : pal::kDim);
			ty += 2;
		}
		if (pool_scroll > 0)
			frame.text(W - 6, first, "↑", pal::kYellow);
		if (pool_scroll + visible < n)
			frame.text(W - 6, first + (visible - 1) * 2, "↓", pal::kYellow);
		if (n > visible) {
			char pos[32];
			snprintf(pos, sizeof(pos), "%d of %d", pool_cursor + 1, n);
			frame.text(W - 6 - (int)strlen(pos), H - 4, pos, pal::kDim);
		}

		frame.text(4, H - 4,
		           ellipsize("the endpoint is editable — press e if a pool has moved",
		                     W - 20),
		           pal::kDim);
		help(" ↑↓ move   ⏎ select   e edit   n new   d delete   i identity   esc back ");
	}

	void draw_edit()
	{
		const int W = frame.width(), H = frame.height();
		window(frame, 0, 0, W, H - 1, editing_new ? "New pool" : "Edit pool", true,
		       pal::kPurple);
		const char *names[3] = {"name", "host", "port"};
		std::string *vals[3] = {&draft.label, &draft.host, &draft.port};
		int ty = 3;
		for (int i = 0; i < 3; ++i) {
			const bool foc = i == field;
			if (foc)
				focus_box(3, ty, W - 6, pal::kYellow);
			frame.text(6, ty, names[i], foc ? pal::kInk : pal::kLabel, pal::kPanel, foc);
			const std::string v = *vals[i] + (foc ? "▌" : "");
			frame.text(20, ty, ellipsize(v.empty() ? "—" : v, W - 24),
			           foc ? pal::kYellow : pal::kInk);
			ty += 2;
		}
		if (!form_err.empty())
			frame.text(6, ty + 1, ellipsize(form_err, W - 10), pal::kRed);
		frame.text(6, H - 4,
		           ellipsize("the payout address is set once under identity, not per pool",
		                     W - 10),
		           pal::kDim);
		help(" ↑↓ field   type to edit   ⏎ save   esc cancel ");
	}

	// Asked once, on first run. Everything else can be picked from a list.
	void draw_setup()
	{
		const int W = frame.width(), H = frame.height();
		window(frame, 0, 0, W, H - 1, "Welcome", true, pal::kGreen);

		int ty = 3;
		if (block_text_width("WGH") <= W - 8) {
			block_text(frame, 6, ty, "WGH", pal::kInk);
			ty += kBlockRows + 1;
		}
		frame.text(6, ty++, "Mining at the speed of Apple Silicon!", pal::kGreen,
		           pal::kPanel, true);
		++ty;
		frame.text(6, ty++, "Two things, once. Everything after this is a list.",
		           pal::kLabel);
		++ty;

		const char *names[2] = {"Verus address", "rig name"};
		std::string *vals[2] = {&id_draft.address, &id_draft.rig};
		const char *hints[2] = {"the wallet rewards are paid to",
		                        "how this machine shows up on the pool"};
		for (int i = 0; i < 2; ++i) {
			const bool foc = i == field;
			if (foc)
				focus_box(5, ty, W - 10, pal::kGreen);
			frame.text(8, ty, names[i], foc ? pal::kInk : pal::kLabel, pal::kPanel, foc);
			const std::string v = *vals[i] + (foc ? "▌" : "");
			frame.text(26, ty, ellipsize(v.empty() ? "—" : v, W - 30),
			           foc ? pal::kYellow : pal::kInk);
			// Below the ring, not on it: the ring occupies ty +/- 1.
			// For the address the hint doubles as live validation, so a typo
			// is caught here rather than as an authorize rejection minutes later.
			const char *bad = (i == 0) ? id_draft.shape() : nullptr;
			frame.text(8, ty + 2, ellipsize(bad ? bad : hints[i], W - 12),
			           bad ? pal::kRed : pal::kDim);
			ty += 4;
		}
		if (!form_err.empty())
			frame.text(6, ty, ellipsize(form_err, W - 10), pal::kRed);
		frame.text(6, H - 4,
		           ellipsize("stored in ~/.config/vh22/config — no wallet, no private key, "
		                     "just the payout address",
		                     W - 10),
		           pal::kDim);
		help(cfg.id.complete() ? " ↑↓ field   type to enter   ⏎ save   esc cancel "
		                       : " ↑↓ field   type to enter   ⏎ save ");
	}

	void help(const std::string &s)
	{
		const int H = frame.height(), W = frame.width();
		frame.hline(0, H - 1, W, " ", pal::kLabel, pal::kBar);
		// The status wins the space it needs; the key hints are the thing that
		// can be shortened, since they are the same every frame.
		std::string msg;
		if (!status.empty() && now_s() < status_until)
			msg = ellipsize(status, W - 4);
		else
			status.clear();
		const int msg_w = msg.empty() ? 0 : disp_len(msg) + 2;
		frame.text(1, H - 1, ellipsize(s, W - msg_w - 2), pal::kLabel, pal::kBar);
		if (!msg.empty())
			frame.text(W - disp_len(msg) - 2, H - 1, msg, status_col, pal::kBar);
	}

	// --- input -----------------------------------------------------------

	// MINE is not reachable until a pool has been chosen: there is nothing it
	// could do, and stopping on it makes the user work out why by themselves.
	bool focusable(int f) const { return f != F_MINE || cfg.chosen; }

	int step_focus(int from, int dir) const
	{
		int f = from;
		for (int i = 0; i < F_COUNT; ++i) {
			f = (f + dir + F_COUNT) % F_COUNT;
			if (focusable(f))
				return f;
		}
		return from;
	}

	void adjust(int dir)
	{
		if (focus == F_THREADS) {
			threads += dir;
			if (threads < 1) threads = 1;
			if (threads > sys.ncpu) threads = sys.ncpu;
			if (engine.active())
				engine.start(threads, lanes);
		} else if (focus == F_LANES) {
			int l = lanes;
			l = dir > 0 ? l * 2 : l / 2;
			if (l < 8) l = 8;
			if (l > 64) l = 64;
			if (l != lanes) {
				lanes = l;
				if (engine.active())
					engine.start(threads, lanes);
			}
		}
	}

	bool on_key(const Event &e)
	{
		if (screen == Screen::Setup) {
			std::string *v[2] = {&id_draft.address, &id_draft.rig};
			switch (e.key) {
			case Key::Up: field = (field + 1) % 2; break;
			case Key::Down:
			case Key::Tab: field = (field + 1) % 2; break;
			case Key::Enter: {
				// Saving nothing and returning to a dashboard that then says
				// "connecting" for ever is not a save. Stay here and say why.
				if (!id_draft.complete()) {
					form_err = "a payout address is required — this is where "
					           "the pool sends your rewards";
					break;
				}
				if (const char *bad = id_draft.shape()) {
					form_err = std::string("that does not look like a payout "
					                       "address: ") + bad;
					break;
				}
				const bool changed = cfg.id.address != id_draft.address ||
				                     cfg.id.rig != id_draft.rig;
				cfg.id = id_draft;
				form_err.clear();
				if (pending_pool >= 0 && pending_pool < (int)cfg.pools.size()) {
					cfg.selected = pending_pool;
					cfg.chosen = true;
				}
				pending_pool = -1;
				clamp_pools();
				save_settings(cfg);
				screen = Screen::Dashboard;
				note("saved");
				// The user string is fixed at authorize time, so an address
				// change that does not reconnect keeps paying the old one
				// while the panel shows the new one.
				if (changed && cfg.chosen) {
					stop_mining();
					connect_selected();
				}
				break;
			}
			case Key::Escape:
				// Leaving without an address is allowed, but it must not leave
				// a pool marked chosen with nothing behind it.
				form_err.clear();
				pending_pool = -1;
				if (!cfg.id.complete()) {
					cfg.chosen = false;
					client.stop();
					note("no payout address set — nothing will be mined", true);
				}
				screen = Screen::Dashboard;
				break;
			case Key::Backspace:
				form_err.clear();
				if (!v[field]->empty())
					v[field]->pop_back();
				break;
			case Key::Char:
				form_err.clear();
				if (e.ch >= 32 && e.ch < 127 && v[field]->size() < 64)
					v[field]->push_back(e.ch);
				break;
			case Key::Quit: return false;
			default: break;
			}
			return true;
		}

		if (screen == Screen::EditPool) {
			std::string *v[3] = {&draft.label, &draft.host, &draft.port};
			switch (e.key) {
			case Key::Up: field = (field + 2) % 3; break;
			case Key::Down:
			case Key::Tab: field = (field + 1) % 3; break;
			case Key::Enter: {
				if (draft.host.empty()) {
					form_err = "a host is required, e.g. na.luckpool.net";
					break;
				}
				const long port = strtol(draft.port.c_str(), nullptr, 10);
				if (draft.port.empty() || port < 1 || port > 65535 ||
				    draft.port.find_first_not_of("0123456789") != std::string::npos) {
					form_err = "the port must be a number from 1 to 65535";
					break;
				}
				if (draft.label.empty())
					draft.label = draft.host;
				draft.builtin = false;   // the user's value wins from here
				const bool live = cfg.chosen && !editing_new &&
				                  cfg.selected == pool_cursor;
				if (editing_new) {
					cfg.pools.push_back(draft);
					pool_cursor = (int)cfg.pools.size() - 1;
				} else if (pool_cursor < (int)cfg.pools.size()) {
					cfg.pools[(size_t)pool_cursor] = draft;
				}
				editing_new = false;
				form_err.clear();
				clamp_pools();
				save_settings(cfg);
				note("saved");
				screen = Screen::Pools;
				// An endpoint edited underneath a live connection has to be
				// retested, or the panel describes one pool and the socket
				// another.
				if (live) {
					stop_mining();
					connect_selected();
				}
				break;
			}
			case Key::Escape:
				// The cursor was never moved past the end, so there is nothing
				// to repair here -- which is the point.
				editing_new = false;
				form_err.clear();
				screen = Screen::Pools;
				break;
			case Key::Backspace:
				form_err.clear();
				if (!v[field]->empty())
					v[field]->pop_back();
				break;
			case Key::Char:
				form_err.clear();
				if (e.ch >= 32 && e.ch < 127 && v[field]->size() < 64)
					v[field]->push_back(e.ch);
				break;
			case Key::Quit: return false;
			default: break;
			}
			return true;
		}

		if (screen == Screen::Pools) {
			switch (e.key) {
			case Key::Up: if (pool_cursor > 0) --pool_cursor; break;
			case Key::Down:
				if (pool_cursor + 1 < (int)cfg.pools.size()) ++pool_cursor;
				break;
			case Key::Enter:
				// Selecting is the common case, so it is the plain key -- and
				// it tests the pool rather than leaving that to a second
				// button. By the time you are back on the dashboard the
				// status says whether the endpoint is any good.
				if (pool_cursor >= 0 && pool_cursor < (int)cfg.pools.size()) {
					// The address check comes first: marking a pool chosen and
					// then bouncing to setup is what left the dashboard saying
					// "connecting" with nothing behind it if setup was skipped.
					if (!cfg.id.complete()) {
						pending_pool = pool_cursor;
						id_draft = cfg.id;
						field = 0;
						form_err = "set your payout address first — the pool "
						           "needs somewhere to send rewards";
						screen = Screen::Setup;
						break;
					}
					stop_mining();
					cfg.selected = pool_cursor;
					cfg.chosen = true;
					save_settings(cfg);
					connect_selected();
					focus = F_MINE;   // the reason you came here
					screen = Screen::Dashboard;
				}
				break;
			case Key::Escape: screen = Screen::Dashboard; break;
			case Key::Char:
				if (e.ch == 'e' && pool_cursor >= 0 &&
				    pool_cursor < (int)cfg.pools.size()) {
					draft = cfg.pools[(size_t)pool_cursor];
					editing_new = false;
					field = 0;
					form_err.clear();
					screen = Screen::EditPool;
				} else if (e.ch == 'n') {
					draft = Pool();
					// The cursor stays on a row that exists. Parking it at
					// size() to mean "new" is what let Escape leave it out of
					// range for the next keystroke to read off the end.
					editing_new = true;
					field = 0;
					form_err.clear();
					screen = Screen::EditPool;
				} else if (e.ch == 'i') {
					id_draft = cfg.id;
					field = 0;
					form_err.clear();
					screen = Screen::Setup;
				} else if (e.ch == 'd') {
					if (cfg.pools.size() <= 1) {
						note("the last pool cannot be deleted — edit it instead",
						     true);
						break;
					}
					// Deleting the row a live connection belongs to used to
					// leave the label pointing at a different pool while the
					// socket stayed where it was.
					const bool was_live = cfg.chosen && cfg.selected == pool_cursor;
					cfg.pools.erase(cfg.pools.begin() + pool_cursor);
					if (was_live) {
						stop_mining();
						client.stop();
						cfg.chosen = false;
						note("deleted — that was the selected pool", true);
					} else {
						if (cfg.selected > pool_cursor)
							--cfg.selected;   // the live row moved up one
						note("deleted");
					}
					clamp_pools();
					save_settings(cfg);
				} else if (e.ch == 'q') {
					return false;
				}
				break;
			case Key::Quit: return false;
			default: break;
			}
			return true;
		}

		switch (e.key) {
		case Key::Up: focus = step_focus(focus, -1); break;
		case Key::Down:
		case Key::Tab: focus = step_focus(focus, +1); break;
		case Key::Left: adjust(-1); break;
		case Key::Right: adjust(+1); break;
		case Key::Enter:
			if (focus == F_MINE) {
				if (mode == Mode::Mining) {
					stop_mining();
					note("stopped");
				} else if (!pool_ready()) {
					// Say which of the several reasons it is, not just "no".
					const StatusLine s = pool_status();
					note(s.text, true);
				} else {
					peak = 0; avg_acc = 0; avg_n = 0;
					engine.set_pool(&client);
					engine.start(threads, lanes);
					kin.begin(now_s());
					mode = Mode::Mining;
					dust.begin(now_s());
					note("mining");
				}
			} else if (focus == F_BENCH) {
				if (mode == Mode::Benchmark) {
					engine.stop();
					mode = Mode::Idle;
					note("stopped");
				} else {
					peak = 0; avg_acc = 0; avg_n = 0;
					stop_mining();
					engine.set_pool(nullptr);
					engine.start(threads, lanes);
					mode = Mode::Benchmark;
					note("benchmarking");
				}
			} else if (focus == F_POOLS) {
				pool_cursor = cfg.selected;
				clamp_pools();
				screen = Screen::Pools;
			}
			break;
		case Key::Char:
			if (e.ch == 'q') return false;
			// The dashboard offered no route to the address it needs; the only
			// way in was through a screen the user had no reason to open.
			if (e.ch == 'i') {
				id_draft = cfg.id;
				field = 0;
				form_err.clear();
				screen = Screen::Setup;
			}
			break;
		case Key::Quit: return false;
		default: break;
		}
		return true;
	}

	int run()
	{
		if (!term.begin()) {
			fprintf(stderr, "vh22-top needs an interactive terminal\n");
			return 1;
		}
		init();
		bool go = true;
		double next = now_s();
		while (go) {
			const Event e = term.poll(60);
			if (e.key == Key::Quit)
				break;
			if (e.key != Key::None && e.key != Key::Resize)
				go = on_key(e);
			if (!go)
				break;

			if (now_s() >= next) {
				next = now_s() + 0.1;
				tick();
			}
			term.measure();
			frame.resize(term.width(), term.height());
			frame.clear();
			// The old floor of 60x16 was below what the dashboard can actually
			// draw: at 16 rows both panels' controls landed off the bottom of
			// the screen while focus still moved onto them.
			if (term.width() < kMinW || term.height() < kMinH) {
				char b[96];
				snprintf(b, sizeof(b), "terminal too small — need %dx%d, this is %dx%d",
				         kMinW, kMinH, term.width(), term.height());
				frame.text(1, 1, ellipsize(b, term.width() - 2), pal::kRed);
				if (term.height() > 3)
					frame.text(1, 3, ellipsize("resize the window, or press q",
					                           term.width() - 2), pal::kDim);
			} else if (screen == Screen::Dashboard) {
				draw_dashboard();
			} else if (screen == Screen::Pools) {
				draw_pools();
			} else if (screen == Screen::Setup) {
				draw_setup();
			} else {
				draw_edit();
			}
			term.present(frame.render());
		}
		engine.stop();
		client.stop();
		term.end();
		return 0;
	}
};

// Bumped by hand, and the release tag is expected to match it.
static const char *kVersion = "1.0.0";

static void usage(FILE *f)
{
	fprintf(f,
	        "vh22-top %s — VerusHash 2.2 miner for Apple silicon\n"
	        "\n"
	        "usage: vh22-top [--version] [--help]\n"
	        "\n"
	        "Takes no configuration on the command line: the payout address is\n"
	        "asked for once on first run, and pools are a list inside the UI.\n"
	        "\n"
	        "  ↑↓      move between controls\n"
	        "  ←→      adjust threads and lanes\n"
	        "  ⏎       select, or start and stop\n"
	        "  i       set the payout address\n"
	        "  q       quit\n"
	        "\n"
	        "  ~/.config/vh22/config   identity and pools, mode 0600\n"
	        "  $VH22_NEWS              ticker copy; also ~/.config/vh22/news.md\n"
	        "\n"
	        "Needs an interactive terminal, at least 60x19.\n",
	        kVersion);
}

int main(int argc, char **argv)
{
	for (int i = 1; i < argc; ++i) {
		const std::string a = argv[i];
		if (a == "--version" || a == "-V") {
			printf("vh22-top %s\n", kVersion);
			return 0;
		}
		if (a == "--help" || a == "-h") {
			usage(stdout);
			return 0;
		}
		fprintf(stderr, "vh22-top: unknown option %s\n\n", a.c_str());
		usage(stderr);
		return 2;
	}
	App app;
	return app.run();
}
