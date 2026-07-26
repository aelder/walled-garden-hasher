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
			stratum::Job j;
			if (!pool_->current(j) || !j.valid) {
				usleep(50000);
				continue;
			}
			if (j.serial != serial) {
				// New job: rebuild the per-template state. The 276 chained
				// Haraka256 of key expansion happen here, once, not per nonce.
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

// --- share accounting -----------------------------------------------------
//
// Populated by the stratum client. accepted/rejected come from the
// mining.submit response, stale from the pool rejecting a share whose job has
// moved on, difficulty from mining.set_target. None of it is observable
// locally, which is why it is all still zero.
struct ShareStats {
	bool connected = false;
	uint64_t accepted = 0, rejected = 0, stale = 0;
	double difficulty = 0;
	double last_share_s = -1;   // seconds since; negative means never
	double connected_since = 0;
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
	int pool_cursor = 0, field = 0;
	Pool draft;
	Identity id_draft;
	std::string status;

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
		if (!cfg.id.complete()) {
			id_draft = cfg.id;
			screen = Screen::Setup;
			field = 0;
		}
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
	void connect_selected()
	{
		client.stop();
		if (!cfg.chosen || !cfg.id.complete() || cfg.pools.empty())
			return;
		const Pool &p = cfg.pools[(size_t)cfg.selected];
		if (p.host.empty()) {
			status = "that pool has no host";
			return;
		}
		stratum::Config sc;
		sc.host = p.host;
		sc.port = p.port;
		sc.user = cfg.id.user();
		sc.pass = "x";
		client.start(sc);
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
				hist.erase(hist.begin());
				hist.push_back(rate);
				if (rate > peak)
					peak = rate;
				avg_acc += rate;
				++avg_n;
			}
		}
		load.sample(sys.ncpu);
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
		int ty = y + 1;
		const int bw = block_text_width(sys.model);
		if (h >= 8 && bw <= w - 6) {
			block_text(frame, x + 3, ty, sys.model, pal::kInk);
			ty += kBlockRows;
		} else {
			frame.text(x + 3, ty++, sys.model, pal::kInk, pal::kPanel, true);
		}

		char b[160];
		frame.text(x + 3, ty++, "VerusHash 2.2  ·  AArch64", pal::kLabel);
		snprintf(b, sizeof(b), "%d cores  ·  %dP + %dE  ·  %.0f GB", sys.ncpu, sys.nperf,
		         sys.neff, sys.mem_gb);
		frame.text(x + 3, ty++, b, pal::kLabel);
		if (h >= 6)
			rainbow_rule(frame, x + 2, y + h - 2, w - 4);
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
				const char g[2] = {row[c], 0};
				frame.put(ox + c, oy + r, g,
				          wet ? bright : lerp(pal::kPanel, pal::kChrome, 0.55));
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

		// Scale ticks, top and bottom.
		frame.text(x + 2, gy, mhs(vmax), pal::kDim);
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
		const char *what = mode == Mode::Mining     ? "● mining"
		                 : mode == Mode::Benchmark ? "● benchmark"
		                                           : "○ idle";
		rx = frame.text(rx + 3, ry, what,
		                mode == Mode::Idle ? pal::kDim : pal::kGreen);
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
		for (int i = 0; i < sys.ncpu; ++i) {
			// Centre the block between the title and the controls, so the
			// slack on a machine with few cores reads as symmetric padding
			// rather than a gap above the controls.
			const int cx = x + 3 + (i / per) * cw;
			const int cy = y + 2 + top_pad + (i % per);
			if (i % per >= rows)
				continue;
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
	void draw_run_label(int x, int y, bool pool_ready, bool mining, bool foc)
	{
		static const char *kReady = ">MINE<";
		static const char *kActive = "!MINING!";
		if (foc)
			frame.text(x - 2, y, "▸", mining || pool_ready ? pal::kGreen : pal::kDim);
		if (!pool_ready && !mining) {
			frame.text(x, y, "mine", pal::kDim);
			frame.text(x + 6, y,
			           cfg.chosen ? "(waiting for the pool)" : "(select a pool)",
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

	void stat(int x, int y, const std::string &k, const std::string &v, Rgb col)
	{
		frame.text(x, y, k, pal::kLabel);
		frame.text(x + 12, y, v, col);
	}

	void draw_pool_panel(int x, int y, int w, int h)
	{
		const bool foc_pools = (screen == Screen::Dashboard) && focus == F_POOLS;
		const bool foc_mine = (screen == Screen::Dashboard) && focus == F_MINE;
		const bool foc = foc_pools || foc_mine;
		window(frame, x, y, w, h, "Pool", foc, pal::kPurple);
		const int c = x + 3;
		const int btn = y + h - 3;
		int ty = y + 2;
		auto room = [&](int need) { return ty + need <= btn - 3; };

		if (!cfg.chosen || cfg.pools.empty()) {
			if (room(1)) frame.text(c, ty++, "no pool selected", pal::kDim);
			if (room(2)) { ++ty; frame.text(c, ty++, "choose one below", pal::kDim); }
		} else {
			const Pool &p = cfg.pools[(size_t)cfg.selected];
			if (room(1))
				frame.text(c, ty++, "● " + p.label, pal::kPurple, pal::kPanel, true);
			if (room(1))
				frame.text(c + 2, ty++, p.host + ":" + p.port, pal::kInk);
			if (room(1))
				frame.text(c + 2, ty++,
				           cfg.id.complete() ? cfg.id.shortened() : "(no wallet set)",
				           cfg.id.complete() ? pal::kLabel : pal::kRed);
		}

		const stratum::State st = client.state();
		const bool live = st != stratum::State::Disconnected;
		const bool on = st == stratum::State::Ready;
		auto &sx = client.stats();
		if (room(3)) {
			++ty;
			// "verified" is the useful word here: the pool answered, gave a
			// target and gave work, so it is known good before mining starts.
			// Anything else shows the client's own note -- "cannot resolve",
			// "connection refused", "reconnecting in 4s" -- because a status
			// that only says "not connected" leaves the user with nothing to
			// act on.
			const std::string note = client.status_text();
			std::string sline;
			if (!cfg.chosen)          sline = "no pool selected";
			else if (mode == Mode::Mining) sline = "mining";
			else if (on)              sline = "verified";
			else if (!note.empty())   sline = note;
			else                      sline = "connecting";
			stat(c, ty++, "status", (on ? "● " : (live ? "◐ " : "○ ")) + sline,
			     on ? pal::kGreen
			        : (st == stratum::State::Failed ? pal::kRed : pal::kDim));
			const double d = sx.difficulty.load();
			stat(c, ty++, "difficulty", d > 0 ? std::to_string((long)d) : "—",
			     d > 0 ? pal::kInk : pal::kDim);
		}

		const int col2 = c + (w - 6) / 2;
		if (room(3)) {
			++ty;
			stat(c, ty, "accepted", std::to_string(sx.accepted.load()),
			     sx.accepted.load() ? pal::kGreen : pal::kDim);
			stat(col2, ty++, "stale", std::to_string(sx.stale.load()),
			     sx.stale.load() ? pal::kYellow : pal::kDim);
			stat(c, ty, "rejected", std::to_string(sx.rejected.load()),
			     sx.rejected.load() ? pal::kRed : pal::kDim);
			const double ls = sx.last_share_time.load();
			char age[32] = "—";
			if (ls > 0)
				snprintf(age, sizeof(age), "%.0fs ago", now_wall() - ls);
			stat(col2, ty++, "last", age, ls > 0 ? pal::kInk : pal::kDim);
		}

		const int bx = x + 2, bw = w - 4;
		const int ix = bx + 3;
		const int mine_row = btn - 2;
		const bool verified = st == stratum::State::Ready;
		draw_run_label(ix, mine_row, verified, mode == Mode::Mining, foc_mine);
		if (foc_mine)
			focus_box(bx, mine_row, bw,
			          mode == Mode::Mining || verified ? pal::kGreen : pal::kDim);
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
		// identity, status, the share grid and its note.
		const int cores_need = (sys.ncpu + 1) / 2 + 10;
		const int pool_need = 15;
		int bot = cores_need > pool_need ? cores_need : pool_need;
		// Reserve a readable graph rather than splitting the remainder evenly:
		// the bottom panels have a fixed content budget, the graph just wants
		// whatever is left.
		const int bot_max = (H - y) - 9;
		if (bot > bot_max) bot = bot_max;
		if (bot < 10) bot = 10;
		const int gh = H - y - bot - 1;
		draw_graph(0, y, W, gh > 5 ? gh : 5);
		y += (gh > 5 ? gh : 5);
		const int lw = W / 2;
		draw_cores(0, y, lw, bot);
		draw_pool_panel(lw, y, W - lw, bot);
		help(" ↑↓ move   ←→ adjust   ⏎ select   q quit ");
	}

	// Pick a pool. That is the whole screen: the wallet is already known, so
	// selecting costs one keystroke and nothing has to be retyped.
	void draw_pools()
	{
		const int W = frame.width(), H = frame.height();
		window(frame, 0, 0, W, H - 1, "Pools", true, pal::kPurple);

		int ty = 2;
		frame.text(4, ty++, "mining as", pal::kLabel);
		frame.text(15, ty - 1, cfg.id.complete() ? cfg.id.user() : "(not set — press i)",
		           cfg.id.complete() ? pal::kInk : pal::kRed, pal::kPanel, true);
		++ty;

		for (size_t i = 0; i < cfg.pools.size(); ++i) {
			const bool cur = (int)i == pool_cursor;
			const bool sel = (int)i == cfg.selected;
			if (cur) {
				frame.text(2, ty, "▸", pal::kYellow);
				focus_box(3, ty, W - 6, pal::kYellow);
			}
			frame.text(6, ty, sel ? "●" : "○", sel ? pal::kPurple : pal::kDim);
			frame.text(8, ty, cfg.pools[i].label, cur ? pal::kInk : pal::kLabel,
			           pal::kPanel, cur);
			frame.text(30, ty, cfg.pools[i].host + ":" + cfg.pools[i].port,
			           cur ? pal::kPurple : pal::kDim);
			ty += 2;
		}

		frame.text(4, H - 4, "the endpoint is editable — press e if a pool has moved",
		           pal::kDim);
		help(" ↑↓ move   ⏎ select   e edit   n new   d delete   i identity   esc back ");
	}

	void draw_edit()
	{
		const int W = frame.width(), H = frame.height();
		window(frame, 0, 0, W, H - 1, "Edit pool", true, pal::kPurple);
		const char *names[3] = {"name", "host", "port"};
		std::string *vals[3] = {&draft.label, &draft.host, &draft.port};
		int ty = 3;
		for (int i = 0; i < 3; ++i) {
			const bool foc = i == field;
			if (foc)
				focus_box(3, ty, W - 6, pal::kYellow);
			frame.text(6, ty, names[i], foc ? pal::kInk : pal::kLabel, pal::kPanel, foc);
			const std::string v = *vals[i] + (foc ? "▌" : "");
			frame.text(20, ty, v.empty() ? "—" : v, foc ? pal::kYellow : pal::kInk);
			ty += 2;
		}
		frame.text(6, H - 4, "the wallet is set once under identity, not per pool",
		           pal::kDim);
		help(" ↑↓ field   type to edit   ⏎ save   esc cancel ");
	}

	// Asked once, on first run. Everything else can be picked from a list.
	void draw_setup()
	{
		const int W = frame.width(), H = frame.height();
		window(frame, 0, 0, W, H - 1, "Welcome", true, pal::kGreen);

		int ty = 3;
		if (block_text_width("VH22") <= W - 8) {
			block_text(frame, 6, ty, "VH22", pal::kInk);
			ty += kBlockRows + 1;
		}
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
			frame.text(26, ty, v.empty() ? "—" : v, foc ? pal::kYellow : pal::kInk);
			// Below the ring, not on it: the ring occupies ty +/- 1.
			frame.text(8, ty + 2, hints[i], pal::kDim);
			ty += 4;
		}
		frame.text(6, H - 4,
		           "stored in ~/.config/vh22/config — no wallet, no private key, just "
		           "the payout address",
		           pal::kDim);
		help(" ↑↓ field   type to enter   ⏎ save   esc skip for now ");
	}

	void help(const std::string &s)
	{
		const int H = frame.height();
		frame.hline(0, H - 1, frame.width(), " ", pal::kLabel, pal::kBar);
		frame.text(1, H - 1, s, pal::kLabel, pal::kBar);
		if (!status.empty())
			frame.text(frame.width() - (int)status.size() - 2, H - 1, status,
			           pal::kGreen, pal::kBar);
	}

	// --- input -----------------------------------------------------------

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
			case Key::Enter:
				cfg.id = id_draft;
				save_settings(cfg);
				screen = Screen::Dashboard;
				status = cfg.id.complete() ? "saved" : "";
				break;
			case Key::Escape: screen = Screen::Dashboard; break;
			case Key::Backspace:
				if (!v[field]->empty())
					v[field]->pop_back();
				break;
			case Key::Char:
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
			case Key::Enter:
				draft.builtin = false;   // the user's value wins from here
				if (pool_cursor >= (int)cfg.pools.size())
					cfg.pools.push_back(draft);
				else
					cfg.pools[(size_t)pool_cursor] = draft;
				save_settings(cfg);
				status = "saved";
				screen = Screen::Pools;
				break;
			case Key::Escape: screen = Screen::Pools; break;
			case Key::Backspace:
				if (!v[field]->empty())
					v[field]->pop_back();
				break;
			case Key::Char:
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
				if (!cfg.pools.empty()) {
					cfg.selected = pool_cursor;
					cfg.chosen = true;
					save_settings(cfg);
					if (mode == Mode::Mining) {
						engine.stop();
						engine.set_pool(nullptr);
						mode = Mode::Idle;
					}
					if (!cfg.id.complete()) {
						id_draft = cfg.id;
						field = 0;
						screen = Screen::Setup;
						status = "set your address first";
						break;
					}
					connect_selected();
					status = "connecting";
					screen = Screen::Dashboard;
				}
				break;
			case Key::Escape: screen = Screen::Dashboard; break;
			case Key::Char:
				if (e.ch == 'e' && !cfg.pools.empty()) {
					draft = cfg.pools[(size_t)pool_cursor];
					field = 0;
					screen = Screen::EditPool;
				} else if (e.ch == 'n') {
					draft = Pool();
					pool_cursor = (int)cfg.pools.size();
					field = 0;
					screen = Screen::EditPool;
				} else if (e.ch == 'i') {
					id_draft = cfg.id;
					field = 0;
					screen = Screen::Setup;
				} else if (e.ch == 'd' && cfg.pools.size() > 1) {
					cfg.pools.erase(cfg.pools.begin() + pool_cursor);
					if (pool_cursor >= (int)cfg.pools.size() && pool_cursor)
						--pool_cursor;
					if (cfg.selected >= (int)cfg.pools.size())
						cfg.selected = 0;
					save_settings(cfg);
					status = "deleted";
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
		case Key::Up: focus = (focus + F_COUNT - 1) % F_COUNT; break;
		case Key::Down:
		case Key::Tab: focus = (focus + 1) % F_COUNT; break;
		case Key::Left: adjust(-1); break;
		case Key::Right: adjust(+1); break;
		case Key::Enter:
			if (focus == F_MINE) {
				if (mode == Mode::Mining) {
					engine.stop();
					engine.set_pool(nullptr);
					mode = Mode::Idle;
					status = "stopped";
				} else if (client.state() != stratum::State::Ready) {
					status = "pool not verified yet";
				} else {
					peak = 0; avg_acc = 0; avg_n = 0;
					engine.set_pool(&client);
					engine.start(threads, lanes);
					kin.begin(now_s());
					mode = Mode::Mining;
					dust.begin(now_s());
					status = "mining";
				}
			} else if (focus == F_BENCH) {
				if (mode == Mode::Benchmark) {
					engine.stop();
					mode = Mode::Idle;
					status = "stopped";
				} else {
					peak = 0; avg_acc = 0; avg_n = 0;
					engine.set_pool(nullptr);
					engine.start(threads, lanes);
					mode = Mode::Benchmark;
					status = "benchmarking";
				}
			} else if (focus == F_POOLS) {
				pool_cursor = cfg.selected;
				screen = Screen::Pools;
			}
			break;
		case Key::Char:
			if (e.ch == 'q') return false;
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
			if (term.width() < 60 || term.height() < 16) {
				frame.text(1, 1, "terminal too small — 60x16 minimum", pal::kRed);
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

int main()
{
	App app;
	return app.run();
}
