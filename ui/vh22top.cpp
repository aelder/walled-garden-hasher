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

// --- pool configuration ---------------------------------------------------

struct Pool {
	std::string label = "";
	std::string host = "";
	std::string port = "3956";
	std::string user = "";
	std::string pass = "x";
};

static std::string config_dir()
{
	const char *home = getenv("HOME");
	return std::string(home ? home : ".") + "/.config/vh22";
}
static std::string config_path() { return config_dir() + "/pools.conf"; }

static std::vector<Pool> load_pools(int *selected)
{
	std::vector<Pool> v;
	*selected = 0;
	FILE *f = fopen(config_path().c_str(), "r");
	if (!f)
		return v;
	char line[512];
	while (fgets(line, sizeof(line), f)) {
		std::string s(line);
		while (!s.empty() && (s.back() == '\n' || s.back() == '\r'))
			s.pop_back();
		const size_t eq = s.find('=');
		if (eq == std::string::npos)
			continue;
		const std::string k = s.substr(0, eq), val = s.substr(eq + 1);
		if (k == "selected") { *selected = atoi(val.c_str()); continue; }
		if (k == "pool") { v.push_back(Pool()); v.back().label = val; continue; }
		if (v.empty())
			continue;
		if (k == "host") v.back().host = val;
		else if (k == "port") v.back().port = val;
		else if (k == "user") v.back().user = val;
		else if (k == "pass") v.back().pass = val;
	}
	fclose(f);
	if (*selected >= (int)v.size())
		*selected = 0;
	return v;
}

static bool save_pools(const std::vector<Pool> &v, int selected)
{
	mkdir(config_dir().c_str(), 0700);
	FILE *f = fopen(config_path().c_str(), "w");
	if (!f)
		return false;
	fprintf(f, "# vh22 pool configuration\nselected=%d\n", selected);
	for (const auto &p : v)
		fprintf(f, "pool=%s\nhost=%s\nport=%s\nuser=%s\npass=%s\n", p.label.c_str(),
		        p.host.c_str(), p.port.c_str(), p.user.c_str(), p.pass.c_str());
	fclose(f);
	chmod(config_path().c_str(), 0600);  // it holds worker credentials
	return true;
}

// --- app ------------------------------------------------------------------

static const std::string kLogoRows[7] = {
	"       .:'   ",
	"    _ :'_    ",
	" .'`_`-'_``. ",
	":________.-' ",
	":_______:    ",
	" :_______`-; ",
	"  `._.-._.'  ",
};

static const char *kLogo[7] = {
	"       .:'",
	"    _ :'_",
	" .'`_`-'_``.",
	":________.-'",
	":_______:",
	" :_______`-;",
	"  `._.-._.'",
};

enum class Screen { Dashboard, Pools, EditPool };
enum Focus { F_THREADS = 0, F_LANES, F_RUN, F_CONNECT, F_POOLS, F_COUNT };

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
	std::vector<Pool> pools;
	int pool_sel = 0, pool_cursor = 0, field = 0;
	Pool draft;
	std::string status;

	void init()
	{
		sys.probe();
		threads = sys.ncpu;
		pools = load_pools(&pool_sel);
		hist.assign(400, 0.0);
		uint8_t header[1487];
		for (size_t i = 0; i < sizeof(header); ++i)
			header[i] = (uint8_t)(i * 31 + 7);
		engine.configure(header, sizeof(header));
		last_t = now_s();
		load.sample(sys.ncpu);
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
		window(frame, x, y, w, h, "vh22", false, pal::kChrome);
		const bool room = h >= 9;
		int tx = x + 3;
		if (room) {
			for (int i = 0; i < 7 && i + 2 < h; ++i)
				frame.text(x + 3, y + 1 + i, kLogo[i], pal::kRainbow[i == 0 ? 0 : i - 1]);
			tx = x + 20;
		}
		int ty = y + 2;
		frame.text(tx, ty++, "VerusHash 2.2", pal::kInk, pal::kPanel, true);
		frame.text(tx, ty++, "native AArch64 · no sse2neon", pal::kLabel);
		++ty;
		char b[160];
		snprintf(b, sizeof(b), "%s", sys.model.c_str());
		frame.text(tx, ty++, b, pal::kInk);
		snprintf(b, sizeof(b), "%d cores  ·  %dP + %dE  ·  %.0f GB", sys.ncpu, sys.nperf,
		         sys.neff, sys.mem_gb);
		frame.text(tx, ty++, b, pal::kLabel);
		if (h >= 9)
			rainbow_rule(frame, x + 2, y + h - 2, w - 4);
	}

	// The logo stands in the plot rather than under it: its glyphs occlude the
	// braille, its negative space lets the stream through, and whatever the
	// waterline has reached lights up in that row's fastfetch stripe colour.
	// Rock in a stream.
	void draw_watermark(int gx, int gy, int gw, int gh, const std::vector<int> &fill,
	                    std::vector<uint8_t> &occlude)
	{
		const int lw = 13, lh = 7;
		if (gw < lw + 4 || gh < lh)
			return;
		const int ox = gx + (gw - lw) / 2;
		const int oy = gy + (gh - lh) / 2;
		const int dots_h = gh * 4;

		for (int r = 0; r < lh; ++r) {
			const std::string &row = kLogoRows[r];
			// fastfetch stripe order: the crown shares green, then the six
			// bands run down the body.
			const Rgb bright = pal::kRainbow[r == 0 ? 0 : (r - 1 < 6 ? r - 1 : 5)];
			for (int c = 0; c < (int)row.size(); ++c) {
				if (row[c] == ' ')
					continue;   // water flows through the gaps
				const int cx = ox + c - gx, cy = oy + r - gy;
				if (cx < 0 || cx >= gw || cy < 0 || cy >= gh)
					continue;
				occlude[(size_t)cy * (size_t)gw + (size_t)cx] = 1;

				// Submerged when the fill at this column reaches into this
				// cell's four dot rows.
				const int top_dot = dots_h - fill[(size_t)cx];
				const bool wet = top_dot <= cy * 4 + 3;
				const char g[2] = {row[c], 0};
				frame.put(ox + c, oy + r, g,
				          wet ? bright : lerp(pal::kPanel, pal::kChrome, 0.55));
			}
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
		std::vector<uint8_t> occlude((size_t)gw * (size_t)gh, 0);
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
		rx = frame.text(rx + 3, ry, engine.active() ? "● running" : "○ idle",
		                engine.active() ? pal::kGreen : pal::kDim);
	}

	void draw_cores(int x, int y, int w, int h)
	{
		const bool foc = (screen == Screen::Dashboard) &&
		                 (focus == F_THREADS || focus == F_LANES || focus == F_RUN);
		window(frame, x, y, w, h, "Cores", foc, pal::kBlue);

		// Two cores per line, each a braille trace of its own recent load --
		// the same plotting language as the hashrate graph, which solid bars
		// were not. Colour ramps within the cluster's family so P and E stay
		// distinguishable while magnitude reads off the ramp.
		const int rows = h - 6;
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

		const int half = (w - 6) / 2;
		int cy = y + h - 3;              // leaves a blank row above the footer
		draw_spin(x + 3, cy, half, "threads", std::to_string(threads), focus == F_THREADS);
		draw_spin(x + 3 + half, cy, half, "lanes", std::to_string(lanes),
		          focus == F_LANES);
		++cy;
		const bool on = engine.active();
		const bool mining = client.state() == stratum::State::Ready;
		draw_button(x + 3, cy, w - 6,
		            on ? "Stop" : (mining ? "Start mining" : "Start benchmark"),
		            focus == F_RUN, on ? pal::kRed : pal::kGreen);
		frame.text(x + w - 27, cy, "no core pinning on macOS", pal::kDim);
	}

	void draw_spin(int x, int y, int w, const std::string &label, const std::string &val,
	               bool foc)
	{
		const Rgb fg = foc ? pal::kInk : pal::kLabel;
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
		const std::string s = (foc ? "▸ " : "  ") + label;
		(void)w;
		frame.text(x, y, s, foc ? col : pal::kLabel, pal::kPanel, foc);
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
		const bool foc_connect = (screen == Screen::Dashboard) && focus == F_CONNECT;
		const bool foc = foc_pools || foc_connect;
		window(frame, x, y, w, h, "Pool", foc, pal::kPurple);
		const int c = x + 3;
		const int btn = y + h - 2;          // the button owns this row
		int ty = y + 2;                     // blank row under the title
		// Every row is guarded: this panel shares its height with the cores
		// panel beside it, so on a short terminal the lower blocks drop
		// rather than overprinting the button.
		auto room = [&](int need) { return ty + need <= btn - 1; };

		if (pools.empty()) {
			if (room(1)) frame.text(c, ty++, "no pool configured", pal::kDim);
			if (room(2)) { ++ty; frame.text(c, ty++, "add one below", pal::kDim); }
		} else {
			const Pool &p = pools[(size_t)pool_sel];
			if (room(1))
				frame.text(c, ty++, "● " + (p.label.empty() ? "(unnamed)" : p.label),
				           pal::kPurple, pal::kPanel, true);
			if (room(1))
				frame.text(c + 2, ty++,
				           p.host.empty() ? "(no host)" : p.host + ":" + p.port,
				           pal::kInk);
			if (room(1))
				frame.text(c + 2, ty++, p.user.empty() ? "(no worker)" : p.user,
				           pal::kLabel);
		}

		const stratum::State st = client.state();
		const bool live = st != stratum::State::Disconnected;
		const bool on = st == stratum::State::Ready;
		auto &sx = client.stats();
		if (room(3)) {
			++ty;
			std::string sline = live ? client.status_text() : "not connected";
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

		const int connect_row = btn - 1;
		draw_button(c, connect_row, w - 6, live ? "Disconnect" : "Connect",
		            foc_connect, live ? pal::kRed : pal::kGreen);
		draw_button(c, btn, w - 6, "Edit pools…", foc_pools, pal::kPurple);
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
		const int cores_need = (sys.ncpu + 1) / 2 + 7;
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

	void draw_pools()
	{
		const int W = frame.width(), H = frame.height();
		window(frame, 0, 0, W, H - 1, "Pools", true, pal::kPurple);
		int ty = 2;
		frame.text(3, ty++, "saved pools", pal::kLabel);
		if (pools.empty())
			frame.text(5, ty++, "none yet — press n to add one", pal::kDim);
		for (size_t i = 0; i < pools.size(); ++i) {
			const bool cur = (int)i == pool_cursor;
			const bool sel = (int)i == pool_sel;
			std::string s = (cur ? "▸ " : "  ");
			s += (sel ? "● " : "○ ");
			s += pools[i].label.empty() ? "(unnamed)" : pools[i].label;
			frame.text(3, ty, s, cur ? pal::kInk : pal::kLabel, pal::kPanel, cur);
			frame.text(34, ty, pools[i].host + ":" + pools[i].port,
			           cur ? pal::kPurple : pal::kDim);
			++ty;
		}
		frame.text(3, H - 4, "⏎ edit   space select   n new   d delete   esc back",
		           pal::kDim);
		help(" ↑↓ move   ⏎ edit   space select   n new   d delete   esc back ");
	}

	void draw_edit()
	{
		const int W = frame.width(), H = frame.height();
		window(frame, 0, 0, W, H - 1, "Edit pool", true, pal::kPurple);
		const char *names[5] = {"label", "host", "port", "worker", "password"};
		std::string *vals[5] = {&draft.label, &draft.host, &draft.port, &draft.user,
		                        &draft.pass};
		int ty = 3;
		for (int i = 0; i < 5; ++i) {
			const bool foc = i == field;
			frame.text(5, ty, names[i], foc ? pal::kInk : pal::kLabel, pal::kPanel, foc);
			const std::string v = *vals[i] + (foc ? "▌" : "");
			frame.text(18, ty, v.empty() ? "—" : v, foc ? pal::kYellow : pal::kInk);
			ty += 2;
		}
		frame.text(5, H - 5, "credentials are stored in ~/.config/vh22/pools.conf (0600)",
		           pal::kDim);
		help(" ↑↓ field   type to edit   ⏎ save   esc cancel ");
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
		if (screen == Screen::EditPool) {
			switch (e.key) {
			case Key::Up: field = (field + 4) % 5; break;
			case Key::Down: field = (field + 1) % 5; break;
			case Key::Enter:
				if (pool_cursor >= (int)pools.size())
					pools.push_back(draft);
				else
					pools[(size_t)pool_cursor] = draft;
				save_pools(pools, pool_sel);
				status = "saved";
				screen = Screen::Pools;
				break;
			case Key::Escape: screen = Screen::Pools; break;
			case Key::Backspace: {
				std::string *v[5] = {&draft.label, &draft.host, &draft.port,
				                     &draft.user, &draft.pass};
				if (!v[field]->empty())
					v[field]->pop_back();
				break;
			}
			case Key::Char: {
				std::string *v[5] = {&draft.label, &draft.host, &draft.port,
				                     &draft.user, &draft.pass};
				if (e.ch >= 32 && e.ch < 127 && v[field]->size() < 64)
					v[field]->push_back(e.ch);
				break;
			}
			case Key::Quit: return false;
			default: break;
			}
			return true;
		}

		if (screen == Screen::Pools) {
			switch (e.key) {
			case Key::Up: if (pool_cursor > 0) --pool_cursor; break;
			case Key::Down:
				if (pool_cursor + 1 < (int)pools.size()) ++pool_cursor;
				break;
			case Key::Enter:
				if (!pools.empty()) {
					draft = pools[(size_t)pool_cursor];
					field = 0;
					screen = Screen::EditPool;
				}
				break;
			case Key::Escape: screen = Screen::Dashboard; break;
			case Key::Char:
				if (e.ch == 'n') {
					draft = Pool();
					pool_cursor = (int)pools.size();
					field = 0;
					screen = Screen::EditPool;
				} else if (e.ch == 'd' && !pools.empty()) {
					pools.erase(pools.begin() + pool_cursor);
					if (pool_cursor >= (int)pools.size() && pool_cursor)
						--pool_cursor;
					if (pool_sel >= (int)pools.size())
						pool_sel = 0;
					save_pools(pools, pool_sel);
					status = "deleted";
				} else if (e.ch == ' ' && !pools.empty()) {
					pool_sel = pool_cursor;
					save_pools(pools, pool_sel);
					status = "selected";
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
			if (focus == F_RUN) {
				if (engine.active()) {
					engine.stop();
					status = "stopped";
				} else {
					peak = 0; avg_acc = 0; avg_n = 0;
					engine.start(threads, lanes);
					status = "running";
				}
			} else if (focus == F_CONNECT) {
				if (client.state() != stratum::State::Disconnected) {
					client.stop();
					engine.set_pool(nullptr);
					if (engine.active())
						engine.start(threads, lanes);
					status = "disconnected";
				} else if (!pools.empty() &&
				           !pools[(size_t)pool_sel].host.empty()) {
					const Pool &p = pools[(size_t)pool_sel];
					stratum::Config cfg;
					cfg.host = p.host;
					cfg.port = p.port;
					cfg.user = p.user;
					cfg.pass = p.pass;
					client.start(cfg);
					engine.set_pool(&client);
					if (engine.active())
						engine.start(threads, lanes);
					status = "connecting";
				} else {
					status = "set a host first";
				}
			} else if (focus == F_POOLS) {
				pool_cursor = pool_sel;
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
