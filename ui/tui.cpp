#include "tui.h"

#include <ctype.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <termios.h>
#include <unistd.h>

namespace vh22 {
namespace tui {

// --- frame ----------------------------------------------------------------

void Frame::resize(int w, int h)
{
	w_ = w < 1 ? 1 : w;
	h_ = h < 1 ? 1 : h;
	cells_.assign((size_t)w_ * (size_t)h_, Cell{});
}

void Frame::clear(Rgb bg)
{
	Cell blank;
	blank.bg = bg;
	for (auto &c : cells_)
		c = blank;
}

void Frame::put(int x, int y, const char *utf8, Rgb fg, Rgb bg, bool bold)
{
	if (x < 0 || y < 0 || x >= w_ || y >= h_)
		return;
	Cell &c = cells_[(size_t)y * (size_t)w_ + (size_t)x];
	size_t n = strlen(utf8);
	if (n > 4)
		n = 4;
	memcpy(c.ch, utf8, n);
	c.ch[n] = 0;
	c.fg = fg;
	c.bg = bg;
	c.bold = bold;
}

// Walks UTF-8 by codepoint so box-drawing and braille count as one column.
int Frame::text(int x, int y, const std::string &s, Rgb fg, Rgb bg, bool bold)
{
	int col = x;
	size_t i = 0;
	while (i < s.size()) {
		const unsigned char b = (unsigned char)s[i];
		size_t len = 1;
		if ((b & 0xE0) == 0xC0) len = 2;
		else if ((b & 0xF0) == 0xE0) len = 3;
		else if ((b & 0xF8) == 0xF0) len = 4;
		if (i + len > s.size())
			len = 1;
		char g[5] = {0};
		memcpy(g, s.data() + i, len);
		put(col, y, g, fg, bg, bold);
		++col;
		i += len;
	}
	return col;
}

void Frame::fill(int x, int y, int w, int h, const char *utf8, Rgb fg, Rgb bg)
{
	for (int j = 0; j < h; ++j)
		for (int i = 0; i < w; ++i)
			put(x + i, y + j, utf8, fg, bg);
}

void Frame::hline(int x, int y, int w, const char *utf8, Rgb fg, Rgb bg)
{
	for (int i = 0; i < w; ++i)
		put(x + i, y, utf8, fg, bg);
}

std::string Frame::render() const
{
	std::string out;
	out.reserve((size_t)w_ * (size_t)h_ * 12);
	out += "\x1b[H";
	Rgb fg = {0, 0, 0}, bg = {0, 0, 0};
	bool bold = false, first = true;
	char buf[64];

	for (int y = 0; y < h_; ++y) {
		snprintf(buf, sizeof(buf), "\x1b[%d;1H", y + 1);
		out += buf;
		for (int x = 0; x < w_; ++x) {
			const Cell &c = cells_[(size_t)y * (size_t)w_ + (size_t)x];
			if (first || c.fg.r != fg.r || c.fg.g != fg.g || c.fg.b != fg.b) {
				snprintf(buf, sizeof(buf), "\x1b[38;2;%u;%u;%um", c.fg.r, c.fg.g,
				         c.fg.b);
				out += buf;
				fg = c.fg;
			}
			if (first || c.bg.r != bg.r || c.bg.g != bg.g || c.bg.b != bg.b) {
				snprintf(buf, sizeof(buf), "\x1b[48;2;%u;%u;%um", c.bg.r, c.bg.g,
				         c.bg.b);
				out += buf;
				bg = c.bg;
			}
			if (first || c.bold != bold) {
				out += c.bold ? "\x1b[1m" : "\x1b[22m";
				bold = c.bold;
			}
			first = false;
			out += c.ch;
		}
	}
	out += "\x1b[0m";
	return out;
}

// --- chrome ---------------------------------------------------------------

void window(Frame &f, int x, int y, int w, int h, const std::string &title, bool focused,
            Rgb accent)
{
	if (w < 4 || h < 2)
		return;
	const Rgb line = focused ? accent : pal::kChrome;

	f.put(x, y, "╭", line);
	f.put(x + w - 1, y, "╮", line);
	f.put(x, y + h - 1, "╰", line);
	f.put(x + w - 1, y + h - 1, "╯", line);
	f.hline(x + 1, y + h - 1, w - 2, "─", line);
	for (int j = 1; j < h - 1; ++j) {
		f.put(x, y + j, "│", line);
		f.put(x + w - 1, y + j, "│", line);
	}

	// Title bar. A Platinum window signalled activation with pinstripes and a
	// close box; an inactive one went blank. Blank reads as broken on a
	// window that can never take focus, so the rule always draws and the
	// close box plus the accent-coloured border carry the focus signal.
	f.hline(x + 1, y, w - 2, "─", line);
	if (focused)
		f.text(x + 2, y, "▢", pal::kInk);
	const std::string t = " " + title + " ";
	int tx = x + (w - disp_len(t)) / 2;
	if (tx < x + 5)
		tx = x + 5;
	f.text(tx, y, t, focused ? pal::kInk : pal::kLabel, pal::kPanel, focused);
}

void rainbow_rule(Frame &f, int x, int y, int w)
{
	for (int i = 0; i < w; ++i) {
		const int band = (i * 6) / (w > 0 ? w : 1);
		f.put(x + i, y, "━", pal::kRainbow[band < 6 ? band : 5]);
	}
}

// --- braille plot ---------------------------------------------------------

// Dot bit layout within a braille cell:  col0 rows0-3 -> 0x01 0x02 0x04 0x40
//                                        col1 rows0-3 -> 0x08 0x10 0x20 0x80
static const uint8_t kDot[2][4] = {{0x01, 0x02, 0x04, 0x40}, {0x08, 0x10, 0x20, 0x80}};

static void encode_braille(uint8_t mask, char out[5])
{
	const unsigned cp = 0x2800u + mask;
	out[0] = (char)(0xE0 | (cp >> 12));
	out[1] = (char)(0x80 | ((cp >> 6) & 0x3F));
	out[2] = (char)(0x80 | (cp & 0x3F));
	out[3] = 0;
}

std::vector<int> plot_fill_dots(int w, int h, const std::vector<double> &series,
                                double vmax)
{
	std::vector<int> fill((size_t)(w > 0 ? w : 0), 0);
	if (w <= 0 || h <= 0)
		return fill;
	if (vmax <= 0)
		vmax = 1;
	const int dots_w = w * 2, dots_h = h * 4;
	const int n = (int)series.size();
	for (int dx = 0; dx < dots_w; ++dx) {
		const int idx = n - dots_w + dx;
		if (idx < 0 || idx >= n)
			continue;
		double v = series[(size_t)idx] / vmax;
		if (v < 0) v = 0;
		if (v > 1) v = 1;
		int filled = (int)(v * dots_h + 0.5);
		if (filled <= 0 && series[(size_t)idx] > 0)
			filled = 1;
		// A cell column spans two dot columns; the taller wins, so a glyph
		// standing there is submerged if either half of it is.
		const int cx = dx / 2;
		if (filled > fill[(size_t)cx])
			fill[(size_t)cx] = filled;
	}
	return fill;
}

void braille_plot(Frame &f, int x, int y, int w, int h, const std::vector<double> &series,
                  double vmax, const PlotMask *occlude)
{
	if (w <= 0 || h <= 0)
		return;
	const int dots_w = w * 2;
	const int dots_h = h * 4;
	if (vmax <= 0)
		vmax = 1;

	std::vector<uint8_t> mask((size_t)w * (size_t)h, 0);

	// Right-aligned: the newest sample sits at the right edge and history
	// scrolls off the left, which is what a rate graph should do.
	const int n = (int)series.size();
	for (int dx = 0; dx < dots_w; ++dx) {
		const int idx = n - dots_w + dx;
		if (idx < 0 || idx >= n)
			continue;
		double v = series[(size_t)idx] / vmax;
		if (v < 0) v = 0;
		if (v > 1) v = 1;
		int filled = (int)(v * dots_h + 0.5);
		if (filled <= 0 && series[(size_t)idx] > 0)
			filled = 1;
		for (int k = 0; k < filled; ++k) {
			const int dy = dots_h - 1 - k;
			const int cx = dx / 2, cy = dy / 4;
			mask[(size_t)cy * (size_t)w + (size_t)cx] |= kDot[dx % 2][dy % 4];
		}
	}

	for (int cy = 0; cy < h; ++cy) {
		// Colour by height through the logo, green at the top.
		const int band = (cy * 6) / h;
		const Rgb col = pal::kRainbow[band < 6 ? band : 5];
		for (int cx = 0; cx < w; ++cx) {
			const size_t at = (size_t)cy * (size_t)w + (size_t)cx;
			const bool have = occlude && at < occlude->hide.size();
			const uint8_t hide = have ? occlude->hide[at] : 0;
			const uint8_t fade = have ? occlude->fade[at] : 0;
			const uint8_t m = (uint8_t)(mask[at] & ~hide);
			if (!m)
				continue;
			char g[5];
			encode_braille(m, g);
			// Thinning alone still reads as a step; thinning plus a fade
			// reads as a shore.
			f.put(x + cx, y + cy, g,
			      fade ? lerp(col, pal::kPanel, (double)fade / 255.0) : col);
		}
	}
}

int disp_len(const std::string &s)
{
	int n = 0;
	for (size_t i = 0; i < s.size();) {
		const unsigned char b = (unsigned char)s[i];
		size_t len = 1;
		if ((b & 0xE0) == 0xC0) len = 2;
		else if ((b & 0xF0) == 0xE0) len = 3;
		else if ((b & 0xF8) == 0xF0) len = 4;
		i += len;
		++n;
	}
	return n;
}

Rgb lerp(Rgb a, Rgb b, double t)
{
	if (t < 0) t = 0;
	if (t > 1) t = 1;
	return Rgb{(uint8_t)(a.r + (b.r - a.r) * t), (uint8_t)(a.g + (b.g - a.g) * t),
	           (uint8_t)(a.b + (b.b - a.b) * t)};
}

void braille_spark(Frame &f, int x, int y, int w, int h, const std::vector<double> &series,
                   Rgb lo, Rgb hi)
{
	if (w <= 0 || h <= 0)
		return;
	const int dots_w = w * 2, dots_h = h * 4;
	std::vector<uint8_t> mask((size_t)w * (size_t)h, 0);
	std::vector<double> colval((size_t)w, 0.0);

	const int n = (int)series.size();
	for (int dx = 0; dx < dots_w; ++dx) {
		const int idx = n - dots_w + dx;
		if (idx < 0 || idx >= n)
			continue;
		double v = series[(size_t)idx];
		if (v < 0) v = 0;
		if (v > 1) v = 1;
		const int cx = dx / 2;
		if (v > colval[(size_t)cx])
			colval[(size_t)cx] = v;
		int filled = (int)(v * dots_h + 0.5);
		if (filled <= 0 && v > 0.01)
			filled = 1;
		for (int k = 0; k < filled; ++k) {
			const int dy = dots_h - 1 - k;
			mask[(size_t)(dy / 4) * (size_t)w + (size_t)cx] |= kDot[dx % 2][dy % 4];
		}
	}

	for (int cy = 0; cy < h; ++cy)
		for (int cx = 0; cx < w; ++cx) {
			const uint8_t m = mask[(size_t)cy * (size_t)w + (size_t)cx];
			if (!m)
				continue;
			char g[5];
			encode_braille(m, g);
			f.put(x + cx, y + cy, g, lerp(lo, hi, colval[(size_t)cx]));
		}
}

void meter(Frame &f, int x, int y, int w, double frac, Rgb full, Rgb empty)
{
	if (frac < 0) frac = 0;
	if (frac > 1) frac = 1;
	const int on = (int)(frac * w + 0.5);
	for (int i = 0; i < w; ++i)
		f.put(x + i, y, i < on ? "▇" : "▁", i < on ? full : empty);
}

// --- half-block text ------------------------------------------------------
//
// 6 wide by 8 tall, one bit per pixel in the low six bits of each row. Strokes
// are two pixels thick wherever the width allows, because at this size a
// single-pixel stroke renders as a thin half block and reads as noise.
namespace {

struct Glyph {
	char c;
	uint8_t rows[8];
};

#define B(a, b, c, d, e, f) \
	((uint8_t)((a) << 5 | (b) << 4 | (c) << 3 | (d) << 2 | (e) << 1 | (f)))

const Glyph kFont[] = {
	{'C', {B(0,1,1,1,1,0), B(1,1,1,1,1,1), B(1,1,0,0,0,0), B(1,1,0,0,0,0),
	       B(1,1,0,0,0,0), B(1,1,0,0,0,0), B(1,1,1,1,1,1), B(0,1,1,1,1,0)}},
	{'P', {B(1,1,1,1,1,0), B(1,1,1,1,1,1), B(1,1,0,0,1,1), B(1,1,1,1,1,1),
	       B(1,1,1,1,1,0), B(1,1,0,0,0,0), B(1,1,0,0,0,0), B(1,1,0,0,0,0)}},
	{'U', {B(1,1,0,0,1,1), B(1,1,0,0,1,1), B(1,1,0,0,1,1), B(1,1,0,0,1,1),
	       B(1,1,0,0,1,1), B(1,1,0,0,1,1), B(1,1,1,1,1,1), B(0,1,1,1,1,0)}},
	{'E', {B(1,1,1,1,1,1), B(1,1,1,1,1,1), B(1,1,0,0,0,0), B(1,1,1,1,1,0),
	       B(1,1,1,1,1,0), B(1,1,0,0,0,0), B(1,1,1,1,1,1), B(1,1,1,1,1,1)}},
	{'0', {B(0,1,1,1,1,0), B(1,1,1,1,1,1), B(1,1,0,0,1,1), B(1,1,0,1,1,1),
	       B(1,1,1,1,0,1), B(1,1,0,0,1,1), B(1,1,1,1,1,1), B(0,1,1,1,1,0)}},
	{'1', {B(0,0,1,1,0,0), B(0,1,1,1,0,0), B(1,1,1,1,0,0), B(0,0,1,1,0,0),
	       B(0,0,1,1,0,0), B(0,0,1,1,0,0), B(1,1,1,1,1,1), B(1,1,1,1,1,1)}},
	{'2', {B(0,1,1,1,1,0), B(1,1,1,1,1,1), B(0,0,0,0,1,1), B(0,0,1,1,1,1),
	       B(1,1,1,1,0,0), B(1,1,0,0,0,0), B(1,1,1,1,1,1), B(1,1,1,1,1,1)}},
	{'3', {B(1,1,1,1,1,0), B(1,1,1,1,1,1), B(0,0,0,0,1,1), B(0,1,1,1,1,0),
	       B(0,1,1,1,1,0), B(0,0,0,0,1,1), B(1,1,1,1,1,1), B(1,1,1,1,1,0)}},
	{'4', {B(1,1,0,0,1,1), B(1,1,0,0,1,1), B(1,1,0,0,1,1), B(1,1,1,1,1,1),
	       B(1,1,1,1,1,1), B(0,0,0,0,1,1), B(0,0,0,0,1,1), B(0,0,0,0,1,1)}},
	{'5', {B(1,1,1,1,1,1), B(1,1,1,1,1,1), B(1,1,0,0,0,0), B(1,1,1,1,1,0),
	       B(0,1,1,1,1,1), B(0,0,0,0,1,1), B(1,1,1,1,1,1), B(1,1,1,1,1,0)}},
	{'6', {B(0,1,1,1,1,0), B(1,1,1,1,1,1), B(1,1,0,0,0,0), B(1,1,1,1,1,0),
	       B(1,1,1,1,1,1), B(1,1,0,0,1,1), B(1,1,1,1,1,1), B(0,1,1,1,1,0)}},
	{'7', {B(1,1,1,1,1,1), B(1,1,1,1,1,1), B(0,0,0,0,1,1), B(0,0,0,1,1,0),
	       B(0,0,1,1,0,0), B(0,0,1,1,0,0), B(0,0,1,1,0,0), B(0,0,1,1,0,0)}},
	{'8', {B(0,1,1,1,1,0), B(1,1,1,1,1,1), B(1,1,0,0,1,1), B(0,1,1,1,1,0),
	       B(0,1,1,1,1,0), B(1,1,0,0,1,1), B(1,1,1,1,1,1), B(0,1,1,1,1,0)}},
	{'9', {B(0,1,1,1,1,0), B(1,1,1,1,1,1), B(1,1,0,0,1,1), B(1,1,1,1,1,1),
	       B(0,1,1,1,1,1), B(0,0,0,0,1,1), B(1,1,1,1,1,1), B(0,1,1,1,1,0)}},
	{'A', {B(0,1,1,1,1,0), B(1,1,1,1,1,1), B(1,1,0,0,1,1), B(1,1,0,0,1,1),
	       B(1,1,1,1,1,1), B(1,1,1,1,1,1), B(1,1,0,0,1,1), B(1,1,0,0,1,1)}},
	{'L', {B(1,1,0,0,0,0), B(1,1,0,0,0,0), B(1,1,0,0,0,0), B(1,1,0,0,0,0),
	       B(1,1,0,0,0,0), B(1,1,0,0,0,0), B(1,1,1,1,1,1), B(1,1,1,1,1,1)}},
	{'M', {B(1,1,0,0,1,1), B(1,1,1,1,1,1), B(1,1,1,1,1,1), B(1,0,1,1,0,1),
	       B(1,0,0,0,0,1), B(1,0,0,0,0,1), B(1,0,0,0,0,1), B(1,0,0,0,0,1)}},
	{'O', {B(0,1,1,1,1,0), B(1,1,1,1,1,1), B(1,1,0,0,1,1), B(1,1,0,0,1,1),
	       B(1,1,0,0,1,1), B(1,1,0,0,1,1), B(1,1,1,1,1,1), B(0,1,1,1,1,0)}},
	{'R', {B(1,1,1,1,1,0), B(1,1,1,1,1,1), B(1,1,0,0,1,1), B(1,1,1,1,1,1),
	       B(1,1,1,1,1,0), B(1,1,0,1,1,0), B(1,1,0,0,1,1), B(1,1,0,0,1,1)}},
	{'T', {B(1,1,1,1,1,1), B(1,1,1,1,1,1), B(0,0,1,1,0,0), B(0,0,1,1,0,0),
	       B(0,0,1,1,0,0), B(0,0,1,1,0,0), B(0,0,1,1,0,0), B(0,0,1,1,0,0)}},
	{'X', {B(1,1,0,0,1,1), B(1,1,0,0,1,1), B(0,1,1,1,1,0), B(0,0,1,1,0,0),
	       B(0,0,1,1,0,0), B(0,1,1,1,1,0), B(1,1,0,0,1,1), B(1,1,0,0,1,1)}},
	{'H', {B(1,1,0,0,1,1), B(1,1,0,0,1,1), B(1,1,0,0,1,1), B(1,1,1,1,1,1),
	       B(1,1,1,1,1,1), B(1,1,0,0,1,1), B(1,1,0,0,1,1), B(1,1,0,0,1,1)}},
	{'V', {B(1,1,0,0,1,1), B(1,1,0,0,1,1), B(1,1,0,0,1,1), B(1,1,0,0,1,1),
	       B(0,1,1,1,1,0), B(0,1,1,1,1,0), B(0,0,1,1,0,0), B(0,0,1,1,0,0)}},
	{'W', {B(1,1,0,0,1,1), B(1,1,0,0,1,1), B(1,1,0,0,1,1), B(1,1,0,0,1,1),
	       B(1,0,1,1,0,1), B(1,0,1,1,0,1), B(1,1,1,1,1,1), B(0,1,1,1,1,0)}},
	{'G', {B(0,1,1,1,1,0), B(1,1,1,1,1,1), B(1,1,0,0,0,0), B(1,1,0,1,1,1),
	       B(1,1,0,0,1,1), B(1,1,0,0,1,1), B(1,1,1,1,1,1), B(0,1,1,1,1,0)}},
	{'%', {B(1,1,0,0,1,1), B(1,1,0,1,1,0), B(0,0,1,1,0,0), B(0,0,1,1,0,0),
	       B(0,1,1,0,0,0), B(0,1,1,0,0,0), B(1,1,0,0,1,1), B(1,1,0,0,1,1)}},
	{'.', {B(0,0,0,0,0,0), B(0,0,0,0,0,0), B(0,0,0,0,0,0), B(0,0,0,0,0,0),
	       B(0,0,0,0,0,0), B(0,0,0,0,0,0), B(0,1,1,0,0,0), B(0,1,1,0,0,0)}},
};
#undef B

const Glyph *find(char c)
{
	for (const auto &g : kFont)
		if (g.c == c)
			return &g;
	return nullptr;
}

} // namespace

int block_text_width(const std::string &s)
{
	return s.empty() ? 0 : (int)s.size() * kBlockAdvance - 1;
}

void block_text(Frame &f, int x, int y, const std::string &s, Rgb fg)
{
	for (size_t i = 0; i < s.size(); ++i) {
		const Glyph *g = find((char)toupper((unsigned char)s[i]));
		if (!g)
			continue;
		const int gx = x + (int)i * kBlockAdvance;
		for (int r = 0; r < kBlockRows; ++r) {
			for (int c = 0; c < kBlockW; ++c) {
				const int bit = kBlockW - 1 - c;
				const bool top = (g->rows[2 * r] >> bit) & 1;
				const bool bot = (g->rows[2 * r + 1] >> bit) & 1;
				const char *ch = top && bot ? "█"
				               : top        ? "▀"
				               : bot        ? "▄"
				                            : nullptr;
				if (ch)
					f.put(gx + c, y + r, ch, fg);
			}
		}
	}
}

// --- terminal -------------------------------------------------------------

static struct termios g_saved;
static bool g_have_saved = false;
static volatile sig_atomic_t g_resized = 0;
static volatile sig_atomic_t g_quit = 0;

static void on_winch(int) { g_resized = 1; }
static void on_term(int) { g_quit = 1; }

static void restore_atexit()
{
	if (g_have_saved) {
		tcsetattr(STDIN_FILENO, TCSAFLUSH, &g_saved);
		g_have_saved = false;
	}
	// Cursor back, leave the alternate screen.
	const char *s = "\x1b[?7h\x1b[?25h\x1b[?1049l";
	ssize_t rc = write(STDOUT_FILENO, s, strlen(s));
	(void)rc;
}

bool Terminal::begin()
{
	if (!isatty(STDIN_FILENO) || !isatty(STDOUT_FILENO))
		return false;
	if (tcgetattr(STDIN_FILENO, &g_saved) != 0)
		return false;
	g_have_saved = true;
	atexit(restore_atexit);

	struct termios raw = g_saved;
	raw.c_lflag &= (tcflag_t)~(ECHO | ICANON | ISIG);
	raw.c_iflag &= (tcflag_t)~(IXON | ICRNL);
	raw.c_cc[VMIN] = 0;
	raw.c_cc[VTIME] = 0;
	if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &raw) != 0)
		return false;

	struct sigaction sa;
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = on_winch;
	sigaction(SIGWINCH, &sa, nullptr);
	sa.sa_handler = on_term;
	sigaction(SIGINT, &sa, nullptr);
	sigaction(SIGTERM, &sa, nullptr);

	const char *s = "\x1b[?1049h\x1b[?25l\x1b[?7l\x1b[2J";
	ssize_t rc = write(STDOUT_FILENO, s, strlen(s));
	(void)rc;
	active_ = true;
	measure();
	return true;
}

void Terminal::end()
{
	if (!active_)
		return;
	active_ = false;
	restore_atexit();
}

void Terminal::measure()
{
	struct winsize ws;
	if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0 && ws.ws_col > 0) {
		w_ = ws.ws_col;
		h_ = ws.ws_row;
	}
}

Event Terminal::poll(int timeout_ms)
{
	if (g_quit)
		return {Key::Quit, 0};
	if (g_resized) {
		g_resized = 0;
		measure();
		return {Key::Resize, 0};
	}

	struct pollfd p = {STDIN_FILENO, POLLIN, 0};
	const int rc = ::poll(&p, 1, timeout_ms);
	if (rc <= 0)
		return {g_quit ? Key::Quit : (g_resized ? Key::Resize : Key::None), 0};

	char c;
	if (read(STDIN_FILENO, &c, 1) != 1)
		return {Key::None, 0};

	if (c == 0x1b) {
		// Escape, or a CSI sequence. VTIME 0 means a bare Escape reads
		// nothing more, which is how we tell them apart.
		char seq[3] = {0};
		struct pollfd q = {STDIN_FILENO, POLLIN, 0};
		if (::poll(&q, 1, 25) > 0 && read(STDIN_FILENO, &seq[0], 1) == 1) {
			if (seq[0] == '[' && ::poll(&q, 1, 25) > 0 &&
			    read(STDIN_FILENO, &seq[1], 1) == 1) {
				switch (seq[1]) {
				case 'A': return {Key::Up, 0};
				case 'B': return {Key::Down, 0};
				case 'C': return {Key::Right, 0};
				case 'D': return {Key::Left, 0};
				default: return {Key::None, 0};
				}
			}
			return {Key::None, 0};
		}
		return {Key::Escape, 0};
	}
	if (c == '\r' || c == '\n')
		return {Key::Enter, 0};
	if (c == '\t')
		return {Key::Tab, 0};
	if (c == 127 || c == 8)
		return {Key::Backspace, 0};
	if (c == 3 || c == 4)  // ^C, ^D
		return {Key::Quit, 0};
	return {Key::Char, c};
}

void Terminal::present(const std::string &s)
{
	ssize_t rc = write(STDOUT_FILENO, s.data(), s.size());
	(void)rc;
}

} // namespace tui
} // namespace vh22
