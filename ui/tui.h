// Terminal layer for vh22-top.
//
// Aesthetic brief: System 7 / Platinum window chrome, the 1977 six-colour
// Apple rainbow as the data palette, btop's braille plotting density. The
// rainbow is not decoration -- the hashrate graph is coloured by height in
// logo order, green at the top, so a healthy run literally paints the logo.
#pragma once

#include <stddef.h>
#include <stdint.h>

#include <string>
#include <vector>

namespace vh22 {
namespace tui {

struct Rgb {
	uint8_t r, g, b;
};

// --- palette --------------------------------------------------------------
//
// The 1977 Apple logo stripes, top to bottom. Sampled from the logo itself
// rather than approximated with ANSI 16, which is the whole reason this wants
// truecolor.
namespace pal {
constexpr Rgb kGreen = {97, 187, 70};
constexpr Rgb kYellow = {253, 184, 39};
constexpr Rgb kOrange = {245, 130, 31};
constexpr Rgb kRed = {224, 58, 62};
constexpr Rgb kPurple = {150, 61, 151};
constexpr Rgb kBlue = {0, 157, 220};

// Platinum greys for chrome. Deliberately desaturated so the rainbow is the
// only thing that draws the eye.
constexpr Rgb kInk = {232, 232, 230};
constexpr Rgb kLabel = {150, 150, 148};
constexpr Rgb kChrome = {110, 110, 108};
constexpr Rgb kDim = {74, 74, 72};
constexpr Rgb kPanel = {26, 26, 28};
constexpr Rgb kBar = {44, 44, 46};

// Logo order, for gradients.
constexpr Rgb kRainbow[6] = {kGreen, kYellow, kOrange, kRed, kPurple, kBlue};
} // namespace pal

// --- frame buffer ---------------------------------------------------------

struct Cell {
	char ch[5] = {' ', 0, 0, 0, 0};
	Rgb fg = pal::kInk;
	Rgb bg = pal::kPanel;
	bool bold = false;
};

class Frame {
public:
	void resize(int w, int h);
	int width() const { return w_; }
	int height() const { return h_; }
	void clear(Rgb bg = pal::kPanel);

	void put(int x, int y, const char *utf8, Rgb fg, Rgb bg = pal::kPanel,
	         bool bold = false);
	// Returns the column after the last glyph written.
	int text(int x, int y, const std::string &s, Rgb fg, Rgb bg = pal::kPanel,
	         bool bold = false);
	void fill(int x, int y, int w, int h, const char *utf8, Rgb fg,
	          Rgb bg = pal::kPanel);
	void hline(int x, int y, int w, const char *utf8, Rgb fg, Rgb bg = pal::kPanel);

	// Renders the whole frame to one escape-sequence string. Full redraw per
	// tick: at 10 fps and this size it is far cheaper than tracking damage,
	// and it cannot desynchronise.
	std::string render() const;

private:
	int w_ = 0, h_ = 0;
	std::vector<Cell> cells_;
};

// --- chrome ---------------------------------------------------------------

// A System 7 window: pinstriped title bar with a close box, centred title,
// square shoulders. `focused` draws the stripes; an unfocused classic Mac
// window had a blank bar, which is exactly the affordance we want for
// keyboard navigation.
void window(Frame &f, int x, int y, int w, int h, const std::string &title, bool focused,
            Rgb accent);

// The six-stripe rainbow rule used as a section divider.
void rainbow_rule(Frame &f, int x, int y, int w);

// --- widgets --------------------------------------------------------------

// btop-style braille plot: 2x4 dots per cell, coloured by height through the
// Apple rainbow with green at the top.
//
// `occlude`, when given, is a w*h byte grid: any cell set is left untouched so
// a foreground element can stand in the plot rather than under it.
void braille_plot(Frame &f, int x, int y, int w, int h, const std::vector<double> &series,
                  double vmax, const std::vector<uint8_t> *occlude = nullptr);

// Height, in dot rows from the bottom, that the plot fills in each cell
// column. Lets an occluding element ask whether the stream has reached it.
std::vector<int> plot_fill_dots(int w, int h, const std::vector<double> &series,
                                double vmax);

// Horizontal meter. `frac` in [0,1].
void meter(Frame &f, int x, int y, int w, double frac, Rgb full, Rgb empty = pal::kBar);

Rgb lerp(Rgb a, Rgb b, double t);

// Columns a string occupies. Layout maths must never use size(): every glyph
// in this UI that matters -- arrows, braille, box drawing -- is multibyte.
int disp_len(const std::string &s);

// A compact braille history trace, for one core per row. Same plotting
// density as braille_plot, but coloured per column by that column's own value
// rather than by height -- at one row tall there is only one height band, so
// the colour has to carry the magnitude instead of the geometry.
void braille_spark(Frame &f, int x, int y, int w, int h, const std::vector<double> &series,
                   Rgb lo, Rgb hi);

// Half-block "ANSI block" text. Glyphs are 6x8 pixels drawn two pixels to a
// cell with the U+2580 half blocks, so a line occupies 4 terminal rows and
// gets double the vertical resolution the character grid would allow.
//
// Currently unused. It was fitted as a "CPU" heading over the cores panel and
// works, but four rows is a lot of vertical budget and the panel reads better
// without it. Kept because the obvious next home is the hashrate readout,
// which would want M, H, / and s added to the font.
enum : int { kBlockRows = 4, kBlockW = 6, kBlockAdvance = 7 };
int block_text_width(const std::string &s);
void block_text(Frame &f, int x, int y, const std::string &s, Rgb fg);

// --- terminal -------------------------------------------------------------

enum class Key {
	None, Up, Down, Left, Right, Enter, Escape, Tab, Backspace, Char, Quit, Resize
};

struct Event {
	Key key = Key::None;
	char ch = 0;
};

class Terminal {
public:
	bool begin();   // raw mode, alternate screen, hidden cursor
	void end();     // always safe to call twice
	Event poll(int timeout_ms);
	void present(const std::string &s);
	int width() const { return w_; }
	int height() const { return h_; }
	void measure();

private:
	int w_ = 80, h_ = 24;
	bool active_ = false;
};

} // namespace tui
} // namespace vh22
