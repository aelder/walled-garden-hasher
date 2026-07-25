// Minimal JSON, enough for stratum and no more.
//
// Stratum speaks line-delimited JSON-RPC with a small vocabulary: objects,
// arrays, strings, numbers, booleans and null, nested two or three deep. That
// does not justify a dependency, and vh22 has none anywhere else.
#pragma once

#include <stdlib.h>

#include <map>
#include <string>
#include <vector>

namespace vh22 {
namespace json {

struct Value;
using Array = std::vector<Value>;
using Object = std::map<std::string, Value>;

enum class Type { Null, Bool, Number, String, Array, Object };

struct Value {
	Type type = Type::Null;
	bool b = false;
	double num = 0;
	std::string str;
	Array arr;
	Object obj;

	bool is_null() const { return type == Type::Null; }
	bool truthy() const { return type == Type::Bool ? b : (type != Type::Null); }

	// Array access; out-of-range yields null rather than throwing, because a
	// short params array from a pool is a protocol event, not an exception.
	const Value &at(size_t i) const
	{
		static const Value kNull;
		return i < arr.size() ? arr[i] : kNull;
	}
	const Value &operator[](const std::string &k) const
	{
		static const Value kNull;
		const auto it = obj.find(k);
		return it == obj.end() ? kNull : it->second;
	}
	std::string as_string() const { return type == Type::String ? str : std::string(); }
	double as_number() const { return type == Type::Number ? num : 0; }
};

class Parser {
public:
	explicit Parser(const std::string &s) : s_(s) {}

	bool parse(Value &out)
	{
		ws();
		if (!value(out))
			return false;
		ws();
		return true;
	}

private:
	void ws()
	{
		while (i_ < s_.size() && (s_[i_] == ' ' || s_[i_] == '\t' || s_[i_] == '\n' ||
		                          s_[i_] == '\r'))
			++i_;
	}
	bool lit(const char *w)
	{
		const size_t n = strlen_(w);
		if (s_.compare(i_, n, w) != 0)
			return false;
		i_ += n;
		return true;
	}
	static size_t strlen_(const char *p)
	{
		size_t n = 0;
		while (p[n]) ++n;
		return n;
	}

	bool string(std::string &out)
	{
		if (i_ >= s_.size() || s_[i_] != '"')
			return false;
		++i_;
		out.clear();
		while (i_ < s_.size() && s_[i_] != '"') {
			char c = s_[i_++];
			if (c != '\\') {
				out.push_back(c);
				continue;
			}
			if (i_ >= s_.size())
				return false;
			const char e = s_[i_++];
			switch (e) {
			case 'n': out.push_back('\n'); break;
			case 't': out.push_back('\t'); break;
			case 'r': out.push_back('\r'); break;
			case 'b': out.push_back('\b'); break;
			case 'f': out.push_back('\f'); break;
			case 'u': {
				// Stratum payloads are hex and ASCII; keep the BMP escape
				// handling to the range that can actually appear.
				if (i_ + 4 > s_.size())
					return false;
				unsigned cp = (unsigned)strtoul(s_.substr(i_, 4).c_str(), nullptr, 16);
				i_ += 4;
				if (cp < 0x80) {
					out.push_back((char)cp);
				} else if (cp < 0x800) {
					out.push_back((char)(0xC0 | (cp >> 6)));
					out.push_back((char)(0x80 | (cp & 0x3F)));
				} else {
					out.push_back((char)(0xE0 | (cp >> 12)));
					out.push_back((char)(0x80 | ((cp >> 6) & 0x3F)));
					out.push_back((char)(0x80 | (cp & 0x3F)));
				}
				break;
			}
			default: out.push_back(e); break;
			}
		}
		if (i_ >= s_.size())
			return false;
		++i_;
		return true;
	}

	bool value(Value &v)
	{
		if (i_ >= s_.size())
			return false;
		const char c = s_[i_];
		if (c == '"') {
			v.type = Type::String;
			return string(v.str);
		}
		if (c == '{') {
			++i_;
			v.type = Type::Object;
			ws();
			if (i_ < s_.size() && s_[i_] == '}') { ++i_; return true; }
			for (;;) {
				ws();
				std::string k;
				if (!string(k))
					return false;
				ws();
				if (i_ >= s_.size() || s_[i_] != ':')
					return false;
				++i_;
				ws();
				Value child;
				if (!value(child))
					return false;
				v.obj[k] = child;
				ws();
				if (i_ < s_.size() && s_[i_] == ',') { ++i_; continue; }
				if (i_ < s_.size() && s_[i_] == '}') { ++i_; return true; }
				return false;
			}
		}
		if (c == '[') {
			++i_;
			v.type = Type::Array;
			ws();
			if (i_ < s_.size() && s_[i_] == ']') { ++i_; return true; }
			for (;;) {
				ws();
				Value child;
				if (!value(child))
					return false;
				v.arr.push_back(child);
				ws();
				if (i_ < s_.size() && s_[i_] == ',') { ++i_; continue; }
				if (i_ < s_.size() && s_[i_] == ']') { ++i_; return true; }
				return false;
			}
		}
		if (c == 't' && lit("true")) { v.type = Type::Bool; v.b = true; return true; }
		if (c == 'f' && lit("false")) { v.type = Type::Bool; v.b = false; return true; }
		if (c == 'n' && lit("null")) { v.type = Type::Null; return true; }

		char *end = nullptr;
		const double d = strtod(s_.c_str() + i_, &end);
		if (end == s_.c_str() + i_)
			return false;
		i_ = (size_t)(end - s_.c_str());
		v.type = Type::Number;
		v.num = d;
		return true;
	}

	const std::string &s_;
	size_t i_ = 0;
};

inline bool parse(const std::string &s, Value &out) { return Parser(s).parse(out); }

// Escapes only what stratum can actually contain: worker names and passwords
// are user-supplied, so quotes and backslashes must not break the frame.
inline std::string quote(const std::string &s)
{
	std::string o = "\"";
	for (char c : s) {
		if (c == '"' || c == '\\')
			o.push_back('\\');
		if ((unsigned char)c < 0x20)
			continue;
		o.push_back(c);
	}
	o.push_back('"');
	return o;
}

} // namespace json
} // namespace vh22
