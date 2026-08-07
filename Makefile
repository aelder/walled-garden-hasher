# vh22 — native AArch64 VerusHash 2.2
#
# -mcpu (not -march): it selects the scheduling model as well as the feature
# set. clang 21 has no apple-m5 model yet, so `native` uses the detected CPU's
# scheduling model.

CXX      ?= clang++
MCPU     ?= native
OPT      ?= -O3
CXXFLAGS ?= $(OPT) -mcpu=$(MCPU) -std=c++17 -Wall -Wextra -Wno-unused-parameter \
            -fno-stack-protector -fomit-frame-pointer
INCLUDES  = -Iinclude -Iref -Inet
DEPFLAGS  = -MMD -MP
LDFLAGS  ?=
LDLIBS   ?= -lpthread

BUILD    = build

ENGINE_SRC = src/verushash.cpp src/clhash_wave.cpp
REF_SRC    = ref/ref.cpp

ENGINE_OBJ = $(ENGINE_SRC:%.cpp=$(BUILD)/%.o)
REF_OBJ    = $(REF_SRC:%.cpp=$(BUILD)/%.o)

BINARIES = $(BUILD)/vh22-selftest $(BUILD)/vh22-bench $(BUILD)/vh22-sieve-oracle \
           $(BUILD)/vh22-top $(BUILD)/vh22-stratum-test

.PHONY: all clean test bench disas crosscheck top stratum-test
all: $(BINARIES)

$(BUILD)/%.o: %.cpp
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) $(DEPFLAGS) $(INCLUDES) -c $< -o $@

$(BUILD)/vh22-selftest: $(BUILD)/tools/selftest.o $(ENGINE_OBJ) $(REF_OBJ)
	$(CXX) $(CXXFLAGS) $^ -o $@ $(LDFLAGS) $(LDLIBS)

$(BUILD)/vh22-bench: $(BUILD)/tools/bench.o $(ENGINE_OBJ)
	$(CXX) $(CXXFLAGS) $^ -o $@ $(LDFLAGS) $(LDLIBS)

$(BUILD)/vh22-sieve-oracle: $(BUILD)/tools/sieve_oracle.o $(ENGINE_OBJ)
	$(CXX) $(CXXFLAGS) $^ -o $@ $(LDFLAGS) $(LDLIBS)

NET_OBJ = $(BUILD)/net/stratum.o
$(BUILD)/vh22-stratum-test: $(BUILD)/tools/stratum_test.o $(NET_OBJ) $(ENGINE_OBJ)
	$(CXX) $(CXXFLAGS) $^ -o $@ $(LDFLAGS) $(LDLIBS)

# Exercises the client against tools/mock_pool.py, which validates the submit
# framing from the pool side.
stratum-test: $(BUILD)/vh22-stratum-test
	@python3 tools/mock_pool.py --port 13956 & \
	 sleep 1; $(BUILD)/vh22-stratum-test --port 13956; rc=$$?; wait; exit $$rc

UI_OBJ = $(BUILD)/ui/tui.o $(BUILD)/ui/vh22top.o
$(BUILD)/vh22-top: $(UI_OBJ) $(NET_OBJ) $(ENGINE_OBJ)
	$(CXX) $(CXXFLAGS) $^ -o $@ $(LDFLAGS) $(LDLIBS)

top: $(BUILD)/vh22-top
	$(BUILD)/vh22-top

# End-to-end diff against the deployed sse2neon implementation, vendored in
# third_party/verus under its own licence. It needs a submodule and a second
# compile of the upstream sources, so it is a gate rather than part of `all`.
UPSTREAM_DIR ?= third_party/verus
UPSTREAM_FLAGS = -O2 -mcpu=$(MCPU) -DARM -I$(UPSTREAM_DIR) -w

# The upstream sources include sse2neon, which is a submodule and is therefore
# absent from a fresh clone. `make test` does not need it; say so plainly here
# rather than failing on a missing header three levels down.
$(BUILD)/upstream/verus_clhash.o: $(UPSTREAM_DIR)/verus_clhash.cpp
	@mkdir -p $(dir $@)
	@test -f $(UPSTREAM_DIR)/sse2neon/sse2neon.h || { \
	  echo "crosscheck needs the sse2neon submodule:"; \
	  echo "    git submodule update --init third_party/verus/sse2neon"; \
	  exit 1; }
	$(CXX) $(UPSTREAM_FLAGS) -std=c++17 -c $< -o $@

# haraka.c is a C translation unit upstream; compiling it as C++ would mangle
# the names the extern "C" declarations in crosscheck.cpp expect.
$(BUILD)/upstream/haraka.o: $(UPSTREAM_DIR)/haraka.c
	@mkdir -p $(dir $@)
	$(CC) $(UPSTREAM_FLAGS) -std=c11 -c $< -o $@

$(BUILD)/vh22-crosscheck: $(BUILD)/tools/crosscheck.o $(ENGINE_OBJ) \
                          $(BUILD)/upstream/verus_clhash.o $(BUILD)/upstream/haraka.o
	$(CXX) $(CXXFLAGS) $^ -o $@ $(LDFLAGS) $(LDLIBS)

crosscheck: $(BUILD)/vh22-crosscheck
	$(BUILD)/vh22-crosscheck

test: $(BUILD)/vh22-selftest
	$(BUILD)/vh22-selftest

bench: $(BUILD)/vh22-bench
	$(BUILD)/vh22-bench

# §10: read the disassembly. The two things clang will silently ruin are
# AESE/AESMC adjacency and the EXT/PMULL pairing.
disas: $(BUILD)/src/clhash_wave.o
	otool -tvV $< | c++filt

clean:
	rm -rf $(BUILD)

-include $(shell find $(BUILD) -name '*.d' 2>/dev/null)
