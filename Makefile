# dns-encrypted-proxy build
#
# One variant per invocation, selected with BUILD=:
#   release   -O3 -flto, section GC, NDEBUG (default)
#   debug     -Og -g
#   asan      -Og -g -fsanitize=address
#   coverage  -O0 -g --coverage; `make coverage` runs the suite and gates
#   analyze   -Og -g plus -fanalyzer and -fstack-usage on production code
#
# Intermediates go to build/<variant>/, runnable binaries to build/bin/.
# Both are overridable (OBJ_DIR=, BIN_DIR=) so the feature matrix can keep
# every combination isolated; sharing build/bin across combinations lets a
# stale binary from another combination survive when its objects are older.
#
# Transport selection: DOH=1 DOT=1 DOQ=0 by default. At least one must be on.
#
# Every flag that reaches the compiler is written to $(OBJ_DIR)/.flags and
# every object depends on it, so switching DOH/DOT/DOQ or the variant inside
# one OBJ_DIR rebuilds instead of linking objects compiled for another shape.

.DEFAULT_GOAL := all

# No built-in rules: with them, make tries to "remake" every included .d
# file from a matching X.d.o through `%: %.o`, and X.d.o matches the
# integration-group pattern below, so it compiled bogus objects on every
# incremental build. Dependency files are only ever produced by -MMD.
MAKEFLAGS += --no-builtin-rules
.SUFFIXES:

BUILD     ?= release
DOH       ?= 1
DOT       ?= 1
DOQ       ?= 0
WERROR    ?= 1
C_LOG_PATH ?= ../c-log
STACK_USAGE_LIMIT ?= 65536
COVERAGE_LINE_THRESHOLD ?= 80
TEST_TIMEOUT ?= 30

CC        ?= cc
PKG_CONFIG ?= pkg-config

OBJ_DIR   ?= build/$(BUILD)
BIN_DIR   ?= build/bin
GEN_DIR   := $(OBJ_DIR)/generated

VALID_BUILDS := release debug asan coverage analyze
ifeq ($(filter $(BUILD),$(VALID_BUILDS)),)
$(error BUILD must be one of: $(VALID_BUILDS) (got '$(BUILD)'))
endif
ifeq ($(DOH)$(DOT)$(DOQ),000)
$(error at least one of DOH, DOT, DOQ must be 1)
endif

# Not an error at parse time: `make clean` and `make help` must work without
# a c-log checkout. Anything that compiles depends on this check instead.
C_LOG_HEADER := $(C_LOG_PATH)/log.h

# --------------------------------------------------------------------------
# Version identity: SEMVER_YYYYMMDD.HHMM.TYPE, stamped when version.h is
# regenerated (release_version or the flag set changed, or it is missing).
# --------------------------------------------------------------------------
VERSION_SEMVER := $(strip $(shell cat release_version 2>/dev/null))
ifeq ($(VERSION_SEMVER),)
$(error release_version is empty or missing)
endif

# --------------------------------------------------------------------------
# Flags
# --------------------------------------------------------------------------
WARN_FLAGS := -Wall -Wextra -Wpedantic -Wshadow \
	-Wunused -Wunused-function -Wunused-variable -Wunused-parameter -Wunused-result \
	-Wdouble-promotion -Wformat=2 -Wformat-truncation \
	-Wmissing-prototypes -Wstrict-prototypes -Wmissing-declarations \
	-Wcast-align -Wcast-qual -Wnull-dereference -Wconversion -Wsign-conversion
ifeq ($(WERROR),1)
WARN_FLAGS += -Werror
endif

HARDEN_FLAGS := -fstack-protector-strong -fstack-clash-protection

OPT_release  := -O3 -DNDEBUG -flto=auto -ffunction-sections -fdata-sections
OPT_debug    := -Og -g
OPT_asan     := -Og -g -fsanitize=address -fno-omit-frame-pointer
OPT_coverage := -O0 -g --coverage
OPT_analyze  := -Og -g -fstack-usage

LDOPT_release  := -flto=auto -Wl,--gc-sections
LDOPT_debug    :=
LDOPT_asan     := -fsanitize=address
LDOPT_coverage := --coverage
LDOPT_analyze  :=

# -fanalyzer only on production translation units: tests deliberately walk
# NULL paths and fault-injected fd states that the analyzer reports as bugs.
ANALYZER_FLAGS := $(if $(filter analyze,$(BUILD)),-fanalyzer)

DEFINES := -DUPSTREAM_DOH_ENABLED=$(DOH) -DUPSTREAM_DOT_ENABLED=$(DOT) -DUPSTREAM_DOQ_ENABLED=$(DOQ)
INCLUDES := -Isrc -I$(GEN_DIR) -I$(C_LOG_PATH)

pkg_cflags = $(shell $(PKG_CONFIG) --cflags $(1) 2>/dev/null)
pkg_libs   = $(shell $(PKG_CONFIG) --libs $(1) 2>/dev/null)
# First pkg-config module name that exists; distros disagree on naming.
pkg_first  = $(firstword $(foreach m,$(1),$(if $(shell $(PKG_CONFIG) --exists $(m) && echo y),$(m))))

PKGS :=
ifeq ($(DOH),1)
PKGS += libcurl
endif
ifneq ($(DOT)$(DOQ),00)
PKGS += openssl
endif
ifeq ($(DOQ),1)
NGTCP2_PKG := $(call pkg_first,ngtcp2 libngtcp2)
NGTCP2_CRYPTO_PKG := $(call pkg_first,ngtcp2_crypto_openssl libngtcp2_crypto_openssl \
	ngtcp2_crypto_ossl libngtcp2_crypto_ossl ngtcp2_crypto_quictls libngtcp2_crypto_quictls)
ifeq ($(NGTCP2_PKG),)
$(error DOQ=1 requires the ngtcp2 pkg-config module (ngtcp2 or libngtcp2))
endif
ifeq ($(NGTCP2_CRYPTO_PKG),)
$(error DOQ=1 requires an ngtcp2 OpenSSL-family crypto module (crypto_openssl, crypto_ossl or crypto_quictls))
endif
PKGS += $(NGTCP2_PKG) $(NGTCP2_CRYPTO_PKG)
endif

BASE_CFLAGS := -std=c11 -pthread $(OPT_$(BUILD)) $(WARN_FLAGS) $(HARDEN_FLAGS) $(DEFINES) $(INCLUDES) \
	$(call pkg_cflags,$(PKGS)) $(CPPFLAGS) $(CFLAGS)
BASE_LDFLAGS := -pthread $(LDOPT_$(BUILD)) $(LDFLAGS)
LIBS := $(call pkg_libs,$(PKGS))

CMOCKA_CFLAGS := $(call pkg_cflags,cmocka)
CMOCKA_LIBS   := $(or $(call pkg_libs,cmocka),-lcmocka)
SSL_LIBS      := $(or $(call pkg_libs,openssl),-lssl -lcrypto)
CURL_LIBS     := $(or $(call pkg_libs,libcurl),-lcurl)

# --------------------------------------------------------------------------
# Sources
# --------------------------------------------------------------------------
LIB_SRCS := src/errors.c src/config.c src/cache.c src/dns_message.c src/logger.c \
	src/iterative_resolver.c src/upstream_bootstrap.c src/upstream_dispatch.c \
	src/upstream.c src/dns_server.c src/metrics.c
ifeq ($(DOH),1)
LIB_SRCS += src/upstream_doh.c
endif
ifeq ($(DOT),1)
LIB_SRCS += src/upstream_dot.c
endif
ifeq ($(DOQ),1)
LIB_SRCS += src/upstream_doq.c src/upstream_doq_ngtcp2.c
endif

PROD_SRCS := $(LIB_SRCS) src/main.c
LIB_OBJS  := $(LIB_SRCS:%.c=$(OBJ_DIR)/%.o)
ERR_OBJ   := $(OBJ_DIR)/src/errors.o

PROXY := $(BIN_DIR)/dns-encrypted-proxy

# Tests come in three link shapes, mirroring how each one is written:
#   LIB    links every production object (black-box over the public API)
#   AMALG  #includes one src/*.c and links errors.o for set_error
#   SOLO   #includes its unit and needs nothing else from src/
TESTS_LIB := test_errors test_config test_cache test_dns_message test_upstream
TESTS_AMALG := test_cache_internal test_metrics_internal test_dns_server_internal \
	test_iterative_resolver_internal test_upstream_bootstrap_internal \
	test_upstream_internal test_upstream_dispatch_internal
TESTS_SOLO := test_dns_message_internal
ifeq ($(DOH),1)
TESTS_AMALG += test_upstream_doh_internal
endif
ifeq ($(DOT),1)
TESTS_AMALG += test_upstream_dot_internal
endif
ifeq ($(DOQ),1)
TESTS_AMALG += test_upstream_doq_internal
TESTS_DOQ_NGTCP2 := test_upstream_doq_ngtcp2_internal
endif
# One source, three binaries: each group exercises a slice of the functions,
# so the rest are inert in any one build.
TESTS_INTEG := test_integration_core test_integration_transport test_integration_runtime

ALL_TESTS := $(TESTS_LIB) $(TESTS_AMALG) $(TESTS_SOLO) $(TESTS_DOQ_NGTCP2) $(TESTS_INTEG)
TEST_BINS := $(ALL_TESTS:%=$(BIN_DIR)/%)

BENCH_BINS := $(BIN_DIR)/cache_bench $(BIN_DIR)/e2e_proxy_bench

# --------------------------------------------------------------------------
# Top-level targets
# --------------------------------------------------------------------------
.PHONY: all proxy tests bench test coverage analyze cppcheck stack-usage \
	lint lint-strict compdb clean distclean help check-c-log

all: proxy tests

proxy: $(PROXY)
tests: $(TEST_BINS)
bench: $(BENCH_BINS)

help:
	@sed -n '2,20p' Makefile | sed 's/^# \{0,1\}//'
	@echo
	@echo 'Targets: all proxy tests bench test coverage analyze cppcheck'
	@echo '         stack-usage lint lint-strict compdb clean distclean'

check-c-log:
	@test -f $(C_LOG_HEADER) || { echo "c-log header not found at $(C_LOG_HEADER); set C_LOG_PATH=<path-to-c-log>" >&2; exit 1; }

# --------------------------------------------------------------------------
# Flag tracking and version header
# --------------------------------------------------------------------------
FLAGS_FILE := $(OBJ_DIR)/.flags
FLAGS_NOW  := $(CC) $(BASE_CFLAGS) $(ANALYZER_FLAGS) | $(BASE_LDFLAGS) $(LIBS) | $(BUILD)

$(FLAGS_FILE): FORCE | check-c-log
	@mkdir -p $(@D)
	@if [ "$$(cat $@ 2>/dev/null)" != '$(FLAGS_NOW)' ]; then printf '%s\n' '$(FLAGS_NOW)' > $@; fi

$(GEN_DIR)/version.h: src/version.h.in release_version $(FLAGS_FILE)
	@mkdir -p $(@D)
	@ts=$$(date -u +%Y%m%d.%H%M); \
	sed -e 's/@PROXY_VERSION_SEMVER@/$(VERSION_SEMVER)/' \
	    -e "s/@PROXY_VERSION_TIMESTAMP@/$$ts/" \
	    -e 's/@PROXY_VERSION_BUILD_TYPE@/$(BUILD)/' \
	    -e "s/@PROXY_VERSION_FULL@/$(VERSION_SEMVER)_$$ts.$(BUILD)/" $< > $@
	@echo "  GEN   $@ ($(VERSION_SEMVER) $(BUILD))"

FORCE:

# --------------------------------------------------------------------------
# Compile rules
# --------------------------------------------------------------------------
$(OBJ_DIR)/src/%.o: src/%.c $(FLAGS_FILE) $(GEN_DIR)/version.h
	@mkdir -p $(@D)
	@echo "  CC    $<"
	@$(CC) $(BASE_CFLAGS) $(ANALYZER_FLAGS) -MMD -MP -c $< -o $@

$(OBJ_DIR)/tests/%.o: tests/%.c $(FLAGS_FILE) $(GEN_DIR)/version.h
	@mkdir -p $(@D)
	@echo "  CC    $<"
	@$(CC) $(BASE_CFLAGS) $(CMOCKA_CFLAGS) -Itests -MMD -MP -c $< -o $@

$(OBJ_DIR)/tools/%.o: tools/%.c $(FLAGS_FILE) $(GEN_DIR)/version.h
	@mkdir -p $(@D)
	@echo "  CC    $<"
	@$(CC) $(BASE_CFLAGS) -MMD -MP -c $< -o $@

INTEG_FLAGS := -Wno-unused-function -Wno-format-nonliteral
$(OBJ_DIR)/tests/integration/test_integration_core.o: GROUP := INTEGRATION_GROUP_CORE
$(OBJ_DIR)/tests/integration/test_integration_transport.o: GROUP := INTEGRATION_GROUP_TRANSPORT
$(OBJ_DIR)/tests/integration/test_integration_runtime.o: GROUP := INTEGRATION_GROUP_RUNTIME
$(OBJ_DIR)/tests/integration/test_integration_%.o: tests/integration/test_integration.c $(FLAGS_FILE) $(GEN_DIR)/version.h
	@mkdir -p $(@D)
	@echo "  CC    $< ($(GROUP))"
	@$(CC) $(BASE_CFLAGS) $(CMOCKA_CFLAGS) -Itests $(INTEG_FLAGS) -D$(GROUP) -MMD -MP -c $< -o $@

# --------------------------------------------------------------------------
# Link rules
# --------------------------------------------------------------------------
$(PROXY): $(OBJ_DIR)/src/main.o $(LIB_OBJS)
	@mkdir -p $(@D)
	@echo "  LD    $@"
	@$(CC) $(BASE_LDFLAGS) $^ $(LIBS) -o $@

$(TESTS_LIB:%=$(BIN_DIR)/%): $(BIN_DIR)/%: $(OBJ_DIR)/tests/unit/%.o $(LIB_OBJS)
	@mkdir -p $(@D)
	@echo "  LD    $@"
	@$(CC) $(BASE_LDFLAGS) $^ $(CMOCKA_LIBS) $(LIBS) -o $@

$(TESTS_AMALG:%=$(BIN_DIR)/%): $(BIN_DIR)/%: $(OBJ_DIR)/tests/unit/%.o $(ERR_OBJ)
	@mkdir -p $(@D)
	@echo "  LD    $@"
	@$(CC) $(BASE_LDFLAGS) $^ $(CMOCKA_LIBS) $(LIBS) -o $@

$(TESTS_SOLO:%=$(BIN_DIR)/%) $(TESTS_DOQ_NGTCP2:%=$(BIN_DIR)/%): $(BIN_DIR)/%: $(OBJ_DIR)/tests/unit/%.o
	@mkdir -p $(@D)
	@echo "  LD    $@"
	@$(CC) $(BASE_LDFLAGS) $^ $(CMOCKA_LIBS) $(LIBS) -o $@

$(TESTS_INTEG:%=$(BIN_DIR)/%): $(BIN_DIR)/%: $(OBJ_DIR)/tests/integration/%.o $(LIB_OBJS)
	@mkdir -p $(@D)
	@echo "  LD    $@"
	@$(CC) $(BASE_LDFLAGS) $^ $(CMOCKA_LIBS) $(LIBS) $(SSL_LIBS) -o $@

$(BIN_DIR)/cache_bench: $(OBJ_DIR)/tools/cache_bench.o $(LIB_OBJS)
	@mkdir -p $(@D)
	@echo "  LD    $@"
	@$(CC) $(BASE_LDFLAGS) $^ $(LIBS) -o $@

$(BIN_DIR)/e2e_proxy_bench: $(OBJ_DIR)/tools/e2e_proxy_bench.o
	@mkdir -p $(@D)
	@echo "  LD    $@"
	@$(CC) $(BASE_LDFLAGS) $^ $(CURL_LIBS) -o $@

# --------------------------------------------------------------------------
# Test runner
#
# Runs from the repo root so fixtures (tests/certs, tools/mock_*.py) resolve
# directly; the integration suite is told where this BIN_DIR's proxy is
# rather than guessing from its cwd.
# --------------------------------------------------------------------------
test: $(PROXY) $(TEST_BINS)
	@pass=0; fail=0; failed=''; \
	for t in $(ALL_TESTS); do \
	    printf '  TEST  %-40s ' "$$t"; \
	    if DNS_ENCRYPTED_PROXY_TEST_BIN='$(PROXY)' timeout $(TEST_TIMEOUT) '$(BIN_DIR)'/$$t > '$(OBJ_DIR)'/$$t.log 2>&1; then \
	        echo ok; pass=$$((pass + 1)); \
	    else \
	        echo "FAIL (exit $$?)"; fail=$$((fail + 1)); failed="$$failed $$t"; \
	        sed 's/^/        /' '$(OBJ_DIR)'/$$t.log; \
	    fi; \
	done; \
	echo "  $$pass passed, $$fail failed"; \
	[ $$fail -eq 0 ] || { echo "  failed:$$failed" >&2; exit 1; }

# --------------------------------------------------------------------------
# Coverage: run the suite under gcov, gate on line coverage, then write HTML.
# The gate runs first so a failing run leaves the previous report in place.
# --------------------------------------------------------------------------
GCOVR_ARGS := -r $(CURDIR) $(OBJ_DIR) --exclude $(CURDIR)/tests --exclude $(CURDIR)/tools \
	--merge-mode-functions merge-use-line-min \
	--gcov-ignore-parse-errors negative_hits.warn_once_per_file

coverage:
ifneq ($(BUILD),coverage)
	@$(MAKE) --no-print-directory BUILD=coverage coverage
else
	@find $(OBJ_DIR) -name '*.gcda' -delete 2>/dev/null || true
	@$(MAKE) --no-print-directory test
	gcovr $(GCOVR_ARGS) --fail-under-line $(COVERAGE_LINE_THRESHOLD) --print-summary
	gcovr $(GCOVR_ARGS) --html-details -o $(OBJ_DIR)/coverage.html
endif

# --------------------------------------------------------------------------
# Static analysis
#
# `analyze` builds everything with -fstack-usage and production code with
# -fanalyzer (any analyzer warning fails the build via -Werror), then gates on
# cppcheck and the per-frame stack limit. Tests are held to the stack limit
# too: a test frame that blows 64 KB is as much a bug as a production one.
# clang-tidy runs advisory; lint-strict gates.
# --------------------------------------------------------------------------
analyze:
ifneq ($(BUILD),analyze)
	@$(MAKE) --no-print-directory BUILD=analyze analyze
else
	@$(MAKE) --no-print-directory proxy tests
	@$(MAKE) --no-print-directory cppcheck
	@$(MAKE) --no-print-directory stack-usage
	@$(MAKE) --no-print-directory lint
endif

stack-usage:
ifneq ($(BUILD),analyze)
	@$(MAKE) --no-print-directory BUILD=analyze stack-usage
else
	@$(MAKE) --no-print-directory proxy tests
	tools/check_stack_usage.sh $(OBJ_DIR) $(STACK_USAGE_LIMIT)
endif

cppcheck: check-c-log
	cppcheck --enable=warning,performance,portability --error-exitcode=1 \
	    --inline-suppr --quiet \
	    --suppress=missingIncludeSystem --suppress=normalCheckLevelMaxBranches \
	    '--suppress=*:$(C_LOG_PATH)/*' --std=c11 \
	    -Isrc -I$(C_LOG_PATH) $(DEFINES) src

# compile_commands.json for clang-tidy and editors, generated from the exact
# flags this Makefile uses. -fanalyzer is GCC-only and clang-tidy's driver
# rejects it outright, so it is left out here rather than filtered later.
COMPDB := $(OBJ_DIR)/compile_commands.json
compdb: $(COMPDB)
$(COMPDB): $(FLAGS_FILE) $(GEN_DIR)/version.h Makefile
	@mkdir -p $(@D)
	@{ echo '['; sep=''; \
	   for f in $(PROD_SRCS); do \
	     printf '%s{"directory":"%s","file":"%s","command":"%s %s -c %s"}\n' \
	       "$$sep" '$(CURDIR)' "$$f" '$(CC)' '$(subst ",\",$(BASE_CFLAGS))' "$$f"; \
	     sep=','; \
	   done; echo ']'; } > $@
	@echo "  GEN   $@"

lint: $(COMPDB)
	tools/run_clang_tidy.sh advisory $(OBJ_DIR) $(PROD_SRCS)

lint-strict: $(COMPDB)
	tools/run_clang_tidy.sh strict $(OBJ_DIR) $(PROD_SRCS)

# --------------------------------------------------------------------------
clean:
	rm -rf $(OBJ_DIR)

distclean:
	rm -rf build

%.d: ;
-include $(shell find $(OBJ_DIR) -name '*.d' 2>/dev/null)
