cmake_minimum_required(VERSION 3.10)
project(dns-encrypted-proxy C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

# ---------------------------------------------------------------------------
# Version identity
#
# release_version holds the bumped-by-hand semver. The compile-time string
# "SEMVER_YYYYMMDD.HHMM.TYPE" is generated into a header that main.c includes
# so the binary can self-identify on --version and at startup.
# ---------------------------------------------------------------------------
file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/release_version" PROXY_VERSION_SEMVER LIMIT_COUNT 1)
if(NOT PROXY_VERSION_SEMVER)
    message(FATAL_ERROR "release_version file is empty or missing at ${CMAKE_CURRENT_SOURCE_DIR}/release_version")
endif()
string(STRIP "${PROXY_VERSION_SEMVER}" PROXY_VERSION_SEMVER)
string(TIMESTAMP PROXY_VERSION_TIMESTAMP "%Y%m%d.%H%M" UTC)

# All ready-to-run binaries (proxy, tests, benchmarks) land in build/bin/
# regardless of which build variant (release/debug/asan/coverage) was configured.
# Last variant built wins — this matches the "build/bin/ holds the binaries you run"
# convention; per-variant intermediates stay in their own build/<type>/ dir.
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/build/bin")

option(WARNINGS_AS_ERRORS "Treat compiler warnings as errors" ON)
option(ENABLE_COVERAGE "Enable gcov/gcovr coverage instrumentation" OFF)
option(ENABLE_ASAN "Enable AddressSanitizer instrumentation" OFF)
option(ENABLE_ANALYZER "Enable GCC -fanalyzer static analysis pass at compile time" OFF)
option(ENABLE_STACK_USAGE_CHECK "Emit per-TU stack-usage info (-fstack-usage) for the stack-usage target" OFF)
option(ENABLE_UPSTREAM_DOH "Enable DoH upstream support" ON)
option(ENABLE_UPSTREAM_DOT "Enable DoT upstream support" ON)
option(ENABLE_UPSTREAM_DOQ "Enable DoQ upstream support" OFF)

set(STACK_USAGE_LIMIT_BYTES 65536 CACHE STRING "Per-frame stack usage limit enforced by the stack-usage target (bytes)")
set(COVERAGE_LINE_THRESHOLD 80 CACHE STRING "Minimum line coverage % required by the coverage target (gcovr --fail-under-line)")

# Always emit compile_commands.json so clang-tidy/static analysis tools work
# without extra plumbing.
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Default to Release if no build type specified — matches "build what's needed,
# not what's trendy"; debug builds are explicitly opt-in via -DCMAKE_BUILD_TYPE=Debug
if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

# Per-build-type flags (override CMake defaults to match standards)
set(CMAKE_C_FLAGS_RELEASE        "-O3 -DNDEBUG"  CACHE STRING "" FORCE)
set(CMAKE_C_FLAGS_DEBUG          "-Og -g"        CACHE STRING "" FORCE)
set(CMAKE_C_FLAGS_RELWITHDEBINFO "-O2 -g -DNDEBUG" CACHE STRING "" FORCE)

# LTO for release builds (link-time optimization). CMake handles the
# compile/link flag dance via INTERPROCEDURAL_OPTIMIZATION rather than raw -flto
# so toolchains using gcc-ar/gcc-ranlib stay correct.
include(CheckIPOSupported)
check_ipo_supported(RESULT IPO_SUPPORTED OUTPUT IPO_ERROR)
if(IPO_SUPPORTED AND CMAKE_BUILD_TYPE STREQUAL "Release")
    set(CMAKE_INTERPROCEDURAL_OPTIMIZATION TRUE)
    message(STATUS "LTO enabled for Release build")
elseif(NOT IPO_SUPPORTED)
    message(STATUS "LTO unavailable: ${IPO_ERROR}")
endif()

set(C_LOG_PATH "${CMAKE_CURRENT_SOURCE_DIR}/../c-log" CACHE PATH "Path to c-log checkout")
set(C_LOG_HEADER_PATH "${C_LOG_PATH}/log.h")
if(NOT EXISTS "${C_LOG_HEADER_PATH}")
    message(FATAL_ERROR "c-log header not found at ${C_LOG_HEADER_PATH}. Set -DC_LOG_PATH=<path-to-c-log>")
endif()
set(C_LOG_INCLUDE_DIR "${C_LOG_PATH}")
message(STATUS "Using C-Log from ${C_LOG_INCLUDE_DIR}")

if(NOT ENABLE_UPSTREAM_DOH AND NOT ENABLE_UPSTREAM_DOT AND NOT ENABLE_UPSTREAM_DOQ)
    message(FATAL_ERROR "At least one upstream provider must be enabled")
endif()

set(PROJECT_WARNING_FLAGS
    -Wall -Wextra -Wpedantic
    -Wshadow
    -Wunused -Wunused-function -Wunused-variable -Wunused-parameter -Wunused-result
    -Wdouble-promotion
    -Wformat=2 -Wformat-truncation
    -Wmissing-prototypes -Wstrict-prototypes -Wmissing-declarations
    -Wcast-align -Wcast-qual
    -Wnull-dereference
    -Wconversion -Wsign-conversion)
if(WARNINGS_AS_ERRORS)
    list(APPEND PROJECT_WARNING_FLAGS -Werror)
endif()

# Stack hardening — applied to every target alongside warnings
set(PROJECT_HARDENING_FLAGS -fstack-protector-strong -fstack-clash-protection)

set(COVERAGE_SUPPORTED FALSE)
if(ENABLE_COVERAGE)
    if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
        set(COVERAGE_SUPPORTED TRUE)
        message(STATUS "Coverage instrumentation enabled")
    else()
        message(WARNING "ENABLE_COVERAGE requested, but compiler '${CMAKE_C_COMPILER_ID}' is not supported for gcov-style coverage")
    endif()
endif()

set(ASAN_SUPPORTED FALSE)
if(ENABLE_ASAN)
    if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
        set(ASAN_SUPPORTED TRUE)
        message(STATUS "AddressSanitizer instrumentation enabled")
    else()
        message(WARNING "ENABLE_ASAN requested, but compiler '${CMAKE_C_COMPILER_ID}' is not supported")
    endif()
endif()

set(ANALYZER_SUPPORTED FALSE)
if(ENABLE_ANALYZER)
    if(CMAKE_C_COMPILER_ID STREQUAL "GNU")
        set(ANALYZER_SUPPORTED TRUE)
        message(STATUS "GCC -fanalyzer enabled")
    else()
        message(WARNING "ENABLE_ANALYZER requested but only supported on GNU compiler (got '${CMAKE_C_COMPILER_ID}')")
    endif()
endif()

set(STACK_USAGE_SUPPORTED FALSE)
if(ENABLE_STACK_USAGE_CHECK)
    if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
        set(STACK_USAGE_SUPPORTED TRUE)
        message(STATUS "Per-TU stack usage emission enabled (limit: ${STACK_USAGE_LIMIT_BYTES} bytes)")
    else()
        message(WARNING "ENABLE_STACK_USAGE_CHECK requested but compiler '${CMAKE_C_COMPILER_ID}' is unsupported")
    endif()
endif()

# Determine the build-type tag for the version string. Sanitizer/coverage
# variants take precedence over the raw CMAKE_BUILD_TYPE since they're the
# more interesting fact about a binary you'd hand someone for triage.
if(ENABLE_ASAN AND ASAN_SUPPORTED)
    set(PROXY_VERSION_BUILD_TYPE "asan")
elseif(ENABLE_COVERAGE AND COVERAGE_SUPPORTED)
    set(PROXY_VERSION_BUILD_TYPE "coverage")
elseif(CMAKE_BUILD_TYPE)
    string(TOLOWER "${CMAKE_BUILD_TYPE}" PROXY_VERSION_BUILD_TYPE)
else()
    set(PROXY_VERSION_BUILD_TYPE "unknown")
endif()
set(PROXY_VERSION_FULL "${PROXY_VERSION_SEMVER}_${PROXY_VERSION_TIMESTAMP}.${PROXY_VERSION_BUILD_TYPE}")
configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/src/version.h.in"
    "${CMAKE_CURRENT_BINARY_DIR}/generated/version.h"
    @ONLY)
message(STATUS "Version: ${PROXY_VERSION_FULL}")

function(apply_target_defaults target_name)
    target_compile_options(${target_name} PRIVATE
        ${PROJECT_WARNING_FLAGS}
        ${PROJECT_HARDENING_FLAGS})
    target_compile_definitions(${target_name} PRIVATE
        UPSTREAM_DOH_ENABLED=$<BOOL:${ENABLE_UPSTREAM_DOH}>
        UPSTREAM_DOT_ENABLED=$<BOOL:${ENABLE_UPSTREAM_DOT}>
        UPSTREAM_DOQ_ENABLED=$<BOOL:${ENABLE_UPSTREAM_DOQ}>)

    target_include_directories(${target_name} PRIVATE ${C_LOG_INCLUDE_DIR})

    if(ENABLE_COVERAGE AND COVERAGE_SUPPORTED)
        target_compile_options(${target_name} PRIVATE -O0 -g --coverage)
        if(CMAKE_VERSION VERSION_LESS 3.13)
            target_link_libraries(${target_name} PRIVATE --coverage)
        else()
            target_link_options(${target_name} PRIVATE --coverage)
        endif()
    endif()

    if(ENABLE_ASAN AND ASAN_SUPPORTED)
        target_compile_options(${target_name} PRIVATE
            -fsanitize=address -fno-omit-frame-pointer)
        if(CMAKE_VERSION VERSION_LESS 3.13)
            target_link_libraries(${target_name} PRIVATE -fsanitize=address)
        else()
            target_link_options(${target_name} PRIVATE -fsanitize=address)
        endif()
    endif()

    if(ENABLE_ANALYZER AND ANALYZER_SUPPORTED)
        # -fanalyzer chokes on the patterns test code uses (intentional NULL
        # paths, fault-injected fd states, internal-include amalgamation).
        # Restrict it to production targets.
        if(NOT ${target_name} MATCHES "^test_")
            target_compile_options(${target_name} PRIVATE -fanalyzer)
        endif()
    endif()

    if(ENABLE_STACK_USAGE_CHECK AND STACK_USAGE_SUPPORTED)
        target_compile_options(${target_name} PRIVATE -fstack-usage)
    endif()
endfunction()

function(add_proxy_test test_name)
    add_test(NAME ${test_name} COMMAND ${test_name})
    set_tests_properties(${test_name} PROPERTIES TIMEOUT 30)
endfunction()

find_package(Threads REQUIRED)
if(ENABLE_UPSTREAM_DOH)
    find_package(CURL REQUIRED)
endif()
if(ENABLE_UPSTREAM_DOT OR ENABLE_UPSTREAM_DOQ)
    find_package(OpenSSL REQUIRED)
endif()

set(DOQ_NGTCP2_LIBS)
if(ENABLE_UPSTREAM_DOQ)
    if(NOT PkgConfig_FOUND)
        find_package(PkgConfig REQUIRED)
    endif()

    # Distros vary in pkg-config module naming: some use ngtcp2/*, others
    # libngtcp2/*. Try both so setup is portable.
    pkg_check_modules(NGTCP2 QUIET IMPORTED_TARGET ngtcp2)
    if(NOT NGTCP2_FOUND)
        pkg_check_modules(NGTCP2 QUIET IMPORTED_TARGET libngtcp2)
    endif()

    pkg_check_modules(NGTCP2_CRYPTO QUIET IMPORTED_TARGET ngtcp2_crypto_openssl)
    if(NOT NGTCP2_CRYPTO_FOUND)
        pkg_check_modules(NGTCP2_CRYPTO QUIET IMPORTED_TARGET libngtcp2_crypto_openssl)
    endif()
    if(NOT NGTCP2_CRYPTO_FOUND)
        pkg_check_modules(NGTCP2_CRYPTO QUIET IMPORTED_TARGET ngtcp2_crypto_ossl)
    endif()
    if(NOT NGTCP2_CRYPTO_FOUND)
        pkg_check_modules(NGTCP2_CRYPTO QUIET IMPORTED_TARGET libngtcp2_crypto_ossl)
    endif()
    if(NOT NGTCP2_CRYPTO_FOUND)
        pkg_check_modules(NGTCP2_CRYPTO QUIET IMPORTED_TARGET ngtcp2_crypto_quictls)
    endif()
    if(NOT NGTCP2_CRYPTO_FOUND)
        pkg_check_modules(NGTCP2_CRYPTO QUIET IMPORTED_TARGET libngtcp2_crypto_quictls)
    endif()

    if(NOT NGTCP2_FOUND)
        message(FATAL_ERROR "ENABLE_UPSTREAM_DOQ=ON requires ngtcp2 dev pkg-config module (ngtcp2 or libngtcp2)")
    endif()
    if(NOT NGTCP2_CRYPTO_FOUND)
        message(FATAL_ERROR "ENABLE_UPSTREAM_DOQ=ON requires an ngtcp2 OpenSSL-family crypto module (ngtcp2/libngtcp2 crypto_openssl, crypto_ossl, or crypto_quictls)")
    endif()

    list(APPEND DOQ_NGTCP2_LIBS PkgConfig::NGTCP2 PkgConfig::NGTCP2_CRYPTO)
endif()

set(DNS_ENCRYPTED_PROXY_SOURCES
    src/errors.c
    src/config.c
    src/cache.c
    src/dns_message.c
    src/logger.c
    src/iterative_resolver.c
    src/upstream_bootstrap.c
    src/upstream_dispatch.c
    src/upstream.c
    src/dns_server.c
    src/metrics.c
)

if(ENABLE_UPSTREAM_DOH)
    list(APPEND DNS_ENCRYPTED_PROXY_SOURCES src/upstream_doh.c)
endif()
if(ENABLE_UPSTREAM_DOT)
    list(APPEND DNS_ENCRYPTED_PROXY_SOURCES src/upstream_dot.c)
endif()
if(ENABLE_UPSTREAM_DOQ)
    list(APPEND DNS_ENCRYPTED_PROXY_SOURCES src/upstream_doq.c)
    list(APPEND DNS_ENCRYPTED_PROXY_SOURCES src/upstream_doq_ngtcp2.c)
endif()

set(DNS_ENCRYPTED_PROXY_LIBS Threads::Threads)
if(ENABLE_UPSTREAM_DOH)
    list(APPEND DNS_ENCRYPTED_PROXY_LIBS CURL::libcurl)
endif()
if(ENABLE_UPSTREAM_DOT)
    list(APPEND DNS_ENCRYPTED_PROXY_LIBS OpenSSL::SSL OpenSSL::Crypto)
endif()
if(ENABLE_UPSTREAM_DOQ)
    list(APPEND DNS_ENCRYPTED_PROXY_LIBS OpenSSL::SSL OpenSSL::Crypto)
    list(APPEND DNS_ENCRYPTED_PROXY_LIBS ${DOQ_NGTCP2_LIBS})
endif()

# Core library (everything except main.c) for linking tests
add_library(dns_encrypted_proxy_lib STATIC ${DNS_ENCRYPTED_PROXY_SOURCES})
target_include_directories(dns_encrypted_proxy_lib PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(dns_encrypted_proxy_lib PUBLIC ${DNS_ENCRYPTED_PROXY_LIBS})
apply_target_defaults(dns_encrypted_proxy_lib)

# Main executable
add_executable(dns-encrypted-proxy src/main.c)
target_link_libraries(dns-encrypted-proxy PRIVATE dns_encrypted_proxy_lib)
target_include_directories(dns-encrypted-proxy PRIVATE ${CMAKE_CURRENT_BINARY_DIR}/generated)
apply_target_defaults(dns-encrypted-proxy)

# Benchmark utility
option(BUILD_BENCHMARKS "Build benchmark utilities" ON)
if(BUILD_BENCHMARKS)
    add_executable(cache_bench tools/cache_bench.c)
    target_link_libraries(cache_bench PRIVATE dns_encrypted_proxy_lib)
    target_include_directories(cache_bench PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
    apply_target_defaults(cache_bench)

    add_executable(e2e_proxy_bench tools/e2e_proxy_bench.c)
    target_link_libraries(e2e_proxy_bench PRIVATE Threads::Threads CURL::libcurl)
    apply_target_defaults(e2e_proxy_bench)
endif()

# Testing support
option(BUILD_TESTS "Build test suite" ON)

if(BUILD_TESTS)
    enable_testing()
    
    # Find cmocka - try pkg-config first, then cmake config
    find_package(PkgConfig QUIET)
    if(PkgConfig_FOUND)
        pkg_check_modules(CMOCKA cmocka)
    endif()
    
    if(NOT CMOCKA_FOUND)
        find_package(cmocka QUIET)
        if(cmocka_FOUND)
            set(CMOCKA_FOUND TRUE)
            set(CMOCKA_LIBRARIES cmocka::cmocka)
        endif()
    endif()
    
    if(CMOCKA_FOUND)
        message(STATUS "cmocka found, building tests")
        find_package(OpenSSL REQUIRED)
        
        # Unit test: errors infrastructure (thread-local buffer + macros)
        add_executable(test_errors tests/unit/test_errors.c)
        target_link_libraries(test_errors dns_encrypted_proxy_lib ${CMOCKA_LIBRARIES} Threads::Threads)
        target_include_directories(test_errors PRIVATE ${CMOCKA_INCLUDE_DIRS} ${CMAKE_CURRENT_SOURCE_DIR}/tests ${CMAKE_CURRENT_SOURCE_DIR}/src)
        apply_target_defaults(test_errors)
        add_proxy_test(test_errors)

        # Unit test: config
        add_executable(test_config tests/unit/test_config.c)
        target_link_libraries(test_config dns_encrypted_proxy_lib ${CMOCKA_LIBRARIES})
        target_include_directories(test_config PRIVATE ${CMOCKA_INCLUDE_DIRS} ${CMAKE_CURRENT_SOURCE_DIR}/tests)
        apply_target_defaults(test_config)
        add_proxy_test(test_config)
        
        # Unit test: cache
        add_executable(test_cache tests/unit/test_cache.c)
        target_link_libraries(test_cache dns_encrypted_proxy_lib ${CMOCKA_LIBRARIES})
        target_include_directories(test_cache PRIVATE ${CMOCKA_INCLUDE_DIRS} ${CMAKE_CURRENT_SOURCE_DIR}/tests)
        apply_target_defaults(test_cache)
        add_proxy_test(test_cache)

        # Unit test: cache internals
        # Amalgamates src/cache.c via #include; pulls in src/errors.c too
        # because cache.c now uses set_error() macros that need
        # proxy_set_error_impl from errors.c.
        add_executable(test_cache_internal tests/unit/test_cache_internal.c src/errors.c)
        target_link_libraries(test_cache_internal ${CMOCKA_LIBRARIES} Threads::Threads)
        target_include_directories(test_cache_internal PRIVATE ${CMOCKA_INCLUDE_DIRS} ${CMAKE_CURRENT_SOURCE_DIR}/tests ${CMAKE_CURRENT_SOURCE_DIR}/src)
        apply_target_defaults(test_cache_internal)
        add_proxy_test(test_cache_internal)
        
        # Unit test: dns_message
        add_executable(test_dns_message tests/unit/test_dns_message.c)
        target_link_libraries(test_dns_message dns_encrypted_proxy_lib ${CMOCKA_LIBRARIES})
        target_include_directories(test_dns_message PRIVATE ${CMOCKA_INCLUDE_DIRS} ${CMAKE_CURRENT_SOURCE_DIR}/tests)
        apply_target_defaults(test_dns_message)
        add_proxy_test(test_dns_message)

        # Unit test: dns_message internals
        add_executable(test_dns_message_internal tests/unit/test_dns_message_internal.c)
        target_link_libraries(test_dns_message_internal ${CMOCKA_LIBRARIES})
        target_include_directories(test_dns_message_internal PRIVATE ${CMOCKA_INCLUDE_DIRS} ${CMAKE_CURRENT_SOURCE_DIR}/tests ${CMAKE_CURRENT_SOURCE_DIR}/src)
        apply_target_defaults(test_dns_message_internal)
        add_proxy_test(test_dns_message_internal)

        # Unit test: upstream
        add_executable(test_upstream tests/unit/test_upstream.c)
        target_link_libraries(test_upstream dns_encrypted_proxy_lib ${CMOCKA_LIBRARIES})
        target_include_directories(test_upstream PRIVATE ${CMOCKA_INCLUDE_DIRS} ${CMAKE_CURRENT_SOURCE_DIR}/tests)
        apply_target_defaults(test_upstream)
        add_proxy_test(test_upstream)

        # Unit test: metrics internals (static helper branch coverage)
        add_executable(test_metrics_internal tests/unit/test_metrics_internal.c)
        target_link_libraries(test_metrics_internal ${CMOCKA_LIBRARIES} Threads::Threads)
        target_include_directories(test_metrics_internal PRIVATE ${CMOCKA_INCLUDE_DIRS} ${CMAKE_CURRENT_SOURCE_DIR}/tests ${CMAKE_CURRENT_SOURCE_DIR}/src)
        apply_target_defaults(test_metrics_internal)
        add_proxy_test(test_metrics_internal)

        # Unit test: dns_server internals (static helper branch coverage)
        # Amalgamates src/dns_server.c via #include; pulls in src/errors.c
        # because dns_server.c now reads proxy_error_message() when
        # dns_cache_init returns non-PROXY_OK.
        add_executable(test_dns_server_internal tests/unit/test_dns_server_internal.c src/errors.c)
        target_link_libraries(test_dns_server_internal ${CMOCKA_LIBRARIES} Threads::Threads)
        target_include_directories(test_dns_server_internal PRIVATE ${CMOCKA_INCLUDE_DIRS} ${CMAKE_CURRENT_SOURCE_DIR}/tests ${CMAKE_CURRENT_SOURCE_DIR}/src)
        apply_target_defaults(test_dns_server_internal)
        add_proxy_test(test_dns_server_internal)

        # Unit test: iterative resolver internals (parser/cache behavior)
        # Amalgamates src/iterative_resolver.c via #include; pulls in
        # src/errors.c because iterative_resolve_a now uses set_error.
        add_executable(test_iterative_resolver_internal tests/unit/test_iterative_resolver_internal.c src/errors.c)
        target_link_libraries(test_iterative_resolver_internal ${CMOCKA_LIBRARIES} Threads::Threads)
        target_include_directories(test_iterative_resolver_internal PRIVATE ${CMOCKA_INCLUDE_DIRS} ${CMAKE_CURRENT_SOURCE_DIR}/tests ${CMAKE_CURRENT_SOURCE_DIR}/src)
        apply_target_defaults(test_iterative_resolver_internal)
        add_proxy_test(test_iterative_resolver_internal)

        # Unit test: upstream bootstrap internals (config apply + stage3)
        add_executable(test_upstream_bootstrap_internal tests/unit/test_upstream_bootstrap_internal.c)
        target_link_libraries(test_upstream_bootstrap_internal ${CMOCKA_LIBRARIES} Threads::Threads)
        target_include_directories(test_upstream_bootstrap_internal PRIVATE ${CMOCKA_INCLUDE_DIRS} ${CMAKE_CURRENT_SOURCE_DIR}/tests ${CMAKE_CURRENT_SOURCE_DIR}/src)
        apply_target_defaults(test_upstream_bootstrap_internal)
        add_proxy_test(test_upstream_bootstrap_internal)

        if(ENABLE_UPSTREAM_DOH)
            # Unit test: upstream DoH internals (static helper branch coverage)
            # Amalgamates src/upstream_doh.c via #include; pulls in src/errors.c
            # because upstream_doh_client_init now uses set_error.
            add_executable(test_upstream_doh_internal tests/unit/test_upstream_doh_internal.c src/errors.c)
            target_link_libraries(test_upstream_doh_internal ${CMOCKA_LIBRARIES} Threads::Threads)
            target_include_directories(test_upstream_doh_internal PRIVATE ${CMOCKA_INCLUDE_DIRS} ${CMAKE_CURRENT_SOURCE_DIR}/tests ${CMAKE_CURRENT_SOURCE_DIR}/src)
            apply_target_defaults(test_upstream_doh_internal)
            add_proxy_test(test_upstream_doh_internal)
        endif()

        # Unit test: upstream orchestrator internals (static/helper branch coverage)
        add_executable(test_upstream_internal tests/unit/test_upstream_internal.c)
        target_link_libraries(test_upstream_internal ${CMOCKA_LIBRARIES} Threads::Threads)
        target_include_directories(test_upstream_internal PRIVATE ${CMOCKA_INCLUDE_DIRS} ${CMAKE_CURRENT_SOURCE_DIR}/tests ${CMAKE_CURRENT_SOURCE_DIR}/src)
        apply_target_defaults(test_upstream_internal)
        add_proxy_test(test_upstream_internal)

        add_executable(test_upstream_dispatch_internal tests/unit/test_upstream_dispatch_internal.c)
        target_link_libraries(test_upstream_dispatch_internal ${CMOCKA_LIBRARIES} Threads::Threads)
        target_include_directories(test_upstream_dispatch_internal PRIVATE ${CMOCKA_INCLUDE_DIRS} ${CMAKE_CURRENT_SOURCE_DIR}/tests ${CMAKE_CURRENT_SOURCE_DIR}/src)
        apply_target_defaults(test_upstream_dispatch_internal)
        add_proxy_test(test_upstream_dispatch_internal)

        if(ENABLE_UPSTREAM_DOT)
            # Unit test: upstream DoT internals (static helper branch coverage)
            # Amalgamates src/upstream_dot.c via #include; pulls in src/errors.c
            # because upstream_dot_client_init now uses set_error.
            add_executable(test_upstream_dot_internal tests/unit/test_upstream_dot_internal.c src/errors.c)
            target_link_libraries(test_upstream_dot_internal ${CMOCKA_LIBRARIES} Threads::Threads)
            target_include_directories(test_upstream_dot_internal PRIVATE ${CMOCKA_INCLUDE_DIRS} ${CMAKE_CURRENT_SOURCE_DIR}/tests ${CMAKE_CURRENT_SOURCE_DIR}/src)
            apply_target_defaults(test_upstream_dot_internal)
            add_proxy_test(test_upstream_dot_internal)
        endif()

        if(ENABLE_UPSTREAM_DOQ)
            # Unit test: upstream DoQ internals (validation and backend handoff)
            add_executable(test_upstream_doq_internal tests/unit/test_upstream_doq_internal.c)
            target_link_libraries(test_upstream_doq_internal ${CMOCKA_LIBRARIES} Threads::Threads)
            target_include_directories(test_upstream_doq_internal PRIVATE ${CMOCKA_INCLUDE_DIRS} ${CMAKE_CURRENT_SOURCE_DIR}/tests ${CMAKE_CURRENT_SOURCE_DIR}/src)
            apply_target_defaults(test_upstream_doq_internal)
            add_proxy_test(test_upstream_doq_internal)

            # Unit test: ngtcp2 DoQ helpers (stream framing/guards)
            add_executable(test_upstream_doq_ngtcp2_internal tests/unit/test_upstream_doq_ngtcp2_internal.c)
            target_link_libraries(test_upstream_doq_ngtcp2_internal ${CMOCKA_LIBRARIES} Threads::Threads ${DNS_ENCRYPTED_PROXY_LIBS})
            target_include_directories(test_upstream_doq_ngtcp2_internal PRIVATE ${CMOCKA_INCLUDE_DIRS} ${CMAKE_CURRENT_SOURCE_DIR}/tests ${CMAKE_CURRENT_SOURCE_DIR}/src)
            apply_target_defaults(test_upstream_doq_ngtcp2_internal)
            add_proxy_test(test_upstream_doq_ngtcp2_internal)
        endif()
        
        # Integration tests (split by functional boundary)
        add_executable(test_integration_core tests/integration/test_integration.c)
        target_compile_definitions(test_integration_core PRIVATE INTEGRATION_GROUP_CORE)
        target_link_libraries(test_integration_core dns_encrypted_proxy_lib ${CMOCKA_LIBRARIES} OpenSSL::SSL OpenSSL::Crypto)
        target_include_directories(test_integration_core PRIVATE ${CMOCKA_INCLUDE_DIRS} ${CMAKE_CURRENT_SOURCE_DIR}/tests)
        apply_target_defaults(test_integration_core)
        # Group split: each group only exercises a subset of test functions; the rest
        # are intentionally inert. Suppress -Wunused-function and -Wformat-nonliteral
        # (used by group-aware vasprintf-style helpers).
        target_compile_options(test_integration_core PRIVATE -Wno-unused-function -Wno-format-nonliteral)
        add_proxy_test(test_integration_core)

        add_executable(test_integration_transport tests/integration/test_integration.c)
        target_compile_definitions(test_integration_transport PRIVATE INTEGRATION_GROUP_TRANSPORT)
        target_link_libraries(test_integration_transport dns_encrypted_proxy_lib ${CMOCKA_LIBRARIES} OpenSSL::SSL OpenSSL::Crypto)
        target_include_directories(test_integration_transport PRIVATE ${CMOCKA_INCLUDE_DIRS} ${CMAKE_CURRENT_SOURCE_DIR}/tests)
        apply_target_defaults(test_integration_transport)
        target_compile_options(test_integration_transport PRIVATE -Wno-unused-function -Wno-format-nonliteral)
        add_proxy_test(test_integration_transport)

        add_executable(test_integration_runtime tests/integration/test_integration.c)
        target_compile_definitions(test_integration_runtime PRIVATE INTEGRATION_GROUP_RUNTIME)
        target_link_libraries(test_integration_runtime dns_encrypted_proxy_lib ${CMOCKA_LIBRARIES} OpenSSL::SSL OpenSSL::Crypto)
        target_include_directories(test_integration_runtime PRIVATE ${CMOCKA_INCLUDE_DIRS} ${CMAKE_CURRENT_SOURCE_DIR}/tests)
        apply_target_defaults(test_integration_runtime)
        target_compile_options(test_integration_runtime PRIVATE -Wno-unused-function -Wno-format-nonliteral)
        add_proxy_test(test_integration_runtime)

        if(ENABLE_COVERAGE AND COVERAGE_SUPPORTED)
            find_program(GCOVR_EXECUTABLE gcovr)
            if(GCOVR_EXECUTABLE)
                set(COVERAGE_TEST_DEPS
                    test_errors test_config test_cache test_cache_internal test_dns_message test_dns_message_internal test_upstream test_metrics_internal test_dns_server_internal test_iterative_resolver_internal test_upstream_bootstrap_internal test_upstream_internal test_upstream_dispatch_internal test_integration_core test_integration_transport test_integration_runtime)
                if(ENABLE_UPSTREAM_DOH)
                    list(APPEND COVERAGE_TEST_DEPS test_upstream_doh_internal)
                endif()
                if(ENABLE_UPSTREAM_DOT)
                    list(APPEND COVERAGE_TEST_DEPS test_upstream_dot_internal)
                endif()
                if(ENABLE_UPSTREAM_DOQ)
                    list(APPEND COVERAGE_TEST_DEPS test_upstream_doq_internal)
                    list(APPEND COVERAGE_TEST_DEPS test_upstream_doq_ngtcp2_internal)
                endif()

                # Two gcovr passes: the first prints the per-file table and
                # gates on the line-coverage threshold; the second emits the
                # browsable HTML report. Failing the gate aborts before the
                # HTML is regenerated, so the previous report is preserved
                # for triage.
                add_custom_target(coverage
                    COMMAND ${CMAKE_CTEST_COMMAND} --output-on-failure --timeout 30
                    COMMAND ${GCOVR_EXECUTABLE} -r ${CMAKE_SOURCE_DIR} ${CMAKE_BINARY_DIR} --exclude ${CMAKE_SOURCE_DIR}/tests --exclude ${CMAKE_SOURCE_DIR}/tools --merge-mode-functions merge-use-line-min --gcov-ignore-parse-errors negative_hits.warn_once_per_file --fail-under-line ${COVERAGE_LINE_THRESHOLD} --print-summary
                    COMMAND ${GCOVR_EXECUTABLE} -r ${CMAKE_SOURCE_DIR} ${CMAKE_BINARY_DIR} --exclude ${CMAKE_SOURCE_DIR}/tests --exclude ${CMAKE_SOURCE_DIR}/tools --merge-mode-functions merge-use-line-min --gcov-ignore-parse-errors negative_hits.warn_once_per_file --html-details -o ${CMAKE_BINARY_DIR}/coverage.html
                    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
                    USES_TERMINAL
                    DEPENDS dns-encrypted-proxy ${COVERAGE_TEST_DEPS}
                    COMMENT "Run tests and generate coverage report (gates at ${COVERAGE_LINE_THRESHOLD}% lines)")
                message(STATUS "Coverage target available (line threshold: ${COVERAGE_LINE_THRESHOLD}%): cmake --build <build-dir> --target coverage")
            else()
                message(WARNING "gcovr not found; install gcovr to enable the 'coverage' target")
            endif()
        endif()
    else()
        message(WARNING "cmocka not found, tests will not be built. Install with: apt install libcmocka-dev")
    endif()
endif()

# ---------------------------------------------------------------------------
# Static analysis & lint targets
#
# All three are best-effort: if the underlying tool isn't installed, the
# corresponding target is skipped with a status message rather than failing
# configure. CI is expected to install the tools and invoke the targets.
# ---------------------------------------------------------------------------

set(LINTABLE_SOURCES ${DNS_ENCRYPTED_PROXY_SOURCES} src/main.c)

find_program(CLANG_TIDY_EXECUTABLE clang-tidy)
if(CLANG_TIDY_EXECUTABLE)
    # 'lint' is advisory — clang-tidy >= 18 returns non-zero on any finding,
    # which would block CI on the existing backlog. 'lint-strict' is the
    # gating variant for use after the backlog is cleared.
    add_custom_target(lint
        COMMAND ${CMAKE_SOURCE_DIR}/tools/run_clang_tidy.sh advisory ${CMAKE_BINARY_DIR} ${LINTABLE_SOURCES}
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
        COMMENT "Running clang-tidy over project sources (advisory)"
        VERBATIM)
    add_custom_target(lint-strict
        COMMAND ${CMAKE_SOURCE_DIR}/tools/run_clang_tidy.sh strict ${CMAKE_BINARY_DIR} ${LINTABLE_SOURCES}
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
        COMMENT "Running clang-tidy strictly (non-zero exit on any finding)"
        VERBATIM)
    message(STATUS "lint target available (${CLANG_TIDY_EXECUTABLE}); lint-strict gates on findings")
else()
    message(STATUS "clang-tidy not found; 'lint' target unavailable")
endif()

find_program(CPPCHECK_EXECUTABLE cppcheck)
if(CPPCHECK_EXECUTABLE)
    # We don't analyse the external c-log header; cppcheck doesn't model
    # localtime_s correctly and produces a false uninitvar there. Suppress
    # noisy 'normalCheckLevelMaxBranches' info messages too — they're
    # advisories about analysis depth, not findings.
    add_custom_target(cppcheck
        COMMAND ${CPPCHECK_EXECUTABLE}
                --enable=warning,performance,portability
                --error-exitcode=1
                --inline-suppr
                --quiet
                --suppress=missingIncludeSystem
                --suppress=normalCheckLevelMaxBranches
                --suppress=*:${C_LOG_INCLUDE_DIR}/*
                --std=c11
                -I${CMAKE_SOURCE_DIR}/src
                -I${C_LOG_INCLUDE_DIR}
                ${CMAKE_SOURCE_DIR}/src
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
        COMMENT "Running cppcheck over src/"
        VERBATIM)
    message(STATUS "cppcheck target available (${CPPCHECK_EXECUTABLE})")
else()
    message(STATUS "cppcheck not found; 'cppcheck' target unavailable")
endif()

if(ENABLE_STACK_USAGE_CHECK AND STACK_USAGE_SUPPORTED)
    add_custom_target(stack-usage
        COMMAND ${CMAKE_SOURCE_DIR}/tools/check_stack_usage.sh
                ${CMAKE_BINARY_DIR}
                ${STACK_USAGE_LIMIT_BYTES}
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
        DEPENDS dns_encrypted_proxy_lib dns-encrypted-proxy
        COMMENT "Verifying every function frame fits under ${STACK_USAGE_LIMIT_BYTES} bytes"
        VERBATIM)
    message(STATUS "stack-usage target available (limit: ${STACK_USAGE_LIMIT_BYTES} bytes)")
endif()

# Umbrella target: run everything that's available. Each sub-target either
# runs or is a no-op if the tool wasn't found at configure time.
set(ANALYZE_DEPENDS)
if(CLANG_TIDY_EXECUTABLE)
    list(APPEND ANALYZE_DEPENDS lint)
endif()
if(CPPCHECK_EXECUTABLE)
    list(APPEND ANALYZE_DEPENDS cppcheck)
endif()
if(ENABLE_STACK_USAGE_CHECK AND STACK_USAGE_SUPPORTED)
    list(APPEND ANALYZE_DEPENDS stack-usage)
endif()
if(ANALYZE_DEPENDS)
    add_custom_target(analyze DEPENDS ${ANALYZE_DEPENDS}
        COMMENT "Running all available static analysis targets")
endif()
