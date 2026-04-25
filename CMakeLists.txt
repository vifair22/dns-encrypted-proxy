cmake_minimum_required(VERSION 3.10)
project(dns-encrypted-proxy C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

# All ready-to-run binaries (proxy, tests, benchmarks) land in build/bin/
# regardless of which build variant (release/debug/asan/coverage) was configured.
# Last variant built wins — this matches the "build/bin/ holds the binaries you run"
# convention; per-variant intermediates stay in their own build/<type>/ dir.
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/build/bin")

option(WARNINGS_AS_ERRORS "Treat compiler warnings as errors" ON)
option(ENABLE_COVERAGE "Enable gcov/gcovr coverage instrumentation" OFF)
option(ENABLE_UPSTREAM_DOH "Enable DoH upstream support" ON)
option(ENABLE_UPSTREAM_DOT "Enable DoT upstream support" ON)
option(ENABLE_UPSTREAM_DOQ "Enable DoQ upstream support" OFF)

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

set(PROJECT_WARNING_FLAGS -Wall -Wextra -Wpedantic)
if(WARNINGS_AS_ERRORS)
    list(APPEND PROJECT_WARNING_FLAGS -Werror)
endif()

set(COVERAGE_SUPPORTED FALSE)
if(ENABLE_COVERAGE)
    if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
        set(COVERAGE_SUPPORTED TRUE)
        message(STATUS "Coverage instrumentation enabled")
    else()
        message(WARNING "ENABLE_COVERAGE requested, but compiler '${CMAKE_C_COMPILER_ID}' is not supported for gcov-style coverage")
    endif()
endif()

function(apply_target_defaults target_name)
    target_compile_options(${target_name} PRIVATE ${PROJECT_WARNING_FLAGS})
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
        add_executable(test_cache_internal tests/unit/test_cache_internal.c)
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
        add_executable(test_dns_server_internal tests/unit/test_dns_server_internal.c)
        target_link_libraries(test_dns_server_internal ${CMOCKA_LIBRARIES} Threads::Threads)
        target_include_directories(test_dns_server_internal PRIVATE ${CMOCKA_INCLUDE_DIRS} ${CMAKE_CURRENT_SOURCE_DIR}/tests ${CMAKE_CURRENT_SOURCE_DIR}/src)
        apply_target_defaults(test_dns_server_internal)
        add_proxy_test(test_dns_server_internal)

        # Unit test: iterative resolver internals (parser/cache behavior)
        add_executable(test_iterative_resolver_internal tests/unit/test_iterative_resolver_internal.c)
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
            add_executable(test_upstream_doh_internal tests/unit/test_upstream_doh_internal.c)
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
            add_executable(test_upstream_dot_internal tests/unit/test_upstream_dot_internal.c)
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
        target_compile_options(test_integration_core PRIVATE -Wno-unused-function)
        target_link_libraries(test_integration_core dns_encrypted_proxy_lib ${CMOCKA_LIBRARIES} OpenSSL::SSL OpenSSL::Crypto)
        target_include_directories(test_integration_core PRIVATE ${CMOCKA_INCLUDE_DIRS} ${CMAKE_CURRENT_SOURCE_DIR}/tests)
        apply_target_defaults(test_integration_core)
        add_proxy_test(test_integration_core)

        add_executable(test_integration_transport tests/integration/test_integration.c)
        target_compile_definitions(test_integration_transport PRIVATE INTEGRATION_GROUP_TRANSPORT)
        target_compile_options(test_integration_transport PRIVATE -Wno-unused-function)
        target_link_libraries(test_integration_transport dns_encrypted_proxy_lib ${CMOCKA_LIBRARIES} OpenSSL::SSL OpenSSL::Crypto)
        target_include_directories(test_integration_transport PRIVATE ${CMOCKA_INCLUDE_DIRS} ${CMAKE_CURRENT_SOURCE_DIR}/tests)
        apply_target_defaults(test_integration_transport)
        add_proxy_test(test_integration_transport)

        add_executable(test_integration_runtime tests/integration/test_integration.c)
        target_compile_definitions(test_integration_runtime PRIVATE INTEGRATION_GROUP_RUNTIME)
        target_compile_options(test_integration_runtime PRIVATE -Wno-unused-function)
        target_link_libraries(test_integration_runtime dns_encrypted_proxy_lib ${CMOCKA_LIBRARIES} OpenSSL::SSL OpenSSL::Crypto)
        target_include_directories(test_integration_runtime PRIVATE ${CMOCKA_INCLUDE_DIRS} ${CMAKE_CURRENT_SOURCE_DIR}/tests)
        apply_target_defaults(test_integration_runtime)
        add_proxy_test(test_integration_runtime)

        if(ENABLE_COVERAGE AND COVERAGE_SUPPORTED)
            find_program(GCOVR_EXECUTABLE gcovr)
            if(GCOVR_EXECUTABLE)
                set(COVERAGE_TEST_DEPS
                    test_config test_cache test_cache_internal test_dns_message test_dns_message_internal test_upstream test_metrics_internal test_dns_server_internal test_iterative_resolver_internal test_upstream_bootstrap_internal test_upstream_internal test_upstream_dispatch_internal test_integration_core test_integration_transport test_integration_runtime)
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

                add_custom_target(coverage
                    COMMAND ${CMAKE_CTEST_COMMAND} --output-on-failure --timeout 30
                    COMMAND ${GCOVR_EXECUTABLE} -r ${CMAKE_SOURCE_DIR} ${CMAKE_BINARY_DIR} --exclude ${CMAKE_SOURCE_DIR}/tests --exclude ${CMAKE_SOURCE_DIR}/tools --merge-mode-functions merge-use-line-min --gcov-ignore-parse-errors negative_hits.warn_once_per_file --print-summary
                    COMMAND ${GCOVR_EXECUTABLE} -r ${CMAKE_SOURCE_DIR} ${CMAKE_BINARY_DIR} --exclude ${CMAKE_SOURCE_DIR}/tests --exclude ${CMAKE_SOURCE_DIR}/tools --merge-mode-functions merge-use-line-min --gcov-ignore-parse-errors negative_hits.warn_once_per_file --html-details -o ${CMAKE_BINARY_DIR}/coverage.html
                    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
                    USES_TERMINAL
                    DEPENDS dns-encrypted-proxy ${COVERAGE_TEST_DEPS}
                    COMMENT "Run tests and generate coverage report")
                message(STATUS "Coverage target available: cmake --build <build-dir> --target coverage")
            else()
                message(WARNING "gcovr not found; install gcovr to enable the 'coverage' target")
            endif()
        endif()
    else()
        message(WARNING "cmocka not found, tests will not be built. Install with: apt install libcmocka-dev")
    endif()
endif()
