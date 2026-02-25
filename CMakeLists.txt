cmake_minimum_required(VERSION 3.10)
project(DOH-Proxy C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

option(WARNINGS_AS_ERRORS "Treat compiler warnings as errors" OFF)
option(ENABLE_COVERAGE "Enable gcov/gcovr coverage instrumentation" OFF)

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

    if(ENABLE_COVERAGE AND COVERAGE_SUPPORTED)
        target_compile_options(${target_name} PRIVATE -O0 -g --coverage)
        if(CMAKE_VERSION VERSION_LESS 3.13)
            target_link_libraries(${target_name} PRIVATE --coverage)
        else()
            target_link_options(${target_name} PRIVATE --coverage)
        endif()
    endif()
endfunction()

find_package(CURL REQUIRED)
find_package(Threads REQUIRED)
find_package(OpenSSL REQUIRED)

# Core library (everything except main.c) for linking tests
add_library(doh_proxy_lib STATIC
    src/config.c
    src/cache.c
    src/dns_message.c
    src/upstream.c
    src/upstream_doh.c
    src/upstream_dot.c
    src/dns_server.c
    src/metrics.c
)
target_include_directories(doh_proxy_lib PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(doh_proxy_lib PUBLIC CURL::libcurl Threads::Threads OpenSSL::SSL OpenSSL::Crypto)
apply_target_defaults(doh_proxy_lib)

# Main executable
add_executable(DOH-Proxy src/main.c)
target_link_libraries(DOH-Proxy PRIVATE doh_proxy_lib)
apply_target_defaults(DOH-Proxy)

# Benchmark utility
option(BUILD_BENCHMARKS "Build benchmark utilities" ON)
if(BUILD_BENCHMARKS)
    add_executable(cache_bench tools/cache_bench.c)
    target_link_libraries(cache_bench PRIVATE doh_proxy_lib)
    target_include_directories(cache_bench PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
    apply_target_defaults(cache_bench)
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
        
        # Unit test: config
        add_executable(test_config tests/unit/test_config.c)
        target_link_libraries(test_config doh_proxy_lib ${CMOCKA_LIBRARIES})
        target_include_directories(test_config PRIVATE ${CMOCKA_INCLUDE_DIRS} ${CMAKE_CURRENT_SOURCE_DIR}/tests)
        apply_target_defaults(test_config)
        add_test(NAME test_config COMMAND test_config)
        
        # Unit test: cache
        add_executable(test_cache tests/unit/test_cache.c)
        target_link_libraries(test_cache doh_proxy_lib ${CMOCKA_LIBRARIES})
        target_include_directories(test_cache PRIVATE ${CMOCKA_INCLUDE_DIRS} ${CMAKE_CURRENT_SOURCE_DIR}/tests)
        apply_target_defaults(test_cache)
        add_test(NAME test_cache COMMAND test_cache)
        
        # Unit test: dns_message
        add_executable(test_dns_message tests/unit/test_dns_message.c)
        target_link_libraries(test_dns_message doh_proxy_lib ${CMOCKA_LIBRARIES})
        target_include_directories(test_dns_message PRIVATE ${CMOCKA_INCLUDE_DIRS} ${CMAKE_CURRENT_SOURCE_DIR}/tests)
        apply_target_defaults(test_dns_message)
        add_test(NAME test_dns_message COMMAND test_dns_message)

        # Unit test: upstream
        add_executable(test_upstream tests/unit/test_upstream.c)
        target_link_libraries(test_upstream doh_proxy_lib ${CMOCKA_LIBRARIES})
        target_include_directories(test_upstream PRIVATE ${CMOCKA_INCLUDE_DIRS} ${CMAKE_CURRENT_SOURCE_DIR}/tests)
        apply_target_defaults(test_upstream)
        add_test(NAME test_upstream COMMAND test_upstream)
        
        # Integration tests (split by functional boundary)
        add_executable(test_integration_core tests/integration/test_integration.c)
        target_compile_definitions(test_integration_core PRIVATE INTEGRATION_GROUP_CORE)
        target_compile_options(test_integration_core PRIVATE -Wno-unused-function)
        target_link_libraries(test_integration_core doh_proxy_lib ${CMOCKA_LIBRARIES})
        target_include_directories(test_integration_core PRIVATE ${CMOCKA_INCLUDE_DIRS} ${CMAKE_CURRENT_SOURCE_DIR}/tests)
        apply_target_defaults(test_integration_core)
        add_test(NAME test_integration_core COMMAND test_integration_core)

        add_executable(test_integration_transport tests/integration/test_integration.c)
        target_compile_definitions(test_integration_transport PRIVATE INTEGRATION_GROUP_TRANSPORT)
        target_compile_options(test_integration_transport PRIVATE -Wno-unused-function)
        target_link_libraries(test_integration_transport doh_proxy_lib ${CMOCKA_LIBRARIES})
        target_include_directories(test_integration_transport PRIVATE ${CMOCKA_INCLUDE_DIRS} ${CMAKE_CURRENT_SOURCE_DIR}/tests)
        apply_target_defaults(test_integration_transport)
        add_test(NAME test_integration_transport COMMAND test_integration_transport)

        add_executable(test_integration_runtime tests/integration/test_integration.c)
        target_compile_definitions(test_integration_runtime PRIVATE INTEGRATION_GROUP_RUNTIME)
        target_compile_options(test_integration_runtime PRIVATE -Wno-unused-function)
        target_link_libraries(test_integration_runtime doh_proxy_lib ${CMOCKA_LIBRARIES})
        target_include_directories(test_integration_runtime PRIVATE ${CMOCKA_INCLUDE_DIRS} ${CMAKE_CURRENT_SOURCE_DIR}/tests)
        apply_target_defaults(test_integration_runtime)
        add_test(NAME test_integration_runtime COMMAND test_integration_runtime)

        if(ENABLE_COVERAGE AND COVERAGE_SUPPORTED)
            find_program(GCOVR_EXECUTABLE gcovr)
            if(GCOVR_EXECUTABLE)
                add_custom_target(coverage
                    COMMAND ${CMAKE_CTEST_COMMAND} --output-on-failure
                    COMMAND ${GCOVR_EXECUTABLE} -r ${CMAKE_SOURCE_DIR} ${CMAKE_BINARY_DIR} --exclude ${CMAKE_SOURCE_DIR}/tests --exclude ${CMAKE_SOURCE_DIR}/tools --gcov-ignore-parse-errors negative_hits.warn_once_per_file --print-summary
                    COMMAND ${GCOVR_EXECUTABLE} -r ${CMAKE_SOURCE_DIR} ${CMAKE_BINARY_DIR} --exclude ${CMAKE_SOURCE_DIR}/tests --exclude ${CMAKE_SOURCE_DIR}/tools --gcov-ignore-parse-errors negative_hits.warn_once_per_file --html-details -o ${CMAKE_BINARY_DIR}/coverage.html
                    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
                    USES_TERMINAL
                    DEPENDS test_config test_cache test_dns_message test_upstream test_integration_core test_integration_transport test_integration_runtime
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
