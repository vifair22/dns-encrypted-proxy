cmake_minimum_required(VERSION 3.10)
project(DOH-Proxy C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

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
target_compile_options(doh_proxy_lib PRIVATE -Wall -Wextra -Wpedantic)
target_link_libraries(doh_proxy_lib PUBLIC CURL::libcurl Threads::Threads OpenSSL::SSL OpenSSL::Crypto)

# Main executable
add_executable(DOH-Proxy src/main.c)
target_compile_options(DOH-Proxy PRIVATE -Wall -Wextra -Wpedantic)
target_link_libraries(DOH-Proxy PRIVATE doh_proxy_lib)

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
        add_test(NAME test_config COMMAND test_config)
        
        # Unit test: cache
        add_executable(test_cache tests/unit/test_cache.c)
        target_link_libraries(test_cache doh_proxy_lib ${CMOCKA_LIBRARIES})
        target_include_directories(test_cache PRIVATE ${CMOCKA_INCLUDE_DIRS} ${CMAKE_CURRENT_SOURCE_DIR}/tests)
        add_test(NAME test_cache COMMAND test_cache)
        
        # Unit test: dns_message
        add_executable(test_dns_message tests/unit/test_dns_message.c)
        target_link_libraries(test_dns_message doh_proxy_lib ${CMOCKA_LIBRARIES})
        target_include_directories(test_dns_message PRIVATE ${CMOCKA_INCLUDE_DIRS} ${CMAKE_CURRENT_SOURCE_DIR}/tests)
        add_test(NAME test_dns_message COMMAND test_dns_message)

        # Unit test: upstream
        add_executable(test_upstream tests/unit/test_upstream.c)
        target_link_libraries(test_upstream doh_proxy_lib ${CMOCKA_LIBRARIES})
        target_include_directories(test_upstream PRIVATE ${CMOCKA_INCLUDE_DIRS} ${CMAKE_CURRENT_SOURCE_DIR}/tests)
        add_test(NAME test_upstream COMMAND test_upstream)
        
        # Integration tests
        add_executable(test_integration tests/integration/test_integration.c)
        target_link_libraries(test_integration doh_proxy_lib ${CMOCKA_LIBRARIES})
        target_include_directories(test_integration PRIVATE ${CMOCKA_INCLUDE_DIRS} ${CMAKE_CURRENT_SOURCE_DIR}/tests)
        add_test(NAME test_integration COMMAND test_integration)
        
        # Coverage support
        option(ENABLE_COVERAGE "Enable code coverage" OFF)
        if(ENABLE_COVERAGE)
            target_compile_options(doh_proxy_lib PRIVATE --coverage)
            target_link_options(doh_proxy_lib PRIVATE --coverage)
        endif()
    else()
        message(WARNING "cmocka not found, tests will not be built. Install with: apt install libcmocka-dev")
    endif()
endif()
