cmake_minimum_required(VERSION 3.10)
project(DOH-Proxy C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

find_package(CURL REQUIRED)
find_package(Threads REQUIRED)

add_executable(
    DOH-Proxy
    src/main.c
    src/config.c
    src/cache.c
    src/dns_message.c
    src/doh_client.c
    src/dns_server.c
)

target_compile_options(DOH-Proxy PRIVATE -Wall -Wextra -Wpedantic)
target_link_libraries(DOH-Proxy PRIVATE CURL::libcurl Threads::Threads)
