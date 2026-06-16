cmake_minimum_required(VERSION 3.18.1)

project("rootjaildetect")

add_library(
        rootjaildetect
        SHARED
        native_security.cpp)

# Align ELF LOAD segments to 16 KB so the .so satisfies Google Play's
# 16 KB memory page size requirement. NDK r27 and earlier do not do this
# by default, so the linker flag is required.
target_link_options(
        rootjaildetect
        PRIVATE
        "-Wl,-z,max-page-size=16384")

find_library(
        log-lib
        log)

find_library(
        dl-lib
        dl)

target_link_libraries(
        rootjaildetect
        ${log-lib}
        ${dl-lib})