cmake_minimum_required(VERSION 3.18.1)

project("rootjaildetect")

add_library(
        rootjaildetect
        SHARED
        native_security.cpp)

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