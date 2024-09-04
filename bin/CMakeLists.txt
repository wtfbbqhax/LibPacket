cmake_minimum_required(VERSION 3.20)
project(pig C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)

add_executable(
    dnshog
)

target_sources(
    dnshog
    PRIVATE
    dns_hog.cc
    daq_print.cc
    daq_print.h
)

target_link_libraries(
    dnshog
    PRIVATE
    daq
    pcap
    packet
)
