cmake_minimum_required(VERSION 3.20)
project(pig C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)

# BPF Filter piglet
add_executable(
    bpf_filter
)

target_sources(
    bpf_filter
    PRIVATE
    bpf_filter.cc
    daq_print.cc
    daq_print.h
)

target_link_libraries(
    bpf_filter
    PRIVATE
    daq
    pcap
    packet
)

# Network echo, re-injects all packets received 
# responds on all ports
add_executable(
    net_echo
)

target_sources(
    net_echo
    PRIVATE
    net_echo.cc
    daq_print.cc
    daq_print.h
)

target_link_libraries(
    net_echo 
    PRIVATE
    daq
    pcap
    packet
)

# DNS Hog
# Sample DNS analyzer
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

# Network flood generator
# Static packet format is hardcoded in code
add_executable(
    flood
)

target_sources(
    flood
    PRIVATE
    flood.cc
    daq_print.cc
    daq_print.h
    csum.c
)

target_link_libraries(
    flood
    PRIVATE
    daq
    pcap
    packet
)
