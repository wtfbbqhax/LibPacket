set(CMAKE_C_STANDARD 11)

add_library(
    packet
    SHARED
)

set_target_properties(
    packet
    PROPERTIES
    VERSION 0.2.2
    SOVERSION 0
)

target_sources(
    packet
    PRIVATE
    checksum.c
    checksum.h
    crc32.h
    eth.c
    eth.h
    geneve.c
    geneve.h
    icmp4.c
    icmp4.h
    icmp6.c
    icmp6.h
    ip4.c
    ip4.h
    ip6.c
    ip6.h
    ipx.c
    ipx.h
    mpls.c
    mpls.h
    packet.c
    packet_private.c
    packet_private.h
    ppp.c
    ppp.h
    pppoe.c
    pppoe.h
    raw.c
    raw.h
    sctp.c
    sctp.h
    spx.c
    spx.h
    tcp.c
    tcp.h
    udp.c
    udp.h
    vlan.c
    vlan.h
)

target_include_directories(
    packet
    BEFORE
    PRIVATE "${CMAKE_SOURCE_DIR}/include"
    PRIVATE "${CMAKE_SOURCE_DIR}"
)

install(
    TARGETS packet
    LIBRARY DESTINATION "${CMAKE_INSTALL_PREFIX}/lib"
)
