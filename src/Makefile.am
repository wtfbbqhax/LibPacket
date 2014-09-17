AUTOMAKE_OPTIONS = foreign no-dependencies

lib_LTLIBRARIES = libpacket.la

libpacket_la_SOURCES = \
    packet_private.h \
    packet_private.c \
    packet.c \
    checksum.h \
    checksum.c\
    raw.c raw.h \
    eth.c eth.h \
    ppp.c ppp.h \
    vlan.c vlan.h \
    mpls.c mpls.h \
    pppoe.c pppoe.h \
    ip4.c ip4.h \
    ip6.c ip6.h \
    ipx.c ipx.h \
    spx.c spx.h \
    sctp.c sctp.h \
    crc32.h \
    tcp.c tcp.h \
    udp.c udp.h

libpacket_la_CPPFLAGS = -Wall -Wextra -Wformat -Wformat-security -pedantic
libpacket_la_CFLAGS = -I$(top_srcdir)/include
libpacket_la_LDFLAGS = -version-info 0:0:0

if HAVE_PCAP_H
    libpacket_la_CPPFLAGS += -DHAVE_PCAP_H
endif


