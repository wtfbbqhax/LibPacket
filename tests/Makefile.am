
TESTS = \
check_packet_create \
check_packet_decode \
check_packet_accessors \
check_packet_alt_payload

noinst_PROGRAMS = \
check_packet_create \
check_packet_decode \
check_packet_accessors \
check_packet_alt_payload

check_packet_create_SOURCES = check_packet_create.c test.h
check_packet_create_LDADD = $(top_builddir)/src/libpacket.la

check_packet_decode_SOURCES = check_packet_decode.c test.h
check_packet_decode_LDADD = $(top_builddir)/src/libpacket.la

check_packet_accessors_SOURCES = check_packet_accessors.c test.h
check_packet_accessors_LDADD = $(top_builddir)/src/libpacket.la

check_packet_alt_payload_SOURCES = check_packet_alt_payload.c test.h
check_packet_alt_payload_LDADD = $(top_builddir)/src/libpacket.la

bin_PROGRAMS=testme
testme_SOURCES=testme.c
testme_LDADD=$(top_builddir)/src/libpacket.la
testme_CFLAGS=-lpcap

#TESTS_ENVIRONMENT = valgrind -q --leak-check=full --error-exitcode=1

AM_CFLAGS = -lcheck
AM_CPPFLAGS = -I$(top_srcdir)/include -I$(top_srcdir)/src 
