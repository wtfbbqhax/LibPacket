AUTOMAKE_OPTIONS = foreign no-dependencies

lib_LTLIBRARIES = libdefrag.la

libdefrag_la_SOURCES = \
	hashtable.c hashtable.h \
	timequeue.c timequeue.h \
	defragment.c defragment.h

#libdefrag_la_CPPFLAGS = -Wall -Wextra -Wformat -Wformat-security -pedantic
libdefrag_la_CFLAGS = -I$(top_srcdir)/include
libdefrag_la_LDFLAGS = -version-info 0:0:0

#if HAVE_PCAP_H
#    libdefrag_la_CPPFLAGS += -DHAVE_PCAP_H
#endif


