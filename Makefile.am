SUBDIRS = include src extras	

if HAVE_LIB_CHECK
SUBDIRS += tests
endif

bin_SCRIPTS = packet-config
CLEANFILES = $(bin_SCRIPTS)
EXTRA_DIST = $(top_srcdir)/packet-config.in

do_subst = sed -e 's,[@]prefix[@],$(prefix),g' \
               -e 's,[@]includedir[@],$(includedir),g' \
               -e 's,[@]libdir[@],$(libdir),g' \
               -e 's,[@]VERSION[@],$(VERSION),g' \
               -e 's,[@]PACKAGE_BUGREPORT[@],$(PACKAGE_BUGREPORT),g'

packet-config: $(top_srcdir)/packet-config.in
	$(do_subst) < $(top_srcdir)/packet-config.in > packet-config
	chmod +x packet-config

# make README
README: $(top_srcdir)/README.in
	$(do_subst) < $(top_srcdir)/README.in > README 

EXTRA_DIST += README
