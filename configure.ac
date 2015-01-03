# Victor J. Roemer <vroemer@badsec.org>
#
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.61)
AC_INIT([libpacket], [0.1.0-alpha.1], [vroemer@badsec.org])
AC_CONFIG_SRCDIR([src/packet.c])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])

AM_INIT_AUTOMAKE([-Wall -Werror foreign color-tests parallel-tests])

#
# Checks for programs.
#
AC_PROG_CC
AC_PROG_CC_C99
AC_PROG_INSTALL
LT_INIT
AC_PROG_LIBTOOL

#
# Setup for host specific needs 
#
case "$host" in
#    *-darwin*)
#    AC_DEFINE([MACOS], [1], [Define if MacOS])
#    ;;
    *-openbsd*)
    AC_DEFINE([OPENBSD], [1], [Define if OpenBSD])
    ;;
#    *-linux*)
#    AC_DEFINE([LINUX], [1], [Define if Linux])
#    ;;
esac

###############################################################################
#                             Debug build option                              #
###############################################################################

AC_ARG_ENABLE(debug,
[  --enable-debug           Enable debug build],
       enable_debug="$enableval", enable_debug="no")

if test "x$enable_debug" = "xyes"; then
    # Set debugging options
    CFLAGS="$CFLAGS -g -ggdb"

    # Turn off any optimization
    CFLAGS=`echo $CFLAGS | sed -e "s/-O./-O0/"`

    # Define DEBUG
    AC_DEFINE([DEBUG], [1], [Debug build])

    # Remove inline functions
    AC_DEFINE([inline], [], [Turn off inline functions])
fi

#AC_CHECK_LIB([check], [srunner_create])
#AM_CONDITIONAL([HAVE_LIB_CHECK],
#    test "x$ac_cv_check_srunner_create" == "xyes")

#
# Checks for header files.
#
AC_HEADER_STDC
AC_CHECK_HEADERS([arpa/inet.h],, AC_ERROR([Missing header arpa/inet.h]))
AC_CHECK_HEADERS([inttypes.h],, AC_ERROR([Missing header inttypes.h]))
AC_CHECK_HEADERS([netinet/in.h],, AC_ERROR([Missing header netinet/in.h]))
AC_CHECK_HEADERS([stdint.h],, AC_ERROR([Missing header stdint.h]))
AC_CHECK_HEADERS([stdbool.h],, AC_ERROR([Missing header stdbool.h]))
AC_CHECK_HEADERS([stdlib.h],, AC_ERROR([Missing header stdlib.h]))
AC_CHECK_HEADERS([string.h],, AC_ERROR([Missing header string.h]))
AC_CHECK_HEADERS([sys/types.h],, AC_ERROR([Missing header sys/types.h]))
AC_CHECK_HEADERS([sys/socket.h],, AC_ERROR([Missing header sys/socket.h]))

# Determine if we have libcheck for regression tests
# TODO: Turn this into a functioning macro to enable regression
#       testing
# AC_CHECK_HEADERS([check.h])
# if test "x$ac_cv_header_check_h" = "xyes"; then
# save_LIBS="$LIBS"
# LIBS=""
# CHECK_LIBS=""
# have_check=no
# AC_SEARCH_LIBS([suite_add_tcase], [check],
#     [have_check=yes
#     CHECK_LIBS="$LIBS"
#     AC_DEFINE(HAVE_LIBCHECK, 1, [Define if the system has libcheck])]
# LIBS="$save_LIBS"
# AC_SUBST(CHECK_LIBS)
# fi
# AM_CONDITIONAL([CHECK], [test "x$have_check" = "xyes"])

AC_CHECK_HEADERS([check.h])
AM_CONDITIONAL([HAVE_LIB_CHECK], [test "x$ac_cv_header_check_h" == "xyes"])

AC_CHECK_HEADERS([pcap.h])
AM_CONDITIONAL([HAVE_PCAP_H], [test "x$ac_cv_header_pcap_h" == "xyes"])

#
# Checks for typedefs, structures, and compiler characteristics.
#
AC_C_INLINE
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T

#
# Check for some functions
#
AC_FUNC_MALLOC
AC_CHECK_FUNCS([memset],, AC_ERROR([Missing function memset]))

# 
# Write the configuration files
#
AC_CONFIG_FILES([Makefile include/Makefile src/Makefile extras/Makefile tests/Makefile])

# 
# Output the data
#
AC_OUTPUT
