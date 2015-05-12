#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.67])
AC_INIT(miruo, 0.9.6, info-miruo@klab.com)
AM_INIT_AUTOMAKE
AC_CONFIG_SRCDIR([miruo.c])
AC_CONFIG_HEADER([config.h])

# Checks for programs.
AC_PROG_CC

# Checks for libraries.

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([arpa/inet.h fcntl.h limits.h netinet/in.h stdint.h stdlib.h string.h sys/socket.h sys/time.h unistd.h pcap.h sys/epoll.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_INT64_T
AC_HEADER_TIME
AC_STRUCT_TM
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_MEMCMP
AC_FUNC_SELECT_ARGTYPES
AC_CHECK_FUNCS([gettimeofday inet_ntoa memset select strerror])

LIBPCAPPATH="/usr"
AC_ARG_WITH(libpcap,
AC_HELP_STRING([--with-libpcap=PATH],[path to libpcap installation]),
  [
    LIBPCAPPATH="$withval"
    LDFLAGS="-L$LIBPCAPPATH/lib -Wl,-rpath -Wl,$LIBPCAPPATH/lib $LDFLAGS"
    CPPFLAGS="-I$LIBPCAPPATH/include $CPPFLAGS"
  ]
)

AC_ARG_ENABLE(libpcap-static,
  AC_HELP_STRING([--enable-libpcap-static],[libpcap static link]),
  [
    LIBS="$LIBS $LIBPCAPPATH/lib/libpcap.a"
  ],
  [
    LIBS="$LIBS -lpcap"
  ]
)

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
