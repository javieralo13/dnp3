#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.59])

AC_INIT([dnp3], [0.9.3], [andy@tranalyzer.com])

AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_SRCDIR([src])

AM_INIT_AUTOMAKE([foreign])

case $OSTYPE in
    darwin*)
        # macOS specific
        apple=true
        ;;
    linux*)
        # Linux specific
        ;;
esac

AM_CONDITIONAL([APPLE], [test x$apple = xtrue])

m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])
m4_ifdef([AM_PROG_AR], [AM_PROG_AR])

# Checks for programs.
#AC_PROG_AWK
AC_PROG_CC
AC_PROG_CC_STDC
AC_PROG_CXX
#AC_PROG_INSTALL
#AC_PROG_MAKE_SET
LT_INIT

# Checks for libraries.
#AC_CHECK_LIB([m], [pow])
#PKG_CHECK_MODULES([MY_LIBRARY], [mylibrary])
#AC_SEARCH_LIBS([gcry_cipher_checktag], [gcrypt],
#        [], [AC_MSG_ERROR([gcrypt library not found])])

# Checks for header files.
AC_HEADER_STDBOOL
AC_CHECK_HEADERS([string.h], [], [AC_MSG_ERROR([<string.h> header missing])])
AC_CHECK_HEADERS([stdio.h stdlib.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_C_INLINE
#AC_C_VOLATILE
AC_TYPE_INT8_T
AC_TYPE_INT16_T
AC_TYPE_INT32_T
AC_TYPE_INT64_T
#AC_TYPE_INTMAX_T
#AC_TYPE_OFF_T
AC_TYPE_SIZE_T
#AC_TYPE_SSIZE_T
AC_TYPE_UINT8_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T

# Checks for library functions.
#AC_FUNC_ERROR_AT_LINE
AC_FUNC_FSEEKO
AC_FUNC_MALLOC
#AC_FUNC_MKTIME
AC_FUNC_REALLOC
#AC_FUNC_STRTOD
AC_CHECK_FUNCS([memset strerror])

AC_CONFIG_FILES([
    Makefile
    src/Makefile
])
AC_OUTPUT
