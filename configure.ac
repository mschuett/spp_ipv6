# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.69)
AC_INIT([spp_ipv6], [1.6], [info@mschuette.name])
AC_CONFIG_SRCDIR([src/spp_ipv6.c])
AM_INIT_AUTOMAKE

# Checks for programs.
AC_PROG_CC
AC_PROG_LIBTOOL

# Check some include files
AC_CHECK_HEADERS([time.h sys/time.h stdlib.h ctype.h string.h sys/queue.h errno.h],
	[mypj_found_std_headers=yes; break;])
AC_CHECK_HEADERS([sf_preproc_info.h sf_types.h],
	[mypj_found_snort_headers=yes; break;])

AS_IF([test "x$mypj_found_std_headers" != "xyes"],
	[AC_MSG_ERROR([Unable to find some standard C headers])])
AS_IF([test "x$mypj_found_snort_headers" != "xyes"],
	[AC_MSG_ERROR([Unable to find Snort headers])])

# Use the same defines Snort used (absolutely critical to ensure struct definitions match)
AM_CFLAGS=`pkg-config --cflags snort`

# Check for int types
AC_CHECK_TYPES([u_int8_t,u_int16_t,u_int32_t,u_int64_t])
AC_CHECK_TYPES([uint8_t,uint16_t,uint32_t,uint64_t])
AC_CHECK_TYPES([int8_t,int16_t,int32_t,int64_t])

AC_FUNC_MALLOC

AC_CONFIG_FILES([Makefile src/Makefile])

AC_SUBST(SOURCE)

AC_OUTPUT

