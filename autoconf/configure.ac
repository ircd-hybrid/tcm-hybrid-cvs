dnl Process this file with autoconf to produce a configure script.

AC_PREREQ(2.53)

AC_COPYRIGHT([$Id: configure.ac,v 1.2 2004/06/02 02:00:38 bill Exp $])

AC_INIT([tcm-hybrid],[3.1.0-pre])

AC_CONFIG_HEADER(include/setup.h)
AC_PREFIX_DEFAULT(/usr/local/tcm)

PACKAGE=tcm-hybrid
VERSION=3.1.2-pre

if test "$prefix" = "NONE"; then
  dnl Be smart.
  if test -d "/usr/local/ircd/bin"; then
    prefix="/usr/local/ircd"
  elif test -d "/home/ircd/bin"; then
    prefix="/home/ircd"
  else
    prefix=$ac_default_prefix
  fi
fi

AC_DEFINE_UNQUOTED(DPATH, "$prefix", [tcm's prefix])

dnl Checks for programs.
AC_PROG_CC

if test "$ac_cv_c_compiler_gnu" = yes; then
  CFLAGS="$CFLAGS -Wall"
fi

AC_ISC_POSIX
AC_PROG_MAKE_SET
AC_PATH_PROG(RM,rm)
AC_PATH_PROG(CP,cp)
AC_PROG_INSTALL
AC_PROG_YACC

if test "$YACC" = "yacc" -a -z "`which $YACC 2>/dev/null`"; then
        AC_MSG_ERROR([could not locate a suitable parser generator; install bison, yacc, or byacc])
fi                 
               
AC_PROG_LEX
  
if test "$LEX" = ":"; then
        AC_MSG_ERROR([could not locate a suitable lexical generator, install flex or lex.])
fi

hold_ldflags=$LDFLAGS     
AC_MSG_CHECKING(for the ld -export-dynamic flag)

dnl Borrowed from hybrid.
if expr "`uname -s`" : ^IRIX >/dev/null 2>&1; then
  found="no, IRIX ld uses -B,dynamic"
  LDFLAGS="${LDFLAGS} -Wl,-B,dynamic"
else
  LDFLAGS="${LDFLAGS} -Wl,-export-dynamic"
  AC_LINK_IFELSE(AC_LANG_PROGRAM([],[int i;]), [found=yes], [found=no])
  LDFLAGS=$hold_ldflags
  AC_MSG_RESULT($found)
  if test "$found" = yes; then
    LDFLAGS="${LDFLAGS} -Wl,-export-dynamic"
  fi
fi

dnl Cascade until we've got the big picture
AC_SEARCH_LIBS(gethostbyname, nsl, ,
[if test "$ac_cv_search_gethostbyname" = "no"; then error=1; fi])

AC_SEARCH_LIBS(socket, socket, ,
[if test "$ac_cv_search_socket" = "no"; then error=1; fi])

AC_SEARCH_LIBS(inet_aton, resolv,
[AC_DEFINE(HAVE_INET_ATON, 1, [Define if inet_aton is available.])],
[if test "$ac_cv_search_inet_aton" = "no"; then UTIL_C=util.c; fi])

dnl Basic check for SSL.
AC_CHECK_HEADER(openssl/rsa.h, , [error=1])

AC_CHECK_LIB(crypto, RSA_private_decrypt, , [error=1])
AC_SEARCH_LIBS(crypt, [crypt descrypt], ,
[if test "$ac_cv_search_crypt" = "no"; then error=1; fi])
AC_SEARCH_LIBS(dlopen, [dl c_r], , 
[if test "$ac_cv_search_dlopen" = "no"; then error=1; fi])

if test "$error" = 1; then
  AC_MSG_ERROR([Missing some essential libraries - see output above for more details. Correct and retry.])
fi

dnl Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([sys/socketvar.h sys/stream.h crypt.h sys/resource.h getopt.h])
AC_CHECK_HEADERS([sys/select.h regex.h])

AC_CHECK_TYPE(socklen_t, ,
	[AC_DEFINE(socklen_t, [unsigned int], [Define a suitable alternative for socklen_t if necessary.])], [#include <sys/types.h>])

dnl Check for stdarg.h - if we can't find it, halt configure
AC_CHECK_HEADER(stdarg.h, , AC_MSG_ERROR(** stdarg.h could not be found - tcm-hybrid will not compile without it **))

if test "$error" = 1; then
  AC_MSG_ERROR([Missing some essential headers - see output above for more details. Correct and retry.])
fi

AC_PROG_GCC_TRADITIONAL
AC_CHECK_FUNC(setrlimit, , [error=1])
AC_CHECK_FUNCS([strcasestr strlcpy strlcat snprintf vsnprintf],, [UTIL_C=util.c])
AC_SUBST(UTIL_C)

if test "$error" = 1; then
  AC_MSG_ERROR([Missing some essential standard function - see output above for more details. Correct and retry.])
fi

AC_OUTPUT([Makefile src/Makefile tools/Makefile])
