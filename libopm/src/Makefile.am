lib_LTLIBRARIES = libopm.la

libopm_la_SOURCES = compat.c compat.h config.c config.h inet.c inet.h \
    libopm.c libopm.h list.c list.h malloc.c malloc.h opm_common.h \
    opm_error.h opm.h opm_types.h proxy.c proxy.h setup.h

include_HEADERS = opm.h opm_error.h opm_types.h opm_common.h

libopm_la_LIBADD = @ETR_SOCKET_LIBS@ @LTLIBOBJS@

noinst_PROGRAMS = test test_debug
test_SOURCES = test.c
test_LDADD = libopm.la compat.o @LIBOBJS@

# An easier-to-debug version of test

test_debug_SOURCES = test.c
test_debug_LDADD = libopm.la compat.o @LIBOBJS@
test_debug_LDFLAGS = -static

# $Id: Makefile.am,v 1.1 2004/06/15 22:36:42 bill Exp $
