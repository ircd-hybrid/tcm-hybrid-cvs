# $Id: Makefile.am,v 1.1 2004/06/15 22:36:33 bill Exp $

AUTOMAKE_OPTIONS = foreign

SUBDIRS = src

EXTRA_DIST = LICENSE

LIBTOOL_DEPS = @LIBTOOL_DEPS@
libtool: $(LIBTOOL_DEPS)
	$(SHELL) ./config.status --recheck

docs:
	-cd doc && $(MAKE) $(AM_MAKEFLAGS) $@
