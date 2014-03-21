# -*- Makefile -*-
# AUTOMAKE

AM_CPPFLAGS = ${regular_CPPFLAGS} -I${abs_top_srcdir}/src
AM_CFLAGS = ${regular_CFLAGS} -lnl

# Not having Kbuild in Makefile.extra because it will already recurse
.PHONY: modules modules_install clean_modules

_kcall = -C ${kbuilddir} M=${abs_srcdir}

modules:
	@echo -n "ipaccount ${PACKAGE_VERSION} - Linux "
	@if [ -n "${kbuilddir}" ]; then ${MAKE} ${_kcall} --no-print-directory -s kernelrelease; fi;
	${AM_V_silent}if [ -n "${kbuilddir}" ]; then ${MAKE} ${_kcall} modules; fi;

modules_install:
	${AM_V_silent}if [ -n "${kbuilddir}" ]; then ${MAKE} ${_kcall} INSTALL_MOD_PATH=${DESTDIR} ext-mod-dir='$${INSTALL_MOD_DIR}' modules_install; fi;

clean_modules:
	${AM_V_silent}if [ -n "${kbuilddir}" ]; then ${MAKE} ${_kcall} clean; fi;

all-local: modules

install-exec-local: modules_install

clean-local: clean_modules

sbin_PROGRAMS = ipaccount
lib_LTLIBRARIES = libipaccount.la libluaipaccount.la
ipaccount_SOURCES = ipaccount.c
ipaccount_LDADD = libipaccount.la

libipaccount_la_SOURCES = libipaccount.c

libluaipaccount_la_SOURCES = luaipaccount.c
libluaipaccount_la_LIBADD = libipaccount.la
libluaipaccount_la_DEPENDENCIES = libipaccount.la

