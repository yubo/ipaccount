AC_INIT([ipaccount], [1.0], [yubo@yubo.org])
AM_INIT_AUTOMAKE([-Wall -Werror foreign])
AC_PROG_CC
AM_PROG_CC_C_O
AC_CONFIG_HEADERS([config.h])
AC_DISABLE_STATIC
AC_PROG_LIBTOOL

AC_ARG_WITH([kbuild],
	AS_HELP_STRING([--with-kbuild=PATH],
	[Path to kernel build directory [[/lib/modules/CURRENT/build]]])

AS_HELP_STRING([--without-kbuild],
	[Build only userspace tools]),
	[kbuilddir="$withval"],
	[kbuilddir="/lib/modules/$(uname -r)/build"])

if [[ "$kbuilddir" == no ]]; then
	kbuilddir="";
fi


regular_CPPFLAGS="-D_LARGEFILE_SOURCE=1 -D_LARGE_FILES -D_FILE_OFFSET_BITS=64 \
	-D_REENTRANT "
regular_CFLAGS="-Wall -Waggregate-return -Wmissing-declarations \
	-Wmissing-prototypes -Wredundant-decls -Wshadow -Wstrict-prototypes \
	-Winline -pipe";


if test -n "$kbuilddir"; then
	AC_MSG_CHECKING([kernel version that we will build against])
	krel="$(make -sC "$kbuilddir" M=$PWD kernelrelease)";
	kmajor="${krel%%[[^0-9]]*}";
	kmajor="$(($kmajor+0))";
	krel="${krel:${#kmajor}}";
	krel="${krel#.}";
	kminor="${krel%%[[^0-9]]*}";
	kminor="$(($kminor+0))";
	krel="${krel:${#kminor}}";
	krel="${krel#.}";
	kmicro="${krel%%[[^0-9]]*}";
	kmicro="$(($kmicro+0))";
	krel="${krel:${#kmicro}}";
	krel="${krel#.}";
	kstable="${krel%%[[^0-9]]*}";
	kstable="$(($kstable+0))";
	if test -z "$kmajor" -o -z "$kminor" -o -z "$kmicro"; then
		echo "WARNING: Version detection did not succeed. Continue at own luck.";
	else
		echo "$kmajor.$kminor.$kmicro.$kstable in $kbuilddir";
		if test "$kmajor" -gt 3 -o "$kmajor" -eq 3 -a "$kminor" -gt 13; then
			echo "WARNING: That kernel version is not officially supported yet. Continue at own luck.";
		elif test "$kmajor" -eq 3 -a "$kminor" -ge 7; then
			:;
		else
			echo "WARNING: That kernel version is not officially supported.";
		fi;
	fi;
fi;



AC_SUBST([regular_CPPFLAGS])
AC_SUBST([regular_CFLAGS])
AC_SUBST([kbuilddir])

AC_CONFIG_FILES([Makefile src/Makefile])
AC_OUTPUT
