
AC_INIT(posixovl, 1.0)
AC_CONFIG_HEADERS(config.h)
AC_PROG_INSTALL
AM_INIT_AUTOMAKE
AC_PROG_CC
AM_PROG_CC_C_O

regular_CFLAGS="-D_FORTIFY_SOURCE=2 -D_LARGEFILE_SOURCE=1 -D_LARGE_FILES \
	-D_FILE_OFFSET_BITS=64 -D_REENTRANT -Wall -Waggregate-return \
	-Wmissing-declarations -Wmissing-prototypes -Wredundant-decls \
	-Wshadow -Wstrict-prototypes -Winline -pipe"
AC_SUBST(regular_CFLAGS)

AC_CHECK_HEADER(attr/xattr.h, [], AC_MSG_ERROR([libattr-devel not installed]))

# FUSE >= 2.7.0 got subtype name support.
# 2.6.5 does not, but has a similar thing.
PKG_CHECK_MODULES([libfuse], [fuse >= 2.7.0], [], [
	PKG_CHECK_MODULES([libfuse], [fuse >= 2.6.5], [
		AC_DEFINE([HAVE_JUST_FUSE_2_6_5], [1],
			[Define if you have a FUSE version >= 2.6.5 but < 2.7.0])
	])
])

# Minium requirements for utimensat(): Linux 2.6.22-rc1 and Glibc 2.6
AC_MSG_CHECKING([for utimensat()])
AC_COMPILE_IFELSE([
		#include <asm/unistd.h>
		static unsigned int x = __NR_utimensat;
	], [
		AC_DEFINE([HAVE_UTIMENSAT], [1],
			[Define if utimensat() function is available])
		AC_MSG_RESULT([yes])
	], [
		AC_MSG_RESULT([no])
	])

AC_OUTPUT([Makefile])
