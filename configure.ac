
AC_INIT(posixovl, 1.0)
AC_CONFIG_HEADERS(config.h)
AM_INIT_AUTOMAKE
AC_PROG_CC
AM_PROG_CC_C_O

AC_CFLAGS="-D_FORTIFY_SOURCE=2 -D_LARGEFILE_SOURCE=1 -D_LARGE_FILES \
	-D_FILE_OFFSET_BITS=64 -D_REENTRANT -Wall -Waggregate-return \
	-Wmissing-declarations -Wmissing-prototypes -Wredundant-decls \
	-Wshadow -Wstrict-prototypes -Winline -pipe"
AC_SUBST(AC_CFLAGS)

AC_CHECK_HEADER(attr/xattr.h, [], AC_MSG_ERROR([libattr-devel not installed]))
PKG_CHECK_MODULES([libfuse], [fuse >= 2.6.5])

AC_CHECK_HEADER([libHX.h], [],
	AC_MSG_ERROR([Need at least libHX 1.10 (http://jengelh.hopto.org/p/libHX/)]),
	[
#include <libHX.h>
#if !defined(_LIBHX_H) || _LIBHX_H < 20070701
#	error You need a newer version of libHX (at least 1.10.0)
#endif
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
