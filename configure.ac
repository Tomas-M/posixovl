
AC_INIT(posixovl, 1.0)
AC_CONFIG_HEADERS(config.h)
AM_INIT_AUTOMAKE
AC_PROG_CC

AC_CFLAGS="-D_FORTIFY_SOURCE=2 -D_LARGEFILE_SOURCE=1 -D_LARGE_FILES \
	-D_FILE_OFFSET_BITS=64 -D_REENTRANT -Wall -Waggregate-return \
	-Wmissing-declarations -Wmissing-prototypes -Wredundant-decls \
	-Wshadow -Wstrict-prototypes -Winline -pipe"

saved_CFLAGS="$CFLAGS"
saved_CPPFLAGS="$CPPFLAGS"
CFLAGS="$CFLAGS $AC_CFLAGS"
CPPFLAGS="$CPPFLAGS $AC_CFLAGS"
AC_CHECK_HEADER(attr/xattr.h, [],
		AC_MSG_ERROR([libattr-devel not installed]))
AC_CHECK_HEADER(fuse.h, [],
		AC_MSG_ERROR([fuse-devel not installed]))
CFLAGS="$saved_CFLAGS"
CPPFLAGS="$saved_CPPFLAGS"

FUSE_CFLAGS=`pkg-config fuse --cflags`
FUSE_LDFLAGS=`pkg-config fuse --libs`
AC_SUBST(AC_CFLAGS)
AC_SUBST(FUSE_CFLAGS)
AC_SUBST(FUSE_LDFLAGS)
AC_OUTPUT([Makefile])
