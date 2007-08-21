# -*- Makefile -*-

AUTOMAKE_OPTIONS       = foreign subdir-objects
AM_CFLAGS              = $(AC_CFLAGS) $(libfuse_CFLAGS)

sbin_PROGRAMS          = mount.posixovl
mount_posixovl_SOURCES = posixovl.c
mount_posixovl_LDADD   = -lHX $(libfuse_LIBS)
