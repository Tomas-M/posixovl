# -*- Makefile -*-

AUTOMAKE_OPTIONS       = foreign subdir-objects
AM_CFLAGS              = $(regular_CFLAGS) $(libfuse_CFLAGS)

sbin_PROGRAMS          = mount.posixovl
EXTRA_PROGRAMS         = socket lntest
mount_posixovl_SOURCES = posixovl.c
mount_posixovl_LDADD   = $(libfuse_LIBS)
