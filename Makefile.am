AUTOMAKE_OPTIONS        = foreign
ACLOCAL_AMFLAGS         = -I autotools
AM_MAKEFLAGS            = -s

pkglib_LTLIBRARIES	= blsb.la
blsb_la_SOURCES		= blsb.c  blsb_help.c
noinst_HEADERS		= blsb.h

blsb_la_LDFLAGS		= -module -avoid-version

EXTRA_DIST              	= autotools/ccdv.c autotools/shtool RELNOTES
dist_doc_DATA		= README.blsb README.blsb.html

include $(top_srcdir)/autotools/rules.mk
