## Process this file with automake to produce Makefile.in
##
## $Id: Makefile.am,v 1.1 2003/01/09 18:13:19 lorgor Exp $

AM_CPPFLAGS = -I../inc -I- @DNETINC@ @PCAPINC@

sbin_PROGRAMS = labrea

labrea_SOURCES = labrea.c labrea_init.c pkt_handler.c lbio.c ctl.c	\
	utils.c pcaputil.c bget.c pkt.c

labrea_LDADD =  @LIBOBJS@ @DNETLIB@ @PCAPLIB@

EXTRA_DIST = getopt1.c getopt.c memcmp.c \
	strlcpy.c syslog.c

DISTCLEANFILES = *~
