## Process this file with automake to produce Makefile.in
##
## $Id: Makefile.am,v 1.1 2003/01/09 18:13:19 lorgor Exp $

man_MANS = labrea.1 labrea.conf.5

labrea.1.txt: labrea.1
	groff -t -e -man -Tascii labrea.1 | col -bx > $@

labrea.conf.5.txt: labrea.conf.5
	groff -t -e -man -Tascii labrea.conf.5 | col -bx > $@

sysconf_DATA = labrea.conf

EXTRA_DIST = DSong-LICENSE labrea.conf labrea.1.txt labrea.conf.5.txt $(man_MANS)

DISTCLEANFILES = *~
