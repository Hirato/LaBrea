/*
 * pcaputil.h
 *
 * Copyright (c) 2001 Dug Song <dugsong@monkey.org>
 *
 * $Id: pcaputil.h,v 1.2 2003/09/12 21:23:39 lorgor Exp $
 */

#ifndef PCAPUTIL_H
#define PCAPUTIL_H

#include <pcap.h>
#ifdef notyet
# include <pcap-int.h>
#endif


pcap_t * pcap_open(char *device);
int	pcap_dloff(pcap_t *pcap);
int	pcap_filter(pcap_t *pcap, const char *fmt, ...);
void	pcap_stat (pcap_t *pd);


#endif /* PCAPUTIL_H */
