/*
 * pcaputil.h
 *
 * Copyright (c) 2001 Dug Song <dugsong@monkey.org>
 *
 * $Id: pcaputil.h,v 1.1 2003/01/09 18:13:19 lorgor Exp $
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
