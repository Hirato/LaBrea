/*
 * Pcaputil.c
 *
 * Copyright (c) 2001, 2002 Dug Song <dugsong@monkey.org>
 * All rights reserved, all wrongs reversed.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The names of the authors and copyright holders may not be used to
 *    endorse or promote products derived from this software without
 *    specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
 * THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * $Id: pcaputil.c,v 1.1 2003/01/09 18:13:19 lorgor Exp $
 */


#include "config.h"

#ifndef WIN32
#include <sys/param.h>
#ifdef HAVE_SYS_IOCTL_H
#include <sys/ioctl.h>
#endif
#endif


#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "labrea.h"
#include "utils.h"
#include "pcaputil.h"

pcap_t *
pcap_open(char *device)
{
	char ebuf[PCAP_ERRBUF_SIZE];
	pcap_t *pcap;
	
	if (device == NULL) {
		if ((device = pcap_lookupdev(ebuf)) == NULL)
			return (NULL);
	}
	if ((pcap = pcap_open_live(device, 31337, 1, PCAP_TIMEOUT, ebuf)) == NULL)
		return (NULL);
	
#ifdef BSD
	{
		int n = 1;

		if (ioctl(pcap_fileno(pcap), BIOCIMMEDIATE, &n) < 0) {
			pcap_close(pcap);
			return (NULL);
		}
	}
#endif
	return (pcap);
}

int
pcap_dloff(pcap_t *pd)
{
	int i;

	i = pcap_datalink(pd);
	
	switch (i) {
	case DLT_EN10MB:
		i = 14;
		break;
	case DLT_IEEE802:
		i = 22;
		break;
	case DLT_FDDI:
		i = 21;
		break;
#ifdef DLT_LOOP
	case DLT_LOOP:
#endif
	case DLT_NULL:
		i = 4;
		break;
	default:
		i = -1;
		break;
	}
	return (i);
}

int
pcap_filter(pcap_t *pcap, const char *fmt, ...)
{
	struct bpf_program fcode;
	char buf[BUFSIZ];
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);
#ifdef notyet
	pcap_freecode(&pcap->fcode);
#endif
	if (pcap_compile(pcap, &fcode, buf, 1, 0) < 0)
		return (-1);
	
	if (pcap_setfilter(pcap, &fcode) == -1)
		return (-1);

	return (0);
}

void
pcap_stat (pcap_t *pd)
{
  struct pcap_stat stat;

  /* show 'em some stats... */
  if (pd != NULL) {
    if (pcap_stats(pd, &stat) >= 0) {
      util_print(NORMAL, "%d/%d packets (received/dropped) by filter", stat.ps_recv, stat.ps_drop);
    }
  }
}
