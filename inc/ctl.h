/* ctl.h
 * This file is part of the LaBrea package
 *
 * Copyright (C) 2001, 2002 Tom Liston <tliston@premmag.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 *
 * $Id: ctl.h,v 1.1 2003/01/09 18:13:19 lorgor Exp $
 */

#ifndef CTL_H
#define CTL_H

#include <signal.h>
#include <dnet.h>
#include "queue.h"

/*
 * Note that data in these control structures is kept in host byte
 * order.  However, mac addresses are the exception. They are not
 * manipulated by the code, so they are kept in network byte order.
 *
 */


/* "new kid on the block" list: IPs that have shown life since their capture */

struct nk_s {
  struct addr		nk_mac; 	/* corresponding MAC addr (netwk byte order) */
  time_t 		nk_time; 	/* Time entry will be culled due to inactivity */
};
typedef struct nk_s nk_t;


/* IP ignore list */

struct ipig {
  struct addr 		ipig_addr;
  SLIST_ENTRY(ipig)	ipig_next;
};

SLIST_HEAD(ipig_q, ipig);


/* Main control structure */

struct ctl_s {

  /* Controlling arrays and structures */
  uint8_t		*exclusion;		/* 1 byte / addr in subnet */
  ip_addr_t		*addr_array;		/* IP src addr for last WHO-HAS ARP seen */
  time_t		*time_array;		/* Time of last WHO-HAS ARP */
  uint8_t 		*port_array;		/* 1 byte / port to monitor */
  nk_t	*		*nk_array;		/* "new kids on block: gratuitous arps seen */

  uint32_t		randqueue2[RANDSIZE2];	/* For linux win probe detection */

  struct ipig_q		ipig_q;			/* IP exclude list */


  /* globals */

  char cfg_file_name[BUFSIZE];	/* Configuration file name */
  int  debuglevel;				/* Level of debug output */

  /* capture performance */
  uint32_t throttlesize;	/* Window size for incoming tcp sessions */
  uint32_t currentbytes;	/* # bytes transmitted this minute */
  uint32_t maxbw;		/* User-specified maximum bandwidth - implies persist mode */
  uint32_t newthisminute;	/* # bytes due to new connections still allowed this minute */
  uint32_t totalbytes;		/* Total bytes transmitted over whole history period */
  uint32_t rate;
  uint32_t past[HIST_MIN+1];	/* History array of bandwidth use */
				/*   each entry = bytes for the corresponding minute */
  int soft_restart;		/* used to delay captures for some minutes   */
				/* after startup to avoid having too many    */
				/* connections if scanned during this period */

  int	boolThread;		/* Win32: signal handling */
  char	syslog_server[MAXHOSTNAMELEN]; /* Win32: Remote syslog server */
  int	syslog_port;	/* Win32: Port to use for remote syslog */

  /* capture range */
  ip_addr_t base;		/* Beginning IP addr of range */
  ip_addr_t topend;		/* Ending IP addr of range */
  uint32_t addresses;		/* # addr in range */

  /* flags */
  uint16_t 		feature;
#define FL_EXCL_RESOLV_IPS	0x0001 	/* -X */
#define FL_SAFE_SWITCH		0x0002	/* -s */
#define FL_NO_RESP		0x0004	/* -a */
#define FL_NO_RST_EXCL_PORT	0x0008	/* -f */

  uint16_t		logging;
#define FL_LOG_BDWTH_SYSLOG	0x0001	/* -b */
#define FL_LOG_ODD_ARPS		0x0002 	/* -q */

  uint16_t		capture;
#define FL_CAPTURE		0x0001	/* -x */
#define FL_HARD_CAPTURE		0x0002	/* -h */
#define FL_AUTO_HARD_CAPTURE	0x0004	/* -H */
#define FL_PERSIST_MODE_ONLY	0x0008	/* -P */
#define FL_PERSIST		0x0010	/* -p */


  uint16_t		mode;
#define FL_TESTMODE		0x0001	/* -T */
#define FL_DONT_DETACH		0x0002	/* -d */
#define FL_DONT_NAG		0x0004	/* -z */
#define FL_SOFT_RESTART		0x0008	/* -R */
#define FL_NO_ARP_SWEEP		0x0010

  volatile sig_atomic_t	signals;
#define SIG_RESTART		0x0001
#define SIG_QUIT		0x0002
#define SIG_TIMER		0x0004
#define SIG_TOGGLE_LOGGING	0x0008
};

typedef struct ctl_s ctl_t;
extern ctl_t ctl;

int 	ctl_init_arrays (int wait);
int	ctl_init();

#endif /* CTL_H */
