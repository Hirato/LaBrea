/* labrea.h
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * $Id: labrea.h,v 1.2 2003/09/12 21:23:39 lorgor Exp $
*/

#ifndef LABREA_H
#define LABREA_H

#include "debug.h"

/* set this to FALSE to eliminate the requirement that the user */
/* supply a "-z" to the program to run it.  Make's 'em read */
/* the instructions... */
#define USEZFLAG TRUE

/* #define to LOG_LOCAL0 (see /usr/include/syslog.h ) or whatever */
/* FACILITY to get logging other than log_DAEMON (djs) */
#define LOGFAC LOG_DAEMON

/* define to whatever makes sense to you for your system setup */
#define LOGTYPE LOG_WARNING
#define INFOTYPE LOG_INFO

/* don't mess with these, unless you know what you're doing */

enum timings_sec {
  MAXARPTIME = 60,		/* If nothing happens within 60 sec of original arp req, */
				/*   the whole capturing cycle restarts again */
  ARP_TIMEOUT = 3,		/* Default arp timeout */
  CULLTIME = 2400,	    	/* "New kids" entries are culled after 40 minutes of */
				/*   inactivity */
  PCAP_TIMEOUT = 100,		/* Wait .1 sec for incoming packets before looping to check signals */

  WAKEUP_MSEC = 1000,		/* Thread wakes up every 1 sec to check for termination */
  WAKEUP_SEC = 60			/* Wake up for periodic cleanup every minute */
				/*   Note that the following defines depend on this one */
};


enum timings_min {
  NK_CULL_INTVL = 2,		/* Cull "new kids" queue every 2 min */
				/*   Also controls timing of arp sweeps */
  DYN_PORT_INTVL = 15,		/* Recalculate dynamic ports every 15 min */
  SOFT_RESTART = 5		/* Hold off captures for 5 min on startup */
				/*   to avoid having too many connections */
				/*   if scanned during this time */
};


enum sizes {
  RANDSIZE2 = 12,		/* Keep 12 different random numbers */
  BUFSIZE = 1024,		/* General character buffer size */
  BPFSIZE = 65536,		/* Holds entire bpf filter */
  IP_INP_SIZE = 20,		/* Max length of IP addr when input: xxx.xxx.xxx.xxx/nn */
  ONE_K = 1024,			/* For conversions */
  HIST_MIN = 4,			/* Keep 5 minutes of bandwidth history */
  MAX_NUM_ADAPTER = 10,         /* Windows only: max num of adapters in list */
  PGM_NAME_SIZE = 50		/* Ident tag for syslog */
};

#ifndef MAXHOSTNAMELEN
#define MAXHOSTNAMELEN	256	/* Maximum size of a hostname */
#endif

/* For control of ports */
enum port_constants {
  PORT_IGNORE = 0,		/* Ignore this port */
  PORT_MONITOR = 1,		/* Monitor this port for activity */
  PORT_NUM = 65535,
  PORT_MAX = 255,		/* Max count possible for a given port */
  PORT_NOISE = 6		/* 1st n SYNs to a given port are considered noise */
};


enum perf_constants {
  THROTTLE_WINDOW_ORD = 10,	/* Window size since if no max b/w specified */
  THROTTLE_WINDOW_SLOW = 3,	/* Window size if b/w limited */
  MAX_BW = 1048576,		/* Maximum bandwidth = 1 Gbyte/sec */
  MAX_ARP_BURST = 85,		/* During arp sweeps, not more than 85 at one time */
  MAX_SUBNET_SIZE = 1024	/* Turn off arp sweep for subnets bigger than this */
};

#define ETH_ADDR_BOGUS	"\x00\x00\x0f\xff\xff\xff"
				/* Bogus MAC addr used in IP capture */
#define IP_ADDR_ZEROS	"\x00\x00\x00\x00"
				/* Used in broadcast arps */
#define LOOPBACK	"127.0.0.1"

/* Configuration file directives and types of capture */
enum cfg_type_enum {
  PT_IGNORE,			/* POR */
  IP_MONITOR=0,			/* initial state for ctl.exclusion array */
  IP_EXCLUDE,			/* EXC */
  IP_HARD_EXCLUDE,		/* HAR */
  IP_HARD_CAPTURED,
  IP_IGNORE,			/* IPI */
  PT_MONITOR,			/* PMN */
  IP_INVALID,
  CFG_INVALID			/* Cfg directive invalid or missing */
};

typedef enum cfg_type_enum config_t;


#ifndef FALSE
#define FALSE   0
#endif

#ifndef TRUE
#define TRUE    1
#endif

#define MYFREE(x) free(x); x = NULL;
#define SWAP(A, B)	((A) ^= (B) ^= (A) ^= (B))

/* Defines to eliminate some ifdefs in the code */
#ifndef WIN32
#define	WIN32_FLG FALSE
#else
#define WIN32_FLG TRUE
#endif

#ifdef WIN32
static inline void setlinebuf(void *iobuf) {}
#endif

void 	labrea_init(int argc, char **argv);


#endif /* LABREA_H */
