/*
 * LaBrea
 *
 * A program to create a tar pit for the connection attempts to a
 * block of ip addresses. LaBrea sits and listens for ARP "who-has"
 * requests.  When an ARP request for a particular IP goes unanswered
 * for longer than it's "rate" setting (default: 3 seconds), LaBrea
 * crafts an ARP reply that routes all traffic destined for the IP to
 * a "bogus" MAC address.  LaBrea then listens for TCP/IP traffic
 * routed to that MAC address and then responds to any SYN packet with
 * a SYN/ACK packet that it creates.
 *
 * LaBrea completely ignores any other input.  This, forces the
 * "client" to wait for its TCP stack to time-out the connection.
 * Because stacks tend to be a bit tenacious about "established"
 * connections, this should bog down the scanner for quite a long
 * while.
 *
 * THIS PROGRAM REQUIRES BOTH LIBDNET and LIBPCAP in order to compile.
 *
 * Copyright (C) 2001, 2002 Tom Liston <tliston@premmag.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 *
 * $Id: labrea.c,v 1.2 2003/09/09 20:49:24 lorgor Exp $ */

#include "config.h"

#ifdef HAVE_ERR_H
#include <err.h>
#else
#include "err.h"
#endif


#include "labrea.h"
#include "ctl.h"
#include "utils.h"
#include "lbio.h"
#include "pkt_handler.h"

/* Definitions of main control structures */
io_t io;
ctl_t ctl;
outp_t outp;

int
main (int argc, char **argv)
{
  labrea_init(argc, argv);	/* Do initialisation */

  if (!WIN32_FLG) 
    util_detach();		/* Fork to become a daemon if unix*/

  util_set_signal_handlers();

  util_alarm();			/* Set an alarm to cause timer pop */

  util_print(NORMAL,"Labrea started");

  /* loop! */
  for(;;) {
    if (pcap_dispatch(io.pcap, -1, &pkt_handler, (u_char *)&ctl) < 0) {
      util_print(NORMAL, "Error in pcap loop - EXITING: %s", pcap_geterr(io.pcap));
      util_clean_exit(1);
    }

    /* Handle signal(s) if set */
    if (ctl.signals) {
      if (ctl.signals & SIG_RESTART)
	util_restart();
      if (ctl.signals & SIG_QUIT)
	util_quit();
#ifndef WIN32
      if (ctl.signals & SIG_TIMER)
	util_timer();
      if (ctl.signals & SIG_TOGGLE_LOGGING)
	util_toggle_logging();
#endif
    }
  }
  util_clean_exit(0);
}
