/* lbio.h
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
 * $Id: lbio.h,v 1.2 2003/09/12 21:23:39 lorgor Exp $
*/

#ifndef LBIO_H
#define LBIO_H

#include <pcap.h>

/* Main IO ctl structure */

struct io_s {
 
  /* control structures (mostly uses netwk byte order) */
  struct intf_entry	*ifent;		/* Interface */
  ip_addr_t		myip;		/* My own IP addr (in host byte order) */
  struct addr		*mymac;     	/* My own IP MAC addr */
  struct addr		*bogus_mac;	/* Bogus mac addr */
  struct pkt		*bcast;		/* Contains broadcast ARP WHO HAS for */
  					/*    switch environment */

  /* global variables */
  u_char		buf[BUFSIZE];
  int		    	mtu;
  int			dloff;		/* Data link offset */
  uint32_t		net;		/* Subnet for capture */
  uint32_t		mask;		/* Netmask for capture */

  /* Declarations for WinPcap list */
  char        		adapter_name_list[MAX_NUM_ADAPTER][BUFSIZE];
					/* WinPcap driver adapter name */
  char        		adapter_desc_list[MAX_NUM_ADAPTER][BUFSIZE];
					/* Adapter descriptions */
  int		  	adapter_total_num;	/* total # adapters in all */
  int		  	adapter_num;
  int		  	intf_num;

  /* handles */
  eth_t			*eth;
  intf_t		*intf;
  pcap_t		*pcap;
  rand_t 		*rnd;
};

typedef struct io_s io_t;
extern io_t io;			/* Let others get at this structure */

void		lbio_init(u_char *dev, u_char *texpr);
int		lbio_send_pkt(const struct pkt *pkt);
int		lbio_send_ip_pkt (struct pkt *new, const struct pkt *pkt,
				  const uint16_t ipl, const u_char *msg);
uint32_t	lbio_rand(void);
void		lbio_send_ARP_Who_Has (ip_addr_t tpa);
void		lbio_send_bogus_ARP (const ip_addr_t tpa, const struct pkt *pkt);
void		lbio_close(void);
char        	*lbio_ntoa (const ip_addr_t ip);
int		lbio_ip_offset (const ip_addr_t ip, ip_addr_t *offset);
int		lbio_print_libdnet_intf_list(void);
int		lbio_print_pcap_adapter_list(void);

#endif /* LBIO_H */
