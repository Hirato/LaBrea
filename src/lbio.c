/*
 * lbio.c
 *
 * This file is part of the LaBrea package
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
 * $Id: lbio.c,v 1.1 2003/01/09 18:13:19 lorgor Exp $ */


#include "config.h"



#include <string.h>
#include <assert.h>

#ifdef HAVE_ERR_H
#include <err.h>
#else
#include "err.h"
#endif

#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif

#include "labrea.h"
#include "bget.h"
#include "pkt.h"
#include "ctl.h"
#include "utils.h"
#include "pcaputil.h"
#include "lbio.h"

#ifdef WIN32
/* has to be here to avoid compile errors with bpf structs */
#include <Packet32.h>
#endif



/*
 * Windows-only
 *
 * Build list of WinPcap device driver adapters
 *
 * returns 0	no errors detected
 *		-1		error when opening interfaces
 *
 * 2002-10-5 Note that libdnet 2.5 requires WinPcap 2.3. In this version, you
 * have to interface directly with the packet driver to get the list of 
 * devices. In WinPcap 3.0, the pcap_findalldevs function is introduced, and
 * this code should be updated to use the new function.
 *
 * This code was adapted from WinPcap 2.3 examples and libdnet 1.5.
 */

int
build_pcap_adapter_list (void)
{
#ifdef WIN32
	
  /* Declarations for WinPcap information */
  int			i=0,j=0;

  /* Unicode strings for WinNT and later */
  WCHAR		adapter_list[MAX_NUM_ADAPTER*2*BUFSIZE];
				/* string that contains a list of the network adapters */
  WCHAR 		*name;		/* Name of adapter in list */

  /* Ascii strings for Win98 / WinME */
  char		adapter_lista[MAX_NUM_ADAPTER*2*BUFSIZE]; /* list of adapters */
  char		*namea;		/* Name of adapter */

  char		*desc;		/* Description of adapter in list */

  ULONG		adapter_length;

  if (!util_check_version_win98()) {
    warnx("*** This version of Windows is not supported.\n"
	  "*** System must be Windows 98 or better");
    return(-1);
  }

  util_print(VERBOSE,"WinPcap library version:%s\n", PacketGetVersion());

  /* 
   * Get information from WinPcap.about driver adapters.
   * This is needed because eth_send opens a WinPcap device.
   */

  if (util_check_version_winNT()) {
    adapter_length= sizeof(adapter_list) / sizeof(adapter_list[0]);

    if(PacketGetAdapterNames((PTSTR)adapter_list,&adapter_length)==FALSE){
      warnx("*** Unable to retrieve the list of the adapters");
      return (-1);
    }

    for (name = adapter_list, i = 0;
	 *name != '\0' && i < MAX_NUM_ADAPTER; i++) {
      wcstombs(io.adapter_name_list[i], name, sizeof(io.adapter_name_list[0]));
      while (*name++ != '\0')
	;
    }
    for (desc = (char *)name + 2, j = 0;
	 *desc != '\0' && j < MAX_NUM_ADAPTER; j++) {
      strlcpy(io.adapter_desc_list[j], desc,
	      sizeof(io.adapter_desc_list[0]));
      while (*desc++ != '\0')
	;
    }

    /*
     * Windows 95 - 98 - ME is in ascii
     */
  } else {
    adapter_length= sizeof(adapter_lista) / sizeof(adapter_lista[0]);
		
    if(PacketGetAdapterNames((PTSTR)adapter_lista,&adapter_length)==FALSE){
      warnx("*** Unable to retrieve the list of the adapters");
      return (-1);
    }

    for (namea = adapter_lista, i = 0;
	 *namea != '\0' && i < MAX_NUM_ADAPTER; i++) {
      strlcpy(io.adapter_name_list[i], namea, sizeof(io.adapter_name_list[0]));
      while (*namea++ != '\0')
	;
    }
    for (desc = (char *)namea + 1, j = 0;
	 *desc != '\0' && j < MAX_NUM_ADAPTER; j++) {
      strlcpy(io.adapter_desc_list[j], desc,
	      sizeof(io.adapter_desc_list[0]));
      while (*desc++ != '\0')
	;
    }
  }
  io.adapter_total_num=i;
#endif
  return (0);
}

/*
 * Windows-only
 *
 * Opens the nth WinPcap device driver adapter and libdnet eth interface
 *
 * returns		0			no errors detected
 *				-1          errors
 */

int
open_winpcap_adapter()
{
#ifdef WIN32
  int j=0;

  /* 
   * Get information from WinPcap.about driver adapters.
   * This is needed because eth_send opens a WinPcap device.
   */
  if (build_pcap_adapter_list() < 0) {
    warnx("*** Problem building WinPcap adapter list.");
    return(-1);
  }

  j = io.adapter_num <= 0 ?  0 : io.adapter_num - 1;
  /* default is the first adapter in the list */

  util_print(VERBOSE,"Using WinPcap adapter %d\n   %s\n    %s",
	     io.adapter_num, io.adapter_name_list[j], io.adapter_desc_list[j]);

  /*
   * Open the WinPcap device for sniffing
   */
  if ((io.pcap = pcap_open(io.adapter_name_list[j])) == NULL) {
    warnx("*** Couldn't open WinPcap adapter" );
    return(-1);
  }

  /*
   * Open libdnet link interface for raw packet output
   */
  if ((io.eth = eth_open(io.adapter_desc_list[j])) == NULL ) {
    warnx("*** Couldn't open libdnet raw link device");
    return(-1);
  }
#endif
  return(0);
}


/*
 * Callback rtn for libdnet's intf_loop
 *
 * Called once for each interface, and choses first that is:
 *		- not the loopback.
 *		- Ethernet
 */

static int
_find_intf(const struct intf_entry *entry, void *arg)
{
  struct addr *a = (struct addr *)arg;
   
  if ((entry->intf_addr.addr_type == ADDR_TYPE_IP) &&
      (entry->intf_addr.addr_ip != a->addr_ip) &&
      (entry->intf_link_addr.addr_type == ADDR_TYPE_ETH)) {
    /*
     * We've found an interface but intf_loop returns
     * an ephemeral intf_entry in the stack
     * so must copy it to more permanent storage
     */
    io.ifent = (struct intf_entry *)io.buf;
    assert(entry->intf_len <= sizeof(io.buf));
    memcpy(io.ifent, entry, entry->intf_len);
    return (TRUE); 
  }
  return (FALSE);		/* Keep on looking */
}

/*
 * Windows-only Callback rtn for libdnet's intf_loop
 *
 * Called once for each interface, and choses n-th interface.
 *
 */

static int
_find_intf_win(const struct intf_entry *entry, void *arg)
{
  int *n = (int *)arg;
  (*n)--;

  if (*n == 0) {
    /*
     * We've found an interface but intf_loop returns
     * an ephemeral intf_entry in the stack
     * so must copy it to more permanent storage
     */
    io.ifent = (struct intf_entry *)io.buf;
    assert(entry->intf_len <= sizeof(io.buf));
    memcpy(io.ifent, entry, entry->intf_len);
    return (TRUE);
  }
  else
    return (FALSE);
}


/* 
 * Initialize IO
 *		dev		device name (unix)
 *		texpr	bpf filter expression
 */

void
lbio_init(u_char *dev, u_char *texpr)
{
  struct addr loopback;
  int dev_cnt = io.intf_num;
  ip_addr_t ip_tmp = 0;		/* For construction of ARP Who-Has */
  
  io.rnd = rand_open();		/* Initialize the libdnet random # generation */

  /* Get the interface handle */
  if ((io.intf = intf_open()) == NULL) {
    warnx("*** Unable to get libdnet handle for interface %s \n", io.ifent->intf_name);
    util_clean_exit(1);
  }

  addr_aton(LOOPBACK, &loopback);

  /*
   * Windows-specific device initialisation
   */
  if (WIN32_FLG) {

    if(io.myip == 0) {
      if (io.intf_num > 0){
	/*
	 * Open user-specified interface
	 */
	if (intf_loop(io.intf, _find_intf_win, &dev_cnt) <= 0) {
	  warnx("*** Unable to get information for libdnet interface %d\n",
		io.intf_num);
	  util_clean_exit(1);
	}
	if (io.ifent->intf_addr.addr_type == ADDR_TYPE_IP &&
	    io.ifent->intf_addr.addr_ip == loopback.addr_ip) {
	  warnx("*** The Loopback interface 127.0.0.1 cannot be used");
	  util_clean_exit(1);
	}
      } else {
	/*
	 * Loop through the interfaces looking for one that is:
	 *	- not a loopback
	 *	- Ethernet
	 */
	if (intf_loop(io.intf, _find_intf, &loopback) <= 0) {
	  warnx("*** Unable to find a suitable interface to open\n");
	  util_clean_exit(1);
	}
      }
      util_print(VERBOSE,
		 "Libdnet interface to be used to determine IP / MAC addresses:\n   %s",
		 io.ifent->intf_name);
    }

    /* open WinPcap device */
	
    if (open_winpcap_adapter() < 0)
      util_clean_exit(1);

    /*
     * Unix-specific device initialisation
     */
  } else {
    if (strlen(dev) > 0) {
      /*
       * User-specified device name
       */
      io.ifent = (struct intf_entry *)io.buf;
      io.ifent->intf_len = sizeof(io.buf);
      strlcpy(io.ifent->intf_name, dev, sizeof(io.ifent->intf_name));

      if (intf_get(io.intf, io.ifent) < 0) {
	warnx("*** Unable to get information for interface %s\n", io.ifent->intf_name);
	util_clean_exit(1);
      }
    } else {
      /*
       * Loop through the interfaces looking for one that is:
       *  - not a loopback
       *	- Ethernet
       */
      if (intf_loop(io.intf, _find_intf, &loopback) <= 0) {
	warnx("*** Unable to find a suitable interface to open\n");
	util_clean_exit(1);
      } 
    }

    /* open our pcap device for sniffing */
    if ((io.pcap = pcap_open(io.ifent->intf_name)) == NULL) {
      warnx("*** Couldn't open pcap device for sniffing" );
      util_clean_exit(1);
    }

    /* open link interface for raw packet output */
    if ((io.eth = eth_open(io.ifent->intf_name)) == NULL ) {
      warnx("*** Couldn't open libdnet link interface");
      util_clean_exit(1);
    }
    util_print(NORMAL, "Initiated on interface: %s", io.ifent->intf_name);
  }

  /*
   * If the host system IP address is not set yet,
   * then pick it up from the interface as well as
   * the capture subnet information
   */
  if (io.myip == 0) {
    if (io.ifent->intf_addr.addr_type == ADDR_TYPE_IP) {    
      if (io.mask == 0) {		/* Initialise net/mask from interf. info */
	addr_btom(io.ifent->intf_addr.addr_bits, &io.mask, IP_ADDR_LEN);
	io.mask = ntohl(io.mask);
	io.net = ntohl(io.ifent->intf_addr.addr_ip);
	io.net &= io.mask;
      }
    
      /* remember our IP address so that can build arps for virtual servers */
      io.myip = ntohl(io.ifent->intf_addr.addr_ip);
    } else {
      warnx("*** Unable to determine IP address from the interface." );
      util_clean_exit(1);
    }
  }
  /*
   * Same thing for the system MAC address
   */
  if (io.mymac == NULL) {	
    if (io.ifent->intf_link_addr.addr_type == ADDR_TYPE_ETH) {
      io.mymac = &(io.ifent->intf_link_addr);
    } else {
      warnx("*** The interface must be of type Ethernet." );
      util_clean_exit(1);
    }
  }

  util_print(VERBOSE, "Host system IP addr: %s, MAC addr: %s",
	     lbio_ntoa(io.myip), addr_ntoa(io.mymac));

  if ((io.dloff = pcap_dloff(io.pcap)) < 0) {
    warnx("*** Couldn't determine link layer offset" );
    util_clean_exit(1);
  }

  /* compile our BPF filter and attach it to the datalink */
  if (pcap_filter(io.pcap, texpr) < 0) {
    warnx("*** Either pcap filter is invalid or error in activation of filter" );
    util_clean_exit(1);
  }

  /* calculate max possible addresses in our netblock; allocate buffer pool */
  if (ctl.capture & FL_CAPTURE) {
    if ((io.mask == 0) || (io.myip == 0)) {
      warnx("*** System IP address or host mask is invalid.");
      util_clean_exit(1);
    }
    ctl.addresses = io.mask ^ 0xFFFFFFFF;
    pkt_init(ctl.addresses+100);	/* Initialize bget pkt pool */
  } else {
    ctl.addresses = 0;
    pkt_init(100);
  }

  /* set our base address */
  ctl.base = io.net;
  ctl.topend = ctl.base + ctl.addresses;

  /* allocate arp pkt used for WHO-HAS */

  if ((io.bcast = pkt_new()) == NULL) {
    warnx("*** Problem allocating WHO-HAS arp pkt");
    util_clean_exit(1);
  }
  io.bcast->pkt_end = io.bcast->pkt_data + ETH_HDR_LEN + ARP_HDR_LEN + ARP_ETHIP_LEN;
  io.bcast->pkt_arp = (struct arp_hdr *) (io.bcast->pkt_data + ETH_HDR_LEN);
  io.bcast->pkt_arp_data = (struct arp_ethip *) (io.bcast->pkt_data + ETH_HDR_LEN + ARP_HDR_LEN);
  ip_tmp = htonl(io.myip);

  /* build broadcast arp WHO HAS pkt used in switch environments */
  
  arp_pack_hdr_ethip( io.bcast->pkt_arp,
		      ARP_OP_REQUEST,
		      io.mymac->addr_eth,   /* We are the sender  */
		      ip_tmp,
		      ETH_ADDR_BROADCAST, 	/* Target is broadcast to find */
		      IP_ADDR_ZEROS);		/*    some IP addr */
		     
  eth_pack_hdr( io.bcast->pkt_eth,
		ETH_ADDR_BROADCAST, 		/* Broadcast addr */
		io.mymac->addr_eth,         /* our mac becomes src MAC */
		ETH_TYPE_ARP);

  pkt_decorate(io.bcast);

  /* allocate and build bogus mac addr structure */
  
  if ((io.bogus_mac = bget(sizeof(struct addr))) == NULL) {
    warnx("*** Problem allocating bogus mac addr structure");
    util_clean_exit(1);
  }
  addr_pack(io.bogus_mac, ADDR_TYPE_ETH, ETH_ADDR_BITS,
	    ETH_ADDR_BOGUS, ETH_ADDR_LEN);
}


/*
 * Send pkt "pkt" out the raw interface
 */

int
lbio_send_pkt(const struct pkt *pkt)
{
  int i = 0;
  
  i = eth_send(io.eth, pkt->pkt_eth, pkt->pkt_end - (u_char *) pkt->pkt_eth);
  return(i);
}


/* 
 * Finish building the new tcp pkt "new", using information in
 * original pkt "pkt", and send out raw interface. Then log a message
 * using text "msg"
 *
 * new		pkt to be sent
 * pkt		original pkt
 * ipl		length of ip pkt
 * msg		msg for log
 */
int
lbio_send_ip_pkt (struct pkt *new, const struct pkt *pkt,
		  const uint16_t ipl, const u_char *msg)
{
  u_char c[] = "*";
  static int star=FALSE;
  int ret_code = 0;

  eth_pack_hdr( new->pkt_eth,
		pkt->pkt_eth->eth_src, /* orig src MAC becomes new dest MAC */
		ETH_ADDR_BOGUS,    /* bogus mac becomes new src MAC */
		ETH_TYPE_IP);

  
  ip_pack_hdr( new->pkt_ip,
	       0,			/* tos */
	       ipl, 			/* IP hdr length */
	       rand_uint16( io.rnd ), 	/* ipid */
	       0,			/* frag offset */
	       IP_TTL_DEFAULT,
	       pkt->pkt_ip->ip_p, 	/* ip protocol of original pkt */
	       pkt->pkt_ip->ip_dst, 	/* orig dst becomes new src addr */
	       pkt->pkt_ip->ip_src );
	       
  ip_checksum(new->pkt_ip,
	      new->pkt_end - new->pkt_eth_data);


  if ((ret_code = lbio_send_pkt(new)) < 0)
    warnx("*** Problem sending packet");

  pkt_free(new);

  if (msg == NULL)
    return(ret_code);

  if (star) {			/* Flip-flop "*" on output to avoid messages in log */
    strncpy(c, " ", sizeof(c));
    star = FALSE;
  } else
    star = TRUE;

  if (pkt->pkt_ip->ip_p == IP_PROTO_TCP)
    util_print(VERBOSE, "%s: %s %i -> %s %i %s", msg,
	       ip_ntoa(&(pkt->pkt_ip->ip_src)), ntohs(pkt->pkt_tcp->th_sport),
	       ip_ntoa(&(pkt->pkt_ip->ip_dst)), ntohs(pkt->pkt_tcp->th_dport), c);
  else
    util_print(VERBOSE, "%s: %s -> %s %s", msg,
	       ip_ntoa(&(pkt->pkt_ip->ip_src)), 
	       ip_ntoa(&(pkt->pkt_ip->ip_dst)), c);

  return(ret_code);
}


/*
 * Generate a random number
 */

uint32_t
lbio_rand(void)
{
  return( rand_uint32(io.rnd) );
}


/*
 * If we are in a switched environment, send our own ARP to be sure
 * that the IP is unused before capturing it.  pkt is the incoming ARP
 * request.
 *
 */
void
lbio_send_ARP_Who_Has (const ip_addr_t tpa)
{
  ip_addr_t tpa_tmp = htonl(tpa);

  DEBUG_PRT(DEBUG_PKTPROC, "lbio_send_ARP_Who_Has: tpa %s",
	    lbio_ntoa(tpa));

  memmove(&(io.bcast->pkt_arp_data->ar_tpa), 
	  &tpa_tmp, sizeof(ip_addr_t));

  eth_send(io.eth, io.bcast->pkt_eth, 
	   io.bcast->pkt_end - (u_char *) io.bcast->pkt_eth);
}



/*
 * Build and send a bogus ARP reply to capture an IP address
 *
 * tpa -> addr IP to be captured
 * pkt -> incoming ARP request pkt
 *
 */
void
lbio_send_bogus_ARP (const ip_addr_t tpa, const struct pkt *pkt)
{
  ip_addr_t ip_tmp;		/* For construction of packets */
  struct pkt *bogus;		/* Contains bogus ARP reply used for */
				/*    IP capturing*/

  ip_tmp = htonl(tpa);

  if ((bogus = pkt_new()) == NULL) {
    warnx("*** Problem initializing bogus arp pkt");
    util_clean_exit(1);
  }

  DEBUG_PRT(DEBUG_PKTPROC, "lbio_send_bogus_ARP: tpa %s",
	    lbio_ntoa(tpa));

  bogus->pkt_end = bogus->pkt_data + ETH_HDR_LEN + ARP_HDR_LEN + ARP_ETHIP_LEN;
  bogus->pkt_arp = (struct arp_hdr *) (bogus->pkt_data + ETH_HDR_LEN);

  arp_pack_hdr_ethip(bogus->pkt_arp,
		     ARP_OP_REPLY,
		     ETH_ADDR_BOGUS,		/* Bogus MAC is the "sender" */
		     ip_tmp,		 	/* for the IP addr that was asked for */
		     pkt->pkt_arp_data->ar_sha,	/* Answer is going back to requestor's	*/
		     pkt->pkt_arp_data->ar_spa); /*    MAC and IP addr 	*/

  eth_pack_hdr( bogus->pkt_eth,
		pkt->pkt_eth->eth_src,	/* Src MAC becomes the new dest MAC 	*/
		ETH_ADDR_BOGUS,		/* Response is from bogus virtual machine  */
		ETH_TYPE_ARP);

  pkt_decorate(bogus);

  lbio_send_pkt(bogus);
  pkt_free(bogus);

  util_print(NORMAL, "Capturing local IP %s", lbio_ntoa(tpa));
}


/*
 * Close I/O and associated services
 *
 */
void
lbio_close (void)
{
  struct pcap_stat stat;

  /* clean up our pcap stuff */
  if(io.pcap != NULL) {
    /* show 'em some stats... */
    if(pcap_stats(io.pcap, &stat) >= 0) {
      util_print(NORMAL, "%d/%d packets (received/dropped) by filter",
		 stat.ps_recv, stat.ps_drop); 
    }
    pcap_close(io.pcap);
  }

  /* clean up our libdnet stuff */
  if (io.rnd != NULL)
    rand_close(io.rnd);
  if (io.eth != NULL)
    eth_close(io.eth);

  /* Free pre-allocated arp pkts */
  if (io.bcast != NULL)
    pkt_free(io.bcast);
}

/*
 * Format IP address for printing
 *
 */
char *
lbio_ntoa (const ip_addr_t ip) {
  ip_addr_t ip_tmp = htonl(ip);

  return(ip_ntoa(&ip_tmp));
}


/*
 * convert IP address into offset in control arrays
 *
 * ip		address to be converted
 * offset	ptr to result
 *
 * returns	0	no errors detected
 *		-1	address is not valid
 */

int
lbio_ip_offset (const ip_addr_t ip, ip_addr_t *offset)
{
  ip_addr_t ip_tmp = ntohl(ip);

  if (ip_tmp < ctl.base) {
    util_print(VERY_VERBOSE,
	       "*** IP address %s is before start of capture subnet - Ignoring",
	       ip_ntoa(&ip) );
    return(-1);
  }
  *offset =  ip_tmp - ctl.base; /* convert to relative offset in range */
  if ((*offset) > ctl.addresses){
    util_print(VERY_VERBOSE,
	       "*** IP address %s is after end of capture subnet - Ignoring",
	       ip_ntoa(&ip));
    return(-1);
  }
  return(0);
}

/*
 * Windows-only
 *
 * Print list of libdnet interfaces
 *
 * returns 0	no errors detected
 *		-1		error when opening interfaces
 *
 *
 * 2002-11-7 Note that both the libdnet interface and the WinPcap device
 *           driver adapter are abstractions for the NIC. Unfortunately, the
 *           human-readable description supplied by the libraries does not
 *           match. So cannot correlate from one to the other.
 *           
 *           When doing packet I/O, it is the WinPcap driver adapter API that
 *           is used.
 *  
 *           However, Labrea needs also to know the home system NIC's IP
 *           and MAC addresses in order to do ARP WHO-HAS among other things.
 *           The libdnet inferface API is used to determine this information.
 *
 *           If there are multiple possibilities, we let the user tell us
 *           which one to use from both lists.
 */

#ifdef WIN32
static int
_print_intf(const struct intf_entry *entry, void *arg)
{
  int *(n) = (int *)arg;
  struct addr loopback; /* Loopback is not allowed */
  static int look_for_default;
  uint32_t mask;

  /* Get set to search for default interface */
  if (*n == 0) 
    look_for_default = TRUE;

  (*n)++;	
  printf("%d    %s:\n", *n, entry->intf_name);

  addr_aton(LOOPBACK, &loopback);
  if (entry->intf_addr.addr_type == ADDR_TYPE_IP) {
    addr_btom(entry->intf_addr.addr_bits, &mask, IP_ADDR_LEN);
    mask = ntohl(mask);
    printf("\tinet %s netmask 0x%x\n",
	   ip_ntoa(&entry->intf_addr.addr_ip),  mask);

    if (entry->intf_link_addr.addr_type == ADDR_TYPE_ETH) {
      printf("\tlink %s\n", addr_ntoa(&entry->intf_link_addr));

      /*
       * If still searching for the default interface
       * and this is not the loopback interface, then
       * have found it.
       */
      if (look_for_default &&
	  (entry->intf_addr.addr_ip != loopback.addr_ip)) {
	printf("===> Default interface\n\n");
	look_for_default = FALSE;
      }
    }
  }
  return (0);
}
#endif

int
lbio_print_libdnet_intf_list (void)
{
#ifdef WIN32
  intf_t	*intf;
  int num_intf=0;
	
  if (!util_check_version_win98()) {
    warnx("*** This version of Windows is not supported.\n"
	  "*** System must be Windows 98 or better");
    return(-1);
  }

  /*
   * Get information from libdnet intf_xx functions.
   * For Windows, this comes from the Win32 MIB-II snmp functions.
   * Needed to get IP / MAC address.
   */

  printf(
	 "*** Libdnet interface list ***\n\n"
	 "* In order to determine the interface's IP and MAC addresses,\n"
	 "Labrea looks through the following list for the the first Ethernet\n"
	 "interface that is not the loopback interface.\n"
	 "* To override this behaviour and select interface m, specify:\n"
	 "			-j m\n"
	 "or manually specify the values to use:\n"
	 "           -I nnn.nnn.nnn.nnn -E xx:xx:xx:xx\n"
	 "* Note that the interface and the driver adapter MUST refer to the\n"
	 "same physical NIC (network interface card).\n\n");
  if ((intf = intf_open()) == NULL)
    err(1, "intf_open");

  if (intf_loop(intf, _print_intf, &num_intf) < 0)
    warnx("*** Error in libdnet intf_loop. Note that on Win98, you \n"
	  "must manually specify the NIC IP and MAC addresses (-I -E).");
  printf("*** End of libdnet interface list ***\n");
#endif
  return (0);
}


/*
 * Windows-only
 *
 * Print list of WinPcap device driver adapters
 *
 * returns 0	no errors detected
 *		-1		error when opening interfaces
 */

int
lbio_print_pcap_adapter_list (void)
{
#ifdef WIN32
	
  int			i=0;

  printf(
	 "\n*** WinPcap driver adapter list\n\n"
	 "* Labrea uses the driver adapter to access the network.\n"
	 "The default is to use the first adapter in the list.\n"
	 "To override this behaviour and select adapter \"n\", specify\n"
	 "		-i n\n");

  if (build_pcap_adapter_list() < 0) {
    warnx("*** Unable to build WinPcap driver adapter list");
    return(-1);
  }
  /*
   * Now print out the resulting list
   */
  for (i=0; i<io.adapter_total_num;i++) {
    printf("%d- %s\n\t%s\n",i+1,io.adapter_name_list[i],
	   io.adapter_desc_list[i]);
    if (i == 0)
      printf("===> Default adapter\n\n");
  }

  printf("*** End of WinPcap Adapter list ***\n\n");
#endif
  return (0);
}

