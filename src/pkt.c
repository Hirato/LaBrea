/*
 * pkt.c
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
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * $Id: pkt.c,v 1.2 2003/09/12 21:23:39 lorgor Exp $
 */

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "bget.h"
#include "pkt.h"

void
pkt_init(int size)
{
  bectl(NULL, malloc, free, sizeof(struct pkt) * size);
}


/*
 * Allocates new IP/ARP packet.
 *
 */
struct pkt *
pkt_new(void)
{
  struct pkt *pkt;
	
  if ((pkt = bget(sizeof(*pkt))) == NULL)
    return (NULL);
       
  pkt->pkt_data = pkt->pkt_buf + PKT_BUF_ALIGN;
  pkt->pkt_eth = (struct eth_hdr *)pkt->pkt_data;
  pkt->pkt_eth_data = pkt->pkt_data + ETH_HDR_LEN;
  pkt->pkt_ip_data = pkt->pkt_data + ETH_HDR_LEN + IP_HDR_LEN;
  pkt->pkt_tcp_data = NULL;
  pkt->pkt_end = pkt->pkt_ip_data;
	
  return (pkt);
}

struct pkt *
pkt_dup(struct pkt *pkt)
{
  struct pkt *new;
  off_t off;
	
  if ((new = bget(sizeof(*new))) == NULL)
    return (NULL);
	
  off = new->pkt_buf - pkt->pkt_buf;
	
  new->pkt_data = pkt->pkt_data + off;
	
  new->pkt_eth = (pkt->pkt_eth != NULL) ?
    (struct eth_hdr *)new->pkt_data : NULL;
	
  new->pkt_eth_data = (pkt->pkt_eth_data != NULL) ?
    pkt->pkt_eth_data + off : NULL;
	
  new->pkt_ip_data = (pkt->pkt_ip_data != NULL) ?
    pkt->pkt_ip_data + off : NULL;
	
  new->pkt_tcp_data = (pkt->pkt_tcp_data != NULL) ?
    pkt->pkt_tcp_data + off : NULL;
	
  memcpy(new->pkt_data, pkt->pkt_data, pkt->pkt_end - pkt->pkt_data);
	
  new->pkt_end = pkt->pkt_end + off;
	
  return (new);
}

/*
 * Validates the contents and length fields of a packet.
 * Progressively sets up ptrs to the various sub-structures.
 *
 * On return, some or all of the following ptrs will be initialized
 * depending type of pkt and which parts of the pkt are valid:
 *
 * pkt->pkt_data		Beginning of packet
 * pkt->pkt_eth			Ethernet hdr
 * pkt->pkt_ip			IP (or ARP) hdr
 * pkt->pkt_ip_data		ICMP or Tcp or Udp hdr
 * pkt->pkt_tcp_data		ICMP msg or Tcp data
 * pkt->pkt_end			End of packet
 *
 * See pkt.h for the details.
 */
void
pkt_decorate(struct pkt *pkt)
{
  u_char *p;
  int hl, len, off;

  pkt->pkt_data = pkt->pkt_buf + PKT_BUF_ALIGN;
  pkt->pkt_eth = NULL;
  pkt->pkt_ip = NULL;
  pkt->pkt_ip_data = NULL;
  pkt->pkt_tcp_data = NULL;

  p = pkt->pkt_data;
	
  if (p + ETH_HDR_LEN > pkt->pkt_end)
    return;			/* Ignore pkt if not at least a complete ethernet hdr */

  pkt->pkt_eth = (struct eth_hdr *)p;
  p += ETH_HDR_LEN;
  pkt->pkt_eth_data = p;

  switch (ntohs(pkt->pkt_eth->eth_type)){
  case ETH_TYPE_IP:
    if (p + IP_HDR_LEN > pkt->pkt_end) /* Check if IP hdr too short */
      return;    
    break;

  case ETH_TYPE_ARP:
    if (p + ARP_HDR_LEN > pkt->pkt_end)	/* Check if arp hdr too short */
      return;

    pkt->pkt_arp = (struct arp_hdr *)p;
    p += ARP_HDR_LEN;

    /* Ensure arp is for Ethernet / IP */
    if ((ntohs(pkt->pkt_arp->ar_hrd) != ARP_HRD_ETH) ||
	(ntohs(pkt->pkt_arp->ar_pro) != ARP_PRO_IP) ||
	(pkt->pkt_arp->ar_hln != ETH_ADDR_LEN) ||
	(pkt->pkt_arp->ar_pln != IP_ADDR_LEN)) {
      pkt->pkt_arp = NULL;
      return;
    }
    pkt->pkt_arp_data = (struct arp_ethip *)p;
    if (p + ARP_ETHIP_LEN < pkt->pkt_end)
      pkt->pkt_end = p + ARP_ETHIP_LEN;

    return;
    /* break; */

  default:
    return;
  }
	
  /* If IP header length is longer than packet length, stop. */
  hl = pkt->pkt_ip->ip_hl << 2;
  if (p + hl > pkt->pkt_end) {
    pkt->pkt_ip = NULL;
    return;
  }
  /* If IP length is longer than packet length, stop. */
  len = ntohs(pkt->pkt_ip->ip_len);
  if (p + len > pkt->pkt_end)
    return;

  /* If IP fragment, stop. */
  off = ntohs(pkt->pkt_ip->ip_off);
  if ((off & IP_OFFMASK) != 0 || (off & IP_MF) != 0)
    return;
	
  pkt->pkt_end = p + len;
  p += hl;

  /* If transport layer header is longer than packet length, stop. */
  switch (pkt->pkt_ip->ip_p) {
  case IP_PROTO_ICMP:
    hl = ICMP_HDR_LEN;
    break;
  case IP_PROTO_TCP:
    if (p + TCP_HDR_LEN > pkt->pkt_end)
      return;
    hl = ((struct tcp_hdr *)p)->th_off << 2;
    break;
  case IP_PROTO_UDP:
    hl = UDP_HDR_LEN;
    break;
  default:
    return;
  }
  if (p + hl > pkt->pkt_end)
    return;
	
  pkt->pkt_ip_data = p;
  p += hl;

  /* Check for transport layer data. */
  switch (pkt->pkt_ip->ip_p) {
  case IP_PROTO_ICMP:
    pkt->pkt_icmp_msg = (union icmp_msg *)p;
		
    switch (pkt->pkt_icmp->icmp_type) {
    case ICMP_ECHO:
    case ICMP_ECHOREPLY:
      hl = sizeof(pkt->pkt_icmp_msg->echo);
      break;
    case ICMP_UNREACH:
      if (pkt->pkt_icmp->icmp_code == ICMP_UNREACH_NEEDFRAG)
	hl = sizeof(pkt->pkt_icmp_msg->needfrag);
      else
	hl = sizeof(pkt->pkt_icmp_msg->unreach);
      break;
    case ICMP_SRCQUENCH:
    case ICMP_REDIRECT:
    case ICMP_TIMEXCEED:
    case ICMP_PARAMPROB:
      hl = sizeof(pkt->pkt_icmp_msg->srcquench);
      break;
    case ICMP_RTRADVERT:
      hl = sizeof(pkt->pkt_icmp_msg->rtradvert);
      break;
    case ICMP_RTRSOLICIT:
      hl = sizeof(pkt->pkt_icmp_msg->rtrsolicit);
      break;
    case ICMP_TSTAMP:
    case ICMP_TSTAMPREPLY:
      hl = sizeof(pkt->pkt_icmp_msg->tstamp);
      break;
    case ICMP_INFO:
    case ICMP_INFOREPLY:
    case ICMP_DNS:
      hl = sizeof(pkt->pkt_icmp_msg->info);
      break;
    case ICMP_MASK:
    case ICMP_MASKREPLY:
      hl = sizeof(pkt->pkt_icmp_msg->mask);
      break;
    case ICMP_DNSREPLY:
      hl = sizeof(pkt->pkt_icmp_msg->dnsreply);
      break;
    default:
      hl = pkt->pkt_end - p + 1;
      break;
    }
    if (p + hl > pkt->pkt_end)
      pkt->pkt_icmp_msg = NULL;
    break;
  case IP_PROTO_TCP:
    if (p < pkt->pkt_end)
      pkt->pkt_tcp_data = p;
    break;
  case IP_PROTO_UDP:
    if (pkt->pkt_ip_data + ntohs(pkt->pkt_udp->uh_ulen) <=
	pkt->pkt_end)
      pkt->pkt_udp_data = p;
    break;
  }
}

void
pkt_free(struct pkt *pkt)
{
  brel(pkt);
}
