
/*
 * pkt.h
 *
 * Copyright (c) 2001 Dug Song <dugsong@monkey.org>
 *
 * Note that data in struct pkt is kept in byte network order
 *
 * $Id: pkt.h,v 1.2 2003/09/12 21:23:39 lorgor Exp $
 */

#ifndef PKT_H
#define PKT_H

#include <dnet.h>

#define PKT_BUF_LEN	(ETH_HDR_LEN + ETH_MTU)
#define PKT_BUF_ALIGN	2

struct pkt {
  struct eth_hdr	*pkt_eth;
  union {
    u_char		*eth_data;
    struct ip_hdr	*ip;
    struct arp_hdr  	*arp;
  } pkt_n_hdr_u;
  union {
    u_char		*ip_data;
    struct icmp_hdr	*icmp;
    struct tcp_hdr	*tcp;
    struct udp_hdr	*udp;
    struct arp_ethip 	*a_data;
  } pkt_t_hdr_u;
  union {
    u_char		*t_data;
    union icmp_msg	*icmp;
  } pkt_t_data_u;

  u_char		 pkt_buf[PKT_BUF_ALIGN + PKT_BUF_LEN];
  u_char		*pkt_data;
  u_char		*pkt_end;

};
#define pkt_arp		 pkt_n_hdr_u.arp
#define pkt_ip		 pkt_n_hdr_u.ip
#define pkt_eth_data	 pkt_n_hdr_u.eth_data

#define pkt_icmp	 pkt_t_hdr_u.icmp
#define pkt_tcp		 pkt_t_hdr_u.tcp
#define pkt_udp		 pkt_t_hdr_u.udp
#define pkt_ip_data	 pkt_t_hdr_u.ip_data
#define pkt_arp_data	 pkt_t_hdr_u.a_data

#define pkt_tcp_data	 pkt_t_data_u.t_data
#define pkt_udp_data	 pkt_t_data_u.t_data
#define pkt_icmp_msg	 pkt_t_data_u.icmp

typedef struct pkt pkt_t;

void		 pkt_init(int size);

pkt_t		*pkt_new(void);
pkt_t		*pkt_dup(pkt_t *pkt);
void		 pkt_decorate(pkt_t *pkt);
void		 pkt_free(pkt_t *pkt);

#endif /* PKT_H */
