/* ctl.c
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
 * $Id: ctl.c,v 1.3 2003/09/12 21:23:39 lorgor Exp $ */

#include "config.h"

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <string.h>
#include <stdio.h>

#ifdef HAVE_TIME_H
#include <time.h>
#endif

#include <stdlib.h>
#include <ctype.h>

#ifdef HAVE_ERR_H
#include <err.h>
#else
#include "err.h"
#endif

#ifdef HAVE_WINDOWS_H
#include <windows.h>
#endif

#include "labrea.h"
#include "bget.h"
#include "pkt.h"
#include "utils.h"
#include "lbio.h"
#include "ctl.h"


/*
 * used to clean up stuff in the input files, this one skips over any
 * spaces and carriage returns and then changes a line feed to a null
 *
 */

static void
cleanup (char *p)
{
  char *p2 = p;

  while(*p != '\0') {
    /*Skip spaces and returns */
    while((*p2 == ' ') || (*p2 == '\r') || (*p2 == '\t')) {
      p2++;
    }
    *p = (char)toupper(*p2);
    if (*p == '\n')
      *p = '\0';
    else {
      p2++;
      p++;
    }
  }
}

static config_t
parse_type (char *mybuffer)
{
  char *p = NULL;
  config_t type = IP_INVALID;

  if ((p = strstr(mybuffer, "HAR")) != NULL){
    type = IP_HARD_EXCLUDE;
  } else {
    if ((p = strstr(mybuffer,"EXC" )) != NULL){
      type = IP_EXCLUDE;
    } else {
      if ((p = strstr(mybuffer, "IPI")) != NULL) {
	type = IP_IGNORE;
      } else {
	if ((p = strstr(mybuffer, "POR")) != NULL){
	  type = PT_IGNORE;
	} else {
	  if ((p = strstr(mybuffer, "PMN")) != NULL){
	    type = PT_MONITOR;
	  } else {
	    type = CFG_INVALID;
	  }
	}
      }
    }
  }
  if (p != NULL)		/* Eliminate the specification field */
    *p = '\0';
  return( type );
}

/*
 * Parses port or port range in configuration file
 *
 * mybuffer	string with ports to be parsed
 * port_value   value to be assigned to port_array
 *
 * Returns      -1 if input_error found
 *              0  if input is correct
 *
 */
static int
parse_port (char * mybuffer, uint16_t port_value)
{
  char *p=NULL;
  unsigned int export=0, lowport=0;
  long i=0;
  char *msg=NULL;
  

  if ((p = strstr(mybuffer, "-")) != NULL) { /* check for range */
    *p = '\0';
    p++;
  }
  
  if ((sscanf(mybuffer, "%u", &lowport) != 1) || (lowport > PORT_NUM)){
    warnx("***Invalid port: %i - Ignoring", lowport);
    return(-1);			/* There is an error */
  }

  if (p != NULL) {		/* Handle range of ports */
    if ((sscanf(p, "%u", &export) != 1) || (export > PORT_NUM)){
      warnx("*** Invalid port: %i - Ignoring", export );
      return(-1);		/* There is an error */
    }
  } else
    export = lowport;

  for(i = lowport; i <= export; i++) {
    ctl.port_array[i] = port_value;
  }

  msg = (port_value == PORT_MAX) ? "monitored" : "ignored";
  if (lowport == export)
    util_print(VERBOSE, "    Port %i %s", lowport, msg);
  else
    util_print(VERBOSE, "    Ports %i-%i %s", lowport, export, msg);

  return(0);			/* No errors were found */
}


/*
 * Parses the HAR (hard exclude) and EXC (exclude) config file statements
 *
 * mybuffer		contains the statement to be parsed
 * exclude_value	is the type of exclusion to be done
 *
 * returns  0		if no errors were found
 *          -1		if there were input errors
 *
 */
static int
parse_ip_exclude (char *mybuffer, config_t exclude_value)
{
  char *p = NULL;		/* Used to find start of second addr in range */
  ip_addr_t lowip=0, exip=0;	/* Low / high IP offsets of addr range */
  ip_addr_t ip=0;		/* Loop index */
  char *msg = NULL;		/* Output msg */
  struct addr inp_addr;		/* I/P addr converted to structure */

  if ((p = strstr(mybuffer, "-")) != NULL) { /* check for range */
    *p = '\0';
    p++;
  }

  /* Parse low IP in range */

  if ((addr_aton(mybuffer, &inp_addr) < 0) || (inp_addr.addr_type != ADDR_TYPE_IP)){
    warnx("*** Invalid IP address: %s - Ignoring", mybuffer);
    return( -1 );
  }
  if( lbio_ip_offset(inp_addr.addr_ip, &lowip) < 0) { /* lowip is converted IP addr */
    warnx("*** Excluded IP address %s not in capture subnet - Ignoring", mybuffer);
    return(-1);
  }

  /* Parse high IP in range if provided */

  if (p != NULL){

    if ((addr_aton(p, &inp_addr) < 0) || (inp_addr.addr_type != ADDR_TYPE_IP)){
      warnx("*** Invalid IP address: %s - Ignoring", mybuffer);
      return( -1 );
    }
    if( lbio_ip_offset(inp_addr.addr_ip, &exip) < 0) { /* exip is high IP addr */
      warnx("*** Excluded IP address %s not in capture subnet - Ignoring", mybuffer);
      return(-1);
    }

    /* Otherwise there is no range: only 1 IP addr was input */
  } else
    exip = lowip;

  msg = (exclude_value == IP_HARD_EXCLUDE) ? " hard excluded:" : " excluded:";

  for(ip = lowip; ip <= exip; ip++) {
    ctl.exclusion[ip] = exclude_value;
    util_print(VERY_VERBOSE, "    IP %s %s", msg, lbio_ntoa(ctl.base+ip)); 
  }
  return(0);
}

static void
init_port_array (void)
{
  long i=0;

  /* ports that always respond (unless turned off in the config file) */

  const long tgt_ports[] = {
    1,  /* tcpmux     */  7,  /* echo       */  9,  /* discard    */
    11, /* systat     */  13, /* daytime    */  15, /* netstat    */
    17, /* qotd       */  18, /* msp        */  19, /* chargen    */
    20, /* ftp-data   */  21, /* ftp        */  22, /* ssh        */
    23, /* telnet     */  25, /* smtp       */  37, /* time       */
    53, /* dns        */  69, /* tftp       */  77, /* rje        */
    79, /* finger     */  80, /* http       */  81, /* RemoConCH. */
    98, /* linuxconf  */  109, /* pop2       */  110, /* pop3       */
    111, /* portmapper */  113, /* ident      */  119, /* nntp       */
    123, /* ntp        */  135, /* netbios win*/  137, /* netbios-ns */
    138, /* netbios-dgm*/  139, /* netbios-ssn*/  143, /* imap2      */
    161, /* snmp       */  162, /* snmp       */  179, /* bgp        */
    194, /* irc        */  389, /* ldap       */  443, /* https      */
    445, /* cfs win2k  */  512, /* exec       */  513, /* login      */
    514, /* shell      */  515, /* printer    */  530, /* courier    */
    1080, /* socks      */  1443, /* MS-Sql     */  1812, /* radius     */
    1813, /* radius-acct*/  2049, /* nfs        */  3306, /* mysql      */
    3389, /* RDP        */  4045, /* lockd      */  6000, /* Xwindows   */
    6001, /* idem       */  6002, /* idem       */  6003, /* idem       */
    6004, /* idem       */  6005, /* idem       */  6346, /* Gnutella   */
    8000, /* web        */  8080, /* web cache  */  8081, /* web proxy  */
    8888, /* Napster    */  12345,/* trojan     */  27374, /* trojan     */
    -1    /* Always the last one */
  };

  /* Set all ports to be monitored */

  for(i=1; i<=PORT_NUM; i++)
    ctl.port_array[i] = PORT_MONITOR;
  
  /* Then set some ports to make us an attractive target */

  i = 0;
  while(tgt_ports[i] > 0) {
    ctl.port_array[ tgt_ports[i] ] = PORT_MAX;
    i++;
  }
}

/*
 * Parse the configuration file
 * 
 * There is a common file with "tags" on lines to indicate what type
 * of configuration the line is supposed to be... for example:
 *
 * 	192.168.0.1 - 192.168.0.10 EXC
 * 		would exclude the range of IPs from 192.168.0.1
 * 		through 192.168.0.10
 *
 * 	192.168.0.20 IPI
 * 		would cause connection attempts sourced from
 * 		192.168.0.20 to NOT be * tarpitted or trapped
 *
 * Tags are: 
 *	HAR	hard-exclude IPs
 *      EXC	exclude IPx
 *      IPI	IP ignore
 *      POR	port ignore
 *      PMN	port monitor
 *
 * Read exclusion files, then initialize control arrays and structures
 * to keep things straight
 *
 * wait		TRUE if should wait before reinitializing
 * 
 * returns      -1 if configuration file has errors
 *              0  if config file processed correctly
 */

int
ctl_init_arrays (int wait)
{
  /* For reading the configuration file */
  FILE *in = NULL;
  char mybuffer[BUFSIZE] = "";
  int input_error = FALSE;

  /* Parsing the config parameters */
  ip_addr_t ip=0, ip1=0;	/* Loop indices */
  char *rtn=NULL;
  config_t set_capture;		/* For auto hard-capture */

  uint16_t tempxflag;
  struct ipig *ipig;

  /* For arp sweep */ 
  time_t current=time(NULL);
  int arp_cnt = 0;		/* # of arps during this burst */
  int arp_delay = -1;		/* For delaying subsequent bursts */
  

  /* shut off capture */
  tempxflag = ctl.capture;
  ctl.capture &= ~(FL_CAPTURE);

  if (wait) {
#ifdef WIN32
    Sleep(1000);
#endif
  }

  if (ctl.capture & FL_AUTO_HARD_CAPTURE)
    set_capture = IP_HARD_CAPTURED;
  else
    set_capture = IP_MONITOR;

  /* clear out the exclusion array */
  for(ip = 0; ip < ctl.addresses + 2; ip++)
    ctl.exclusion[ip] = set_capture;

  /* clear the ARP addr array */
  if (ctl.addr_array != NULL) {
    for(ip = 0; ip < ctl.addresses + 2; ip++)
      ctl.addr_array[ip] = 0;
  }

  /* clear out the ARP time array */
  if (ctl.time_array != NULL) {
    for(ip = 0; ip < ctl.addresses + 2; ip++)
      ctl.time_array[ip] = 0;
  }

  /* clear out the nk array */
  for (ip = 0; ip < ctl.addresses + 2; ip++) {
    util_nk_free(ip);
  }

  init_port_array();

  /* free up our ignore list */

  SLIST_FOREACH(ipig, &ctl.ipig_q, ipig_next){
    brel(ipig);
  }
  SLIST_INIT(&ctl.ipig_q);	/* Reinitialize the list */

  /* parse the configuration file */
  if ((in = fopen(ctl.cfg_file_name, "r")) == NULL) {
    warnx("*** Config file %s not found", ctl.cfg_file_name);
  } else {
    util_print(VERBOSE, "...Processing configuration file");

    while((rtn = fgets(mybuffer, BUFSIZE, in)) != NULL ) {
      if ((*mybuffer != '#') && (strlen(mybuffer) > 2)) {
	util_print(VERBOSE, ">> %s", mybuffer);
	cleanup(mybuffer);
      } else
	continue;
	  

      switch( parse_type( mybuffer )) {

      case IP_HARD_EXCLUDE:
	if (parse_ip_exclude(mybuffer, IP_HARD_EXCLUDE) < 0)
	  input_error = TRUE;
	break;
	
      case IP_EXCLUDE :
	if (parse_ip_exclude(mybuffer, IP_EXCLUDE) < 0)
	  input_error = TRUE;
	break;

      case IP_IGNORE:
	ipig = (struct ipig *) bget(sizeof(*ipig));
	if (ipig == NULL) {	  
	  warnx("***Problem allocating IP Ignore list element");
	  input_error = TRUE;
	  break;
	}
	if ((addr_aton(mybuffer, &(ipig->ipig_addr)) < 0)
	    || (ipig->ipig_addr.addr_type != ADDR_TYPE_IP)) {
	  warnx("***Invalid IP address: %s - Ignoring", mybuffer);
	  input_error = TRUE;
	  break;
	}
	SLIST_INSERT_HEAD(&ctl.ipig_q, ipig, ipig_next); 

	if (addr_ntop(&(ipig->ipig_addr), mybuffer, sizeof(mybuffer)) < 0)
	  break;
	util_print(VERY_VERBOSE, "    Ignoring IP: %s", mybuffer);
	break;

      case PT_IGNORE:
	if (parse_port(mybuffer, PORT_IGNORE) < 0)
	  input_error = TRUE;
	break;

      case PT_MONITOR:
	if (parse_port(mybuffer, PORT_MAX) < 0)
	  input_error = TRUE;
	break;
	
      case CFG_INVALID:
      default:
	warnx("*** Configuration file - line with missing or invalid specifier:\n%s", 
	      mybuffer);
	input_error = TRUE;

      } /* end switch on type of config stmt */
    } /* end read loop */
  
    util_print(VERBOSE, "... End of configuration file processing\n");
    fclose(in);
  }

  if (ctl.feature & FL_EXCL_RESOLV_IPS) {
    util_print(VERBOSE, "LaBrea will exclude resolvable IP addresses.");
    for(ip1 = ctl.base; ip1 <= ctl.topend; ip1++) {
      ip = htonl(ip1);
      if (gethostbyaddr((void *)&ip,4,AF_INET)) {
        ctl.exclusion[ip1-ctl.base] = IP_EXCLUDE;
	util_print(VERBOSE, "IP excluded via DNS: %s", lbio_ntoa(ip1));
      }
    }
  }
  /* turn on ARP capture -- if it was on */
  ctl.capture |= (tempxflag & FL_CAPTURE);

  /* 
   * Force an arp sweep for used IP addresses by setting expired nk
   * entries
   */
  if ((!(ctl.mode & FL_NO_ARP_SWEEP)) &&
      (ctl.capture & FL_CAPTURE)) {
    
    for (ip = 1; ip < ctl.addresses; ip++) {
      if ((ctl.exclusion[ip] == IP_MONITOR) ||
	  (ctl.exclusion[ip] == IP_HARD_EXCLUDE)) {
	/* 
	 * If have reached max # of arps for this burst, then delay
	 * the next batch until the next nk cull pass
	 */
	if ((++arp_cnt) > MAX_ARP_BURST) {
	  arp_cnt = 0;
	  if (arp_delay == -1)
	    arp_delay = 0;
	  else
	    arp_delay += (NK_CULL_INTVL*60); /* delay in seconds */
	}
	/* Send immediate WHO-HAS ARP for first batch of IPs */
	if (arp_delay == -1)
	  lbio_send_ARP_Who_Has(ctl.base + ip);
	else
	  /* Force an ARP WHO-HAS by setting an expired nk element */
	  util_nk_new(ip , current - CULLTIME + arp_delay, ETH_ADDR_BOGUS);
      }
    }
  }

  if (input_error)
    return(-1);
  else
    return(0);
}

/*
 * Initialize processing for ctl routines
 *
 * Returns -1 if initialization errors occurred
 *         0  if no errors occurred 
 */

int
ctl_init()
{
  int c = 0;

  DEBUG_PRT(DEBUG_INIT, "ctl_init");
  
  /* Initialize random #s for Linux window probe detection */
  for(c = 0; c < RANDSIZE2; c++)
    ctl.randqueue2[c] = lbio_rand();

  /* allocate our exclusion array */
  if ((ctl.exclusion = calloc(ctl.addresses+2, sizeof(*ctl.exclusion))) == NULL) {
    warnx(  "*** calloc error: exclusion - unable to allocate memory" );
    util_clean_exit(1);
  }

  /* Allocate port array */
  if ((ctl.port_array = calloc(PORT_NUM + 1,sizeof(*ctl.port_array))) == NULL) {
    warnx(  "*** calloc error: port_array - unable to allocate memory" );
    util_clean_exit(1);
  }
  /* if we're going to use it, allocate our array for holding ARP times */
  if (ctl.capture & FL_CAPTURE) {
    if ((ctl.time_array = calloc(ctl.addresses+2,sizeof(*ctl.time_array))) == NULL) {
      warnx(  "*** calloc error: time_array - unable to allocate memory" );
      util_clean_exit(1);
    }
    if ((ctl.addr_array = calloc(ctl.addresses+2,sizeof(*ctl.addr_array))) == NULL) {
      warnx(  "*** calloc error: addr_array - unable to allocate memory" );
      util_clean_exit(1);
    }
    if ((ctl.nk_array = calloc(ctl.addresses+2,sizeof(*ctl.nk_array))) == NULL) {
      warnx(  "*** calloc error: nk_array - unable to allocate memory" );
      util_clean_exit(1);
    }
  }

  /* initialize IP ignore list */
  SLIST_INIT(&ctl.ipig_q);	/* and set up the list */
  

  /* If soft restart enabled, then hold off captures for specified # minutes */
  if (ctl.soft_restart > 0) {
    for (c = 0; c < ctl.soft_restart; c++) {
      ctl.past[c] = ctl.maxbw * 60;	
      /* max bandwidth in bytes/sec * 60 sec/min = bytes for this min */
    }
    ctl.newthisminute = 0;
    ctl.totalbytes = ctl.maxbw * ctl.soft_restart * 60;
  }

  return(ctl_init_arrays(0));
}

