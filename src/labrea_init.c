/*
 * labrea_init.c
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
 * $Id: labrea_init.c,v 1.2 2003/09/12 21:23:39 lorgor Exp $
 */

#include "config.h"

#include <assert.h>
#include <string.h>
#include <ctype.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <stdlib.h>
#include <stdio.h>

#ifdef HAVE_GETOPT_H
#include <getopt.h>
#else
#include "getopt.h"
#endif

#ifdef HAVE_ERR_H
#include <err.h>
#else
#include "err.h"
#endif

#include "labrea.h"
#include "pcaputil.h"
#include "ctl.h"
#include "utils.h"
#include "lbio.h"

int input_error = FALSE;	/* True if errors on input */

static void __inline
Usage (void)
{
  if (WIN32_FLG)
    /* Windows-specific options */
	  
    warnx("\n\n\nUsage: LaBrea <options> <BPF filter>\n"
	  "Options:\n"
	  "--winpcap-dev (-j) intfnum	: libdnet interface to be used i.e. -j 3\n"
	  "--list-interfaces (-D)  : Lists available adapters / interfaces for -i/-j\n"
	  "--syslog-server addr    : IP address or hostname of remote syslog server\n"
	  "--syslog-port           : Remote syslog port"
	  );
  else
    /* Unix-specific options */

    warnx("\n\n\nUsage: LaBrea <options> <BPF filter>\n"
	  "Options:\n"
	  "--device (-i) interface : Set a non-default interface\n"
	  "--foreground (-d)       : Do NOT detach process\n"
	  );
  /* General options */
  warnx(
	"--bpf-file (-F) filename : Specify a BPF filter filename\n"
	"--network (-n) nnn.nnn.nnn.nnn[/mm] : User specified capture subnet\n"
	"--mask (-m) nnn.nnn.nnn.nnn	: User specified capture subnet mask\n"
	"--throttle-size (-t) datasize : Connection throttling size (bytes)\n"
	"--arp-timeout (-r) rate	: Arp timeout rate (seconds)\n"
	"--switch-safe (-s)      : \"Safe\" operation in a switched environment\n"
	"--log-to-syslog (-l)    : Log activity to syslog\n"
	"--verbose (-v)          : Verbosely log activity\n"
	"--init-file filename    : Specify alternative config file\n"
	"--hard-capture (-h)     : \"Hard\" capture IPs\n"
	"--disable-capture (-x)  : Disable IP capture\n"
	"--version (-V)          : Print version information and exit\n"
	"--no-resp-synack (-a)   : Do not respond to SYN/ACKs and PINGs\n"
	"--quiet (-q)            : Do not report odd (out of netblock) ARPs\n"
	"--dry-run (-T)          : Test mode - Prints out messages but DOES NOT RUN\n"
	"--soft-restart (-R)     : Soft restart - Wait while recapturing active connects\n"
	"--max-rate (-p) maxrate : \"Persist\" state capture connect attempts up to Kb/sec\n"
	"--persist-mode-only (-P): Persist mode capture only\n"
	"--log-bandwidth (-b)    : Log bandwidth usage to syslog\n"
	"--log-to-stdout (-o)    : Output to stdout instead of syslog, implies -d\n"
	"--log-timestamp-epoch  (-O) : Same as -o w/time output in seconds since epoch\n"
	"--exclude-resolvable-ips (-X) : Automatically exclude resolvable IPs from capture\n"
	"--auto-hard-capture (-H) : Automatically hard capture addresses not excluded\n"
	"--no-resp-excluded-ports (-f) : \"Firewall\" excluded ports\n"
	"--no-arp-sweep          : Do not arp sweep subnet for occupied IPs\n"
	"--my-ip-addr (-I) ipaddr : IP address of this system\n"
	"--my-mac-addr (-E) macaddr : MAC address of this system\n"
	"--debug nnn             : Debug output for debug levels nnn (requires compile option)\n"
	"--no-nag (-z)           : Allow execution and bypass nag reminder\n"
	"--help --usage (-?)     : This message\n"
	);

  util_clean_exit(1);
}


/*
 * Concatenate string chunk to string texpr, taking care not to run
 * off the end of texpr
 */

static void
build_bpf_filter(u_char *texpr, const u_char *chunk, const size_t siz)
{
  u_char *p = texpr;
  int len = strlen(texpr);
  
  p += len;
  len = siz - len -1;
  if (strlcpy(p, chunk, len) >= len) {
    warnx("*** Truncation occurred - bpf filter too long");
    input_error = TRUE;
  }
}


/*
 * used to clean up stuff in in the input files, this changes line feeds
 * and carriage returns to spaces
 * 
 */

static void
cleanup2 (char *p)
{
  while(*p != '\0') {
    if ((*p == '\r') || (*p == '\n'))
      *p = ' ';
    p++;
  }
}


/*
 * input a number, checking for validity and watching for buffer overflow
 *
 */
static int
read_number (u_char *p)
{
  char buf[BUFSIZE]="";
  char *invalid = NULL;
  int result = 0;

  strlcpy(buf, p, sizeof(buf));	    /* Copy, watching for buffer overflow */
  result = strtol(buf, &invalid, 10); /* Convert to integer, checking validity */
  if ((strlen(invalid) > 0) || (result < 0)) {
    strlcpy(buf, invalid, sizeof(buf));
    warnx("*** Invalid integer input: %s", buf);
    input_error = TRUE;
  }
  return(result);
}

void
labrea_init (int argc, char **argv)
{
  int usernet = FALSE;		/* True if user-specified subnet for capturing */
  int man_host_info = FALSE; /* True if user-specified host information */
  char *texpr = NULL;		/* Buffer for holding bpf filter */

  char dev[BUFSIZE]="";		/* Input device name */
  char pgm_name[PGM_NAME_SIZE]="";		/* Name of invoking pgm */

  struct addr cap_net;		/* For manual input of capture subnet */
  struct addr cap_mask;		/* For manual input of capture subnet mask */
  struct addr myip_tmp={ADDR_TYPE_NONE};
  /* For manual input of system IP address */

  /* decl for reading input files */
  char ffname[BUFSIZE] = "";	/* Input file name */
  FILE *in = NULL;		/* Input file descriptor */
  char *rtn = NULL;		/* Return ptr from fgets */
  static char mybuffer[BUFSIZE] = ""; /* Buffer to hold input string */

  int c = 0;			/* Index for getopt */

  /* decl for getopt_long */

  int option_index = 0;		/* Option index */  

  static struct option long_options[] =
    {
      {"network", 			required_argument,	0, 'n'},
      {"mask", 				required_argument,	0, 'm'},
      {"device", 				required_argument,	0, 'i'},
      {"winpcap-dev",			required_argument,	0, 'j'},
      {"my-ip-addr",			required_argument,	0, 'I'},
      {"my-mac-addr",			required_argument,	0, 'E'},
      {"quiet",  				no_argument,       	0, 'q'},
      {"bpf-file",  			required_argument, 	0, 'F'},
      {"throttle-size",  			required_argument, 	0, 't'},
      {"arp-timeout",    	   		required_argument, 	0, 'r'},
      {"switch-safe",    			no_argument, 		0, 's'},
      {"exclude-resolvable-ips", 		no_argument, 		0, 'X'},
      {"disable-capture", 		no_argument, 		0, 'x'},
      {"hard-capture",   			no_argument,		0, 'h'},
      {"soft-restart",   			no_argument, 		0, 'R'},
      {"auto-hard-capture", 		no_argument, 		0, 'H'},
      {"max-rate",   			required_argument,	0, 'p'},
      {"log-bandwidth", 			no_argument, 		0, 'b'},
      {"persist-mode-only", 		no_argument, 		0, 'P'},
      {"no-resp-synack", 			no_argument, 		0, 'a'},
      {"no-resp-excluded-ports", 		no_argument,		0, 'f'},
      {"log-to-syslog", 			no_argument, 		0, 'l'},
      {"verbose", 			no_argument, 		0, 'v'},
      {"log-to-stdout", 			no_argument, 		0, 'o'},
      {"log-timestamp-epoch", 		no_argument,		0, 'O'},
      {"version", 			no_argument, 		0, 'V'},
      {"dry-run", 			no_argument, 		0, 'T'},
      {"foreground", 			no_argument, 		0, 'd'},
      {"no-nag", 				no_argument, 		0, 'z'},
      {"usage", 				no_argument, 		0, '?'},
      {"help", 				no_argument, 		0, '?'},
      {"init-file",   			required_argument,	0, '2'},
      {"no-arp-sweep",   			no_argument,		0, '3'},
      {"syslog-server",  			required_argument,	0, '4'},
      {"syslog-port",   			required_argument,	0, '5'},
#ifdef DEBUG_LB
      {"debug",		   		required_argument,	0, '6'},
#endif
      {"list-interfaces",   		no_argument,		0, 'D'},
      {0, 0, 0, 0}
    };


  static char rcsid[] = PACKAGE_STRING " " PACKAGE_BUGREPORT;
  static char bpf[]     = "arp or (ip and ether dst host 00:00:0F:FF:FF:FF)";

  char bigstring2[] =
    "You MUST read the INSTALL file!  Don't try to run this\n"
    "program without understanding how it works and what it can do!\n"
    "In the INSTALL file, you'll find the command line switch\n"
    "necessary to allow LaBrea to run.";


  /* Allocate / initialize main ctl structures and set defaults */

  memset(&ctl, 0, sizeof(ctl));	/* Initialize ctl and io structures */
  memset(&io, 0, sizeof(io));		

  strlcpy(pgm_name, argv[0], sizeof(pgm_name));	/* Get name of pgm for log msgs */
  util_init();

  io.mymac = NULL;
  ctl.throttlesize = THROTTLE_WINDOW_ORD; /* Default window size = 10 */
  ctl.rate = ARP_TIMEOUT;	/* Default arp timeout rate = 3 sec */
  ctl.logging |= FL_LOG_ODD_ARPS;
  ctl.capture |=  FL_CAPTURE;
  strlcpy(ctl.cfg_file_name, LABREA_CONF, sizeof(ctl.cfg_file_name));

  if ((texpr = calloc(BPFSIZE ,sizeof(* texpr))) == NULL) {
    warnx(  "*** calloc error: texpr - unable to allocate memory" );
    util_clean_exit(1);
  }

  addr_pack(&cap_net, ADDR_TYPE_NONE, 0, IP_ADDR_ZEROS,IP_ADDR_LEN);
  addr_pack(&cap_mask, ADDR_TYPE_NONE, 0,  IP_ADDR_ZEROS,IP_ADDR_LEN);

  /*
   * Windows-only defaults
   */
  if (WIN32_FLG) {
    ctl.syslog_port = 514;		/* Windows-only: default syslog port */
    outp.output |= FL_OUTP_STDOUT; /* Log to stdout */
  }

  /* parse the command line */
  while(TRUE){
    c = getopt_long(argc, argv, "n:m:i:j:I:E:qF:t:r:sXxhRHp:bPaflvoOVTdz?2:3D",
		    long_options, &option_index);

    if (c == EOF)		/* If at end of options, then stop */
      break;

    DEBUG_PRT(DEBUG_INIT, "labrea_init: option: %d", c);

    switch(c) {
    case 'X':
      ctl.feature |= FL_EXCL_RESOLV_IPS;
      break;
    case 'O':
      outp.output |= (FL_OUTP_STDOUT_EPOCH | FL_OUTP_STDOUT);
      ctl.mode |= FL_DONT_DETACH;
      break;
    case 'T':
      ctl.mode |= FL_TESTMODE;
      outp.verbose = VERY_VERBOSE;
      outp.output |= FL_OUTP_STDOUT;
      ctl.mode |= FL_DONT_DETACH;
      break;
    case 'R':
      ctl.soft_restart = SOFT_RESTART;
      assert( (HIST_MIN+1) >= SOFT_RESTART); /* If not will overflow past[] array */
      break;
    case 'o':
      outp.output |= FL_OUTP_STDOUT;
      ctl.mode |= FL_DONT_DETACH;
      break;
    case 'd':
      ctl.mode |= FL_DONT_DETACH;
      break;
    case 'x':
      ctl.capture &= ~(FL_CAPTURE); /* Turn off capture */
      break;
    case 'b':
      ctl.logging |= FL_LOG_BDWTH_SYSLOG;
      break;
    case 'v':
      outp.verbose += 1;
      break;
    case 'z':
      ctl.mode |= FL_DONT_NAG;
      break;
    case 's':
      ctl.feature |= FL_SAFE_SWITCH;
      break;
    case 'q':
      ctl.logging &= ~(FL_LOG_ODD_ARPS);
      break;
    case 'a':
      ctl.feature |= FL_NO_RESP;
      break;
    case 'l':
      outp.output &= ~FL_OUTP_STDOUT;
      break;
    case 'n':
      if ((addr_aton(optarg, &cap_net) < 0)) {
	warnx("*** Subnet to be captured must be specified as xxx.xxx.xxx.xxx[/nn]");
	input_error = TRUE;
      }
      else
	usernet = TRUE;
      break;
    case 'm':
      if ((addr_aton(optarg, &cap_mask) < 0)) {
	warnx("*** Subnet mask should be specified as xxx.xxx.xxx.xxx");
	input_error = TRUE;
      }
      else 
	usernet = TRUE;
      break;      
    case 'F':
      strlcpy(ffname, optarg, sizeof(ffname));
      break;
    case 'f':
      ctl.feature |= FL_NO_RST_EXCL_PORT;
      break;
    case 'i':
      strlcpy(dev, optarg, sizeof(dev));
      /* lbio_init will do further checking */
      break;
    case 'j':
      if (WIN32_FLG) {
	io.intf_num = read_number(optarg);
	if (io.intf_num <=0 || io.intf_num > MAX_NUM_ADAPTER) {
	  warnx("*** Winpcap device specified %d is invalid", io.intf_num);
	  input_error = TRUE;
	}
      }
      else {
	warnx( "*** Option -j not supported on unix.");
	input_error = TRUE;
      }
      break;
    case 'D':
      if (WIN32_FLG) {   
	lbio_print_pcap_adapter_list();
	lbio_print_libdnet_intf_list();
	util_clean_exit(0);
      }
      else {
	warnx( "*** Option -D not supported on unix.");
	input_error = TRUE;
      }
      break;

    case 'E':
      if ((io.mymac = calloc(1, sizeof(struct addr))) == NULL) {
	warnx(  "*** calloc error: io.mymac - unable to allocate memory" );
	util_clean_exit(1);
      }
      if ((addr_aton(optarg, io.mymac) < 0) ||
	  (io.mymac->addr_type != ADDR_TYPE_ETH)) {
	warnx("*** MAC addr should be specified as xx:xx:xx:xx:xx:xx");
	input_error = TRUE;
      } else 
	man_host_info = TRUE;
      break;

    case 'I':
      if ((addr_aton(optarg, &myip_tmp) < 0) ||
	  (myip_tmp.addr_type != ADDR_TYPE_IP)) {
	warnx("*** IP addr should be specified as nn.nn.nn.nn");
	input_error = TRUE;
      } else {
	io.myip = ntohl(myip_tmp.addr_ip);
	man_host_info = TRUE;
      }
      break;

    case 't':
      ctl.throttlesize = read_number(optarg);
      break;
    case 'r':
      ctl.rate = read_number(optarg);
      break;
    case 'h':
      ctl.capture |= FL_HARD_CAPTURE;
      break;
    case 'H':
      ctl.capture |= (FL_HARD_CAPTURE | FL_AUTO_HARD_CAPTURE);
      break;
    case '?':
      Usage();
      break;
    case 'P':
      ctl.capture |= FL_PERSIST_MODE_ONLY;
      break;
    case 'p':
      ctl.maxbw = read_number(optarg);
      break;
    case 'V':
      puts(rcsid);
      util_clean_exit(0);
    case '2':
      strlcpy(ctl.cfg_file_name, optarg, sizeof(ctl.cfg_file_name));
      break;
    case '3':
      ctl.mode |= FL_NO_ARP_SWEEP;
      break;
    case '4':
      if (WIN32_FLG) {
	strlcpy(ctl.syslog_server, optarg, MAXHOSTNAMELEN);
      } else {
	warnx("*** option --syslog-server is not supported on unix");
	input_error = TRUE;
      }
      break;
    case '5':
      if (WIN32_FLG) {
	ctl.syslog_port = read_number(optarg);
	if ((ctl.syslog_port < 0) ||
	    (ctl.syslog_port > PORT_NUM)) {
	  warnx("*** Remote syslog port %d is invalid",
		ctl.syslog_port);
	  input_error = TRUE;
	}
      } else {
	warnx("*** option --syslog-port is not supported on unix");
	input_error = TRUE;
      }
      break;
    case '6':
      ctl.debuglevel = read_number(optarg);
      break;
    default:
      Usage();
      break;
    }
  }
  if (ctl.maxbw > 0) {
    ctl.maxbw = ctl.maxbw >> 3;	/* Convert Kbits to Kbytes */
    if (ctl.maxbw > MAX_BW) {
      ctl.maxbw = MAX_BW;	/* Max 1 GByte to avoid integer overflows */
    }
    ctl.throttlesize = THROTTLE_WINDOW_SLOW;
    ctl.newthisminute = ctl.maxbw * ONE_K;	/* Convert Kbytes to bytes */
  }

  if (!WIN32_FLG) {
    /* line buffer the output */
    if (outp.output & FL_OUTP_STDOUT)
      setlinebuf(stdout);
  }

  if (USEZFLAG) {
    if (!(ctl.mode & FL_DONT_NAG)) {
      if (ctl.mode & FL_TESTMODE)
	warnx("*** You're missing the \"-z\" flag. See the docs.");
      else {
	warnx( bigstring2 );
      }
      input_error = TRUE;
    }
  }

  if (man_host_info &&
      ((io.myip == 0) ||
       (io.mymac == NULL))) {
    warnx("*** Both the system IP addr and MAC addr must be specified (-I -E)\n"
	  "    In addition, the capture subnet must also be specified (-n)");
    input_error = TRUE;
  }


  /* calculate subnet and netmask values from the user-specified values, if any */

  if (usernet) {
    /* If mask specified with -m parameter, then use it */
    if (cap_mask.addr_type != ADDR_TYPE_NONE)
      addr_mtob(&(cap_mask.addr_ip), IP_ADDR_LEN, &(cap_net.addr_bits));
  }

  if (usernet || man_host_info) {
    if ((cap_net.addr_bits == 0) || 
	(cap_net.addr_bits == IP_ADDR_BITS) ||
	(cap_net.addr_ip == 0)) {
      warnx("*** Both the capture subnet address and subnet mask must be specified.\n"
	    "Consider using the -n parameter with CIDR notation (ie xx.xx.xx.xx/nn).");
      input_error = TRUE;
    } 
    util_print(VERBOSE, "User specified capture subnet / mask: %s", addr_ntoa(&cap_net));

    addr_btom(cap_net.addr_bits, &io.mask, IP_ADDR_LEN);
    io.mask = ntohl(io.mask);
    io.net = ntohl(cap_net.addr_ip);
    io.net &= io.mask;
  }

  /* create our bpf filter */
  if (ctl.capture & FL_CAPTURE) {
    build_bpf_filter(texpr, bpf, BPFSIZE);

    util_print(VERBOSE, "LaBrea will attempt to capture unused IPs.");

    /* tack any additional stuff onto our BPF filter */
    if (optind < argc) {
      if (strlen(ffname) > 0) {
	warnx("*** Command line filter and filter file specified - Ambiguous!");
	input_error = TRUE;
      }
      build_bpf_filter(texpr, " or (", BPFSIZE);

      for(c = optind; c < argc; c++) 
	build_bpf_filter(texpr, argv[c], BPFSIZE); /* tack on another argument */

      build_bpf_filter(texpr, ")", BPFSIZE);


    } else {  
      /* handle filter file */
      if (strlen(ffname) > 0) {
	if ((in = fopen(ffname, "r")) == NULL) {
	  warnx(  "*** Unable to open filter file %s", ffname );
	  input_error = TRUE;
	} else {
	  build_bpf_filter(texpr, " or (", BPFSIZE);

	  while ((rtn = fgets(mybuffer, sizeof(mybuffer), in)) != NULL) {
	    if (*mybuffer != '#') {
	      cleanup2(mybuffer);
	      build_bpf_filter(texpr, mybuffer, BPFSIZE);
	    }
	    fclose(in);
	    build_bpf_filter(texpr, ")", BPFSIZE);
	  }
	}
      }
    }
  } else { 
    util_print(VERBOSE, "LaBrea will NOT attempt to capture unused IPs.");
    /*
     * Turn off Arp sweep as well since makes no sense unless are capturing IPs.
     */
    ctl.mode |= FL_NO_ARP_SWEEP;
  }

  util_print(VERBOSE, "Full internal BPF filter: %s", texpr);

  /*
   * Windows-specific checks
   */
  if (WIN32_FLG) {
    if (io.intf_num > 0)
      util_print(VERBOSE, "Winpcap device %d will be used",
		 io.intf_num);
    if (strlen(ctl.syslog_server) > 0) {
      util_print(VERBOSE, "Syslog will be sent to %s, port %d",
		 ctl.syslog_server, ctl.syslog_port);
    } else {
      if (!(outp.output & FL_OUTP_STDOUT)) {
	if (!util_check_version_winNT()) {
	  warnx("*** Syslog output to Windows event file requires WinNT or better");
	  input_error = TRUE;
	}
      }
    }
  }			
  if (!(ctl.logging & FL_LOG_ODD_ARPS))
    util_print(VERBOSE, "LaBrea will NOT warn when it sees ARPs from outside the netblock");

  util_print(VERBOSE, "LaBrea will log to %s",
	     (outp.output & FL_OUTP_STDOUT)? "stdout" : "syslog");

  if (outp.verbose == VERBOSE)
    util_print(VERBOSE, "Logging will be verbose.");
  else
    util_print(VERY_VERBOSE, "Logging will be very verbose.");

  if (ctl.capture & FL_HARD_CAPTURE)
    util_print(VERBOSE, "IPs will be \"hard captured\".");

  if (ctl.feature & FL_SAFE_SWITCH)
    util_print(VERBOSE, "LaBrea will attempt to operate safely in a switched environment");

  if (ctl.feature & FL_NO_RESP)
    util_print(VERBOSE, "SYN/ACKs or PINGS will not be answered.");

  if (ctl.feature & FL_NO_RST_EXCL_PORT)
    util_print(VERBOSE,
	       "Ports will be firewalled. No RST will be returned for excluded ports.");

  if (ctl.maxbw > 0) {
    util_print(VERBOSE, "Connections will be captured in persist state up to %u Kb/sec",
	       ctl.maxbw << 3);
    if (ctl.logging & FL_LOG_BDWTH_SYSLOG)
      util_print(VERBOSE, "Bandwidth use will be logged every minute.");
  } else {
    if (ctl.logging & FL_LOG_BDWTH_SYSLOG) {
      warnx("*** The --max-rate (-p) option must be specified if bandwidth is to be logged.");
      input_error = TRUE;
    }
  }

  if (ctl.capture & FL_HARD_CAPTURE)
    util_print(VERBOSE,
	       "Non-excluded addresses will be automatically marked as being hard captured");

  if (ctl.soft_restart > 0)
    util_print(VERBOSE,
	       "A soft restart will be attempted during %i minutes.", ctl.soft_restart);

  if (ctl.capture & FL_PERSIST_MODE_ONLY) {
    if (ctl.maxbw == 0) {
      warnx("(*** If --persist-mode-only (-P) is specified,"
	    "then --max-rate (-p) must also be specified.");
      input_error = TRUE;
    }
    else {
      util_print(VERBOSE, "ONLY Persist mode capture will be done.");
    }
  }

  if (input_error) {
    warnx("*** Errors in input - exiting.");
  }

  /* Initialize IO */
  lbio_init(dev, texpr);

  /* Now we know how many IP addresses are in the subnet */
  if (ctl.addresses >= MAX_SUBNET_SIZE) {
    warnx("*** The Capture subnet is large. labrea works better if the capture subnet size\n"
	  "is limited to the actual physical segment size (hub or switch vlan).\n"
	  "Consider using -n or -m parameters.");
    ctl.mode |= FL_NO_ARP_SWEEP; /* Too big to do arp sweeping */
  }

  if (ctl.mode & FL_NO_ARP_SWEEP)
    util_print(VERBOSE, "An arp sweep for occupied IP addresses will not be performed.");


  /* Initialize main ctl structures */  
  if (ctl_init() < 0) {
    input_error = TRUE; 
  }


  util_print(VERBOSE, "Network number: %s", lbio_ntoa(io.net));
  util_print(VERBOSE, "Netmask: %s", lbio_ntoa(io.mask));
  util_print(VERBOSE, "Number of addresses LaBrea will watch for ARPs: %u",
	     ctl.addresses);
  util_print(VERBOSE, "Range: %s - %s",
	     lbio_ntoa(ctl.base), lbio_ntoa(ctl.topend));
  util_print(VERBOSE, "Throttle size set to WIN %i", ctl.throttlesize);
  util_print(VERBOSE, "Rate (-r) set to %i", ctl.rate);

  if (ctl.mode & FL_TESTMODE) {
    util_print(NORMAL, "Test mode run complete... LaBrea is exiting.");
    util_clean_exit(0);
  } else {
    if (input_error) {
      warnx("*** Errors in initialization ... exiting");
      util_clean_exit(0);
    }
  }

  if (!(outp.output & FL_OUTP_STDOUT))
    util_open_syslog(pgm_name);	/* Open up syslog */
  return;
}
