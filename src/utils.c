/*
 * utils.c
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
 * $Id: utils.c,v 1.2 2003/09/09 20:49:24 lorgor Exp $
 */

#include "config.h"


#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <sys/stat.h>

#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>

#ifdef HAVE_TIME_H
#include <time.h>
#endif

#include <signal.h>

#ifdef HAVE_SYSLOG_H 
#include <syslog.h>
#else
#include "syslog.h"
#endif

#include <errno.h>

#ifdef HAVE_ERR_H
#include <err.h>
#else
#include "err.h"
#endif

#ifdef HAVE_WINSOCK_H
#include <winsock.h>
#endif

#ifdef HAVE_WINDOWS_H
#include <windows.h>
#endif

#include "bget.h"
#include "pkt.h"
#include "labrea.h"
#include "pcaputil.h"
#include "ctl.h"
#include "lbio.h"
#include "utils.h"


void
util_init(void)
{
  memset(&outp, 0, sizeof(outp));
  outp.verbose = NORMAL;
}

void
util_open_syslog(char *ident)
{
  /* set up logging */
  openlog(ident, 0, LOGFAC);
  if (!WIN32_FLG)
    outp.syslog_open = TRUE;
}

/*
 * Print a message to STDOUT, with the timestamp in one of two
 * formats, or we send it to syslog
 *
 */

void
util_print(const amt_log_t verbosity_msg, const char *fmt, ...)
{
  char buf[BUFSIZE] = "";
  char tnow[BUFSIZE] = "";
  time_t current = time(NULL);
  char *p = NULL;

  va_list ap;

  if (verbosity_msg > outp.verbose)
    return;
        
  va_start(ap, fmt);
  if (fmt != NULL) {
    vsnprintf(buf, sizeof(buf), fmt, ap);
  }
  va_end(ap);

  if (outp.output & FL_OUTP_STDOUT || !outp.syslog_open) {
    if (outp.output & FL_OUTP_STDOUT_EPOCH)
      (void)printf("%lu %s\n", current, buf);
    else {
      strlcpy(tnow, ctime(&current),sizeof(tnow));
      p = tnow + strlen(tnow) -1; /* Point to last character */
      if (*p == '\n')
	*p = ' ';		/* replace trailing \n by blank */
      (void)printf("%s %s\n", tnow, buf);
    }
  } else
    syslog(INFOTYPE, buf);
}


/*
 * Cleanly exit by freeing arrays, list memory, closing down syslog,
 * pcap, etc.
 *
 */

void
util_clean_exit(int err) 
{
  ip_addr_t offset;
  struct ipig *ipig, *next_i;

  /* free up our arrays */
  
  if (ctl.nk_array != NULL) {
    for (offset = 0; offset <= ctl.addresses; offset++)
      util_nk_free(offset);
    MYFREE(ctl.nk_array);
  }

  if (ctl.addr_array != NULL) {
    MYFREE(ctl.addr_array);
  }
  if (ctl.time_array != NULL) {
    MYFREE(ctl.time_array);
  }
  if (ctl.exclusion != NULL) {
    MYFREE(ctl.exclusion);
  }
  if (ctl.port_array != NULL) {
    MYFREE(ctl.port_array);
  }
  
  for (ipig = SLIST_FIRST(&ctl.ipig_q); ipig != SLIST_END(&ctl.ipig_q); ipig = next_i) {
    next_i = SLIST_NEXT(ipig, ipig_next);
    SLIST_REMOVE_HEAD(&ctl.ipig_q, ipig_next);
    brel(ipig);
  }
  SLIST_INIT(&ctl.ipig_q);

  util_print(NORMAL, "Labrea exiting...");

  /* shut down syslog connection */
  if (outp.syslog_open)
    closelog();

  /* shut down I/O */
  lbio_close();

 
  exit(err);
}


/*
 * detach this process and become a daemon (under unix)
 */


void
util_detach (void)
{
#ifndef WIN32
  pid_t fs;

  /* don't detach if not supposed to */
  if ((ctl.mode & FL_DONT_DETACH) 
      || (ctl.mode & FL_TESTMODE))
    return;
  
  if (getppid() != 1) {
    fs = fork();
    if (fs > 0)
      exit(0); /* parent */
    if (fs < 0) {
      errx(EPERM, "Error starting fork");
    }
    setsid();
  }
  /* redirect stdin/stdout/stderr to /dev/null */
  close(0);
  close(1);
  close(2);
  open("/dev/null", O_RDWR);
  dup(0);
  dup(0);
#endif
  return;
}



/*
 * Allocate and initialize new "new kid" element
 *
 * This marks an IP address as belonging to another machine that has
 * sent a gratuitous ARP to announce its presence.
 *
 * offset		offset in ctl arrays corresponding to ip addr
 * culltime		expiry time for this element
 * mac			corresponding mac addr
 *
 * returns	0	elt allocated and initialized
 *		-1	problem encountered
 */
int
util_nk_new (const ip_addr_t offset, const time_t culltime, const uint8_t *mac) 
{
  nk_t  *nk;			/* New nk element */
  
  if ((nk = (nk_t *) bget(sizeof(nk_t))) == NULL) {
    warnx("Error allocating nk element");
    return(-1);
  }

  ctl.nk_array[offset] = nk;
  nk->nk_time = culltime; /* Set time to be culled */

  addr_pack(&(nk->nk_mac), ADDR_TYPE_ETH, ETH_ADDR_BITS,
	    mac, ETH_ADDR_LEN);
  return(0);
}

/*
 * Free nk element 
 *
 * offset		offset in ctl arrays corresponding to ip addr
 */
void
util_nk_free( const ip_addr_t offset )
{
  nk_t *nk;

  if ((nk = ctl.nk_array[offset]) != NULL) {
    DEBUG_PRT(DEBUG_SIGNAL, "util_nk_free: %d", offset);
    brel(nk);
    ctl.nk_array[offset] = NULL;
  }
}

/*
 * Do processing for a kill / int signal
 */

void
util_quit (void)
{
#ifdef WIN32

  DEBUG_PRT(DEBUG_SIGNAL, "util_quit");

  WSACleanup();
  if (ctl.boolThread){
    ctl.boolThread = FALSE;
    while(!ctl.boolThread){
      /* 
       * util_timer will reset the boolThread flag once
       * the thread exits.
       */
      DEBUG_PRT(DEBUG_SIGNAL, "util_quit: loop %d", ctl.boolThread);
      Sleep(300);			/* Not too tight a loop */
    }
  }
#endif
  ctl.signals &= ~SIG_QUIT;
  util_clean_exit(0);
}


/*
 * Do processing for a HUP signal
 */
void
util_restart (void)
{
  DEBUG_PRT(DEBUG_SIGNAL, "util_restart");
  ctl_init_arrays(1);
  util_print(NORMAL, "Received HUP signal, processing re-initialized...");
  ctl.signals &= ~SIG_RESTART; /* reset flag */
  return;
}


/*
 * Do processing of a USR1 signal: toggle logging off / on
 */

void
util_toggle_logging(void)
{
  if (WIN32_FLG)
    return;
  if ((outp.verbose == QUIET) && (outp.savedatalog == QUIET)) {
    outp.verbose = NORMAL;
    util_print(QUIET, "Received USR1 signal, starting data logging");
  } else {
    if (outp.savedatalog != QUIET) {
      outp.verbose = outp.savedatalog;
      outp.savedatalog = QUIET;
      util_print(QUIET, "Received USR1 signal, restarting data logging");
    } else {
      outp.savedatalog = outp.verbose;
      outp.verbose = QUIET;
      util_print(QUIET, "Received USR1 signal, stopping data logging");
    }
  }
  ctl.signals &= ~SIG_TOGGLE_LOGGING; /* reset flag */
  return;
}


/*
 * Handle timer interrupts
 *
 * This routine wakes up every minute to do processing.
 */

void
timer_pop(void) {
  int avgbw, i;
  /* 
   * Run nk list (count down to zero) every few min. But initialize to
   * force cull on 1st timer pop so that arp sweeps can start.
   */
  static int nk_cull_cnt = 1;

  /* Recalculate dynamic ports every 15 min */
  static int dyn_port_cnt = DYN_PORT_INTVL;
		

  nk_t *nk;			/* Used to run nk list */


  ip_addr_t offset=0;
  time_t current = 0;

  DEBUG_PRT(DEBUG_SIGNAL, "timer_pop: nk_cull_cnt: %d, soft_restart: %d"
	    " dyn_port_cnt: %d", 
	    nk_cull_cnt, ctl.soft_restart, dyn_port_cnt);

  ctl.totalbytes -= ctl.past[HIST_MIN];
  for(i = HIST_MIN; i; i--)
    ctl.past[i] = ctl.past[i - 1];
  ctl.past[0] = ctl.currentbytes;
  ctl.totalbytes += ctl.past[0];
  ctl.currentbytes = 0;

  /* Avg Bandwidth = Total # bytes / total sec of hist */
  avgbw = ctl.totalbytes / ((HIST_MIN+1)*60);

  if (ctl.logging & FL_LOG_BDWTH_SYSLOG) {
    util_print(NORMAL, "Current average bw: %i (bytes/sec)", avgbw);
  }
     
  /*
   * This allows for a "soft" restart by letting 5 minutes go by
   * before allowing any new connections are captured.  If you
   * restart with this enabled, then it should "recapture" the old
   * stuff, and base the bw calc on that before grabbing anything
   * new...
   *                          
   * I got bit by this... that's why I thought to do it...
   */

  if (ctl.soft_restart > 0)
    ctl.soft_restart--;
  else
    /*
     * Attempt to keep bw in line when you're getting hammered by
     * limiting new connections that we'll allow to be captured per
     * minute
     */
    ctl.newthisminute = (ctl.maxbw > avgbw) ?  (ctl.maxbw - avgbw) : 0;

  /*
   * When a machine sends out a gratuitous ARP to announce its
   * presence, then it is placed on the "new kids" list.
   *
   * Now run through the "new kids" array to cull out IP addr that have
   * shown no activity within the given time period.
   */ 
  if ((--nk_cull_cnt) <= 0) {
    current = time(NULL);     

    for (offset = 0; offset <= ctl.addresses; offset++) {
      /* 
       * Cull the entries that have timed out with no response but
       * send a Who-Has arp to see if someone's still there
       */
      if ((nk = ctl.nk_array[offset]) != NULL) {
	if ((nk->nk_time + CULLTIME) <= current) {
	  lbio_send_ARP_Who_Has(ctl.base + offset);
	  util_nk_free(offset);
	}
      }
    }
    nk_cull_cnt = NK_CULL_INTVL; /* Reset counter */
  }

  /*
   * Recalculate dynamic port array if firewalling ports
   *
   * Reduce count on all ports being monitored so that random
   * "noise" is eliminated.  However once / if a port has "maxed
   * out", it will always respond from then on.
   *  
   */
  if (ctl.feature & FL_NO_RST_EXCL_PORT) {
    if ((--dyn_port_cnt) <= 0) {
      for(i=1; i<=PORT_NUM; i++){
	if ((ctl.port_array[i] > PORT_MONITOR)
	    &&(ctl.port_array[i] < PORT_MAX)) {
	  DEBUG_PRT(DEBUG_SIGNAL, "timer_pop: reducing count port %d = ",
		    i, ctl.port_array[i]);
	  ctl.port_array[i]--;
	}
      }
      dyn_port_cnt = DYN_PORT_INTVL; /* Reset counter */
    }
  }
}


/*
  * Windows timer handler
  *
  *	Under windows, a separate thread is set up. It sleeps
  * normally, waking up to check for termination (ie if
  * boolThread = FALSE).
  *
  * Every n cycles (= 1 min), a timer pop is simulated.
  */

#ifdef WIN32
DWORD WINAPI
util_timer(LPVOID lpAintGonnaUseThis)
{
  int j = 0;

  /* 
   */
  ctl.boolThread = TRUE;
  for(;;) {
    j++;
    if (!ctl.boolThread) {
      ctl.boolThread = TRUE;
      DEBUG_PRT(DEBUG_SIGNAL, "util_timer: exit thread");
      ExitThread(0);
    }
    if (j >= WAKEUP_SEC) {
      j = 0;
      timer_pop();		/* Process timer pop */
    }
    Sleep(WAKEUP_MSEC);
  }
  return(0);
}
#else

/*
  * Unix timer handler
  */

void
util_timer(void)
{
  timer_pop();		/* Process timer pop */

  ctl.signals &= ~SIG_TIMER; /* reset flag */  
  alarm(WAKEUP_SEC);
}
#endif

/*
 * Signal handlers - just set flags to fire up mainline processing
 */

RETSIGTYPE
catch_sig_restart(int sig)
{
  ctl.signals |= SIG_RESTART;
}

RETSIGTYPE
catch_sig_quit(int sig)
{
  if (WIN32_FLG)
    ctl.signals |= SIG_QUIT;
  else
    util_quit();
  /*
   * Quit directly since pcap_dispatch might not timeout on certain
   * systems.
   */
}

RETSIGTYPE
catch_sig_timer(int sig)
{
  ctl.signals |= SIG_TIMER;
}

RETSIGTYPE
catch_sig_toggle_logging(int sig)
{
  ctl.signals |= SIG_TOGGLE_LOGGING;
}



/*
 * set up the signal handlers
 */

void
util_set_signal_handlers(void)
{
#ifdef WIN32
  DWORD dummy;	/* For thread creation */
#else
  static sigset_t set;
  sigemptyset(&set);
  sigprocmask(SIG_SETMASK, &set, NULL);
#endif

  /* set signals so that we behave nicely */

#ifdef LB_SYSTEM_IS_SUN
  /* special function call for solaris so signal hdlr doesn't go away */
  sigset(SIGTERM, catch_sig_quit);
  sigset(SIGINT, catch_sig_quit);
  sigset(SIGQUIT, catch_sig_quit);
  sigset(SIGHUP, catch_sig_restart);
  sigset(SIGALRM, catch_sig_timer);
  sigset(SIGUSR1, catch_sig_toggle_logging);
#elif defined(WIN32)
  /* windows signal handlers */
  signal(SIGTERM, catch_sig_quit);
  signal(SIGINT, catch_sig_quit);
#else
  /* generic unix signal handlers */
  signal(SIGTERM, catch_sig_quit);
  signal(SIGINT, catch_sig_quit);
  signal(SIGQUIT, catch_sig_quit);
  signal(SIGHUP, catch_sig_restart);
  signal(SIGALRM, catch_sig_timer);
  signal(SIGUSR1, catch_sig_toggle_logging);
#endif
}


/*
 * set up the timer pop
 */

void
util_alarm(void)
{
#ifndef WIN32
  /* fire off an alarm */
  alarm(WAKEUP_SEC);	
#else
  /* Under windows, fire up a thread to simulate a timer pop */
  CloseHandle(CreateThread(NULL,0,util_timer,0,0,&dummy));
#endif
}

/*
 * Windows only: Check version of Windows that are running on
 *
 * returns:		1	Version is Win98 or better
 *              0   Version is Win95 or something else not supported
 *
 */
int
util_check_version_win98 (void)
{
#ifdef WIN32
  OSVERSIONINFO osvi;
  BOOL bIsWindows98orLater = FALSE;

  if (util_check_version_winNT())		/* If WinNT or better then ok */
    return (TRUE);

  osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);	
  GetVersionEx (&osvi);
	
  bIsWindows98orLater = 
    (osvi.dwPlatformId == VER_PLATFORM_WIN32_WINDOWS) &&
    ( (osvi.dwMajorVersion > 4) ||
      ( (osvi.dwMajorVersion == 4) && (osvi.dwMinorVersion > 0) ) );
  return(bIsWindows98orLater);
#else
  return(0);
#endif
}

/*
 * Windows only: Check version of Windows that are running on
 *
 * returns:		1	Version is NT4.0 or better
 *              0   Version is Win95/98 or something else not supported
 *
 */
int
util_check_version_winNT (void)
{
#ifdef WIN32
  OSVERSIONINFO osvi;
  BOOL bIsWindowsNTorLater = FALSE;

  osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);	
  GetVersionEx (&osvi);
  bIsWindowsNTorLater = (osvi.dwPlatformId == VER_PLATFORM_WIN32_NT) &&
    (osvi.dwMajorVersion >= 4);

  return(bIsWindowsNTorLater);
#else
  return(0);
#endif
}
