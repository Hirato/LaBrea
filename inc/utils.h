/* utils.h
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
 * $Id: utils.h,v 1.1 2003/01/09 18:13:19 lorgor Exp $
*/

#ifndef UTILS_H
#define UTILS_H

#include <dnet.h>
 
/* Degree of verbosity in logging */
typedef enum {QUIET, NORMAL, VERBOSE, VERY_VERBOSE} amt_log_t;


/* Output / logging control structure */
struct outp_s {

  /* flags */
  uint16_t 		output;
#define FL_OUTP_STDOUT_EPOCH	0x0001 	/* -O */
#define FL_OUTP_STDOUT		0x0002	/* -o */



  /* globals */
  amt_log_t		verbose;	/* Degree of verbosity in logging */
  int			savedatalog;	/* Save old logging level when logging turned off */
  int			syslog_open;	/* TRUE if syslog open */
};

typedef struct outp_s outp_t;
extern outp_t outp;



void		util_init(void);
void		util_open_syslog(char *ident);
void		util_print(const amt_log_t verbosity_msg, const char *fmt, ...);
void		util_clean_exit(int err);
int		util_nk_new (const ip_addr_t offset, const time_t culltime,
			     const uint8_t *mac);
void		util_nk_free( const ip_addr_t offset );
void		util_detach (void);

void		util_set_signal_handlers(void);
void		util_quit (void);
void		util_restart (void);
#ifndef WIN32
void		util_toggle_logging(void);
#endif

#ifdef WIN32
DWORD WINAPI	util_timer(LPVOID lpAintGonnaUseThis);
#else
void		util_timer(void);
#endif

int		util_check_version_win98(void);
int		util_check_version_winNT(void);



#endif /* UTILS_H */
