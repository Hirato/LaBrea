/* $Id: debug.h,v 1.2 2003/09/12 21:23:39 lorgor Exp $ */
/*
** Copyright (C) 1998-2002 Martin Roesch <roesch@sourcefire.com>
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License as published by
** the Free Software Foundation; either version 2 of the License, or
** (at your option) any later version.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
**
** $Id: debug.h,v 1.2 2003/09/12 21:23:39 lorgor Exp $
*/


#ifndef DEBUG_H
#define DEBUG_H

#define DEBUG_TEXT "LABREA_DEBUG: "

#define DEBUG_ALL             		0xffffffff
#define DEBUG_INIT            		0x00000001  /* 1 */
#define DEBUG_PKTIO			0x00000002  /* 2 */
#define DEBUG_PKTPROC		  	0x00000004  /* 4 */
#define DEBUG_SIGNAL		  	0x00000008  /* 8 */
#define DEBUG_xxx3          		0x00000010  /* 16 */
#define DEBUG_xxx4			0x00000020  /* 32 */
#define DEBUG_xxx5			0x00000040  /* 64 */
#define DEBUG_xxx6			0x00000080  /* 128 */
#define DEBUG_xxx7			0x00000100  /* 256 */
#define DEBUG_xxx8			0x00000200  /* 512 */
#define DEBUG_xxx9			0x00000400  /* 1024 */
#define DEBUG_xxx10			0x00000800  /* 2048 */
#define DEBUG_xxx11			0x00001000  /* 4096 */
#define DEBUG_xxx12			0x00002000  /* 8192 */
#define DEBUG_xxx13			0x00004000  /* 16384 */
#define DEBUG_xxx14			0x00008000  /* 32768 */
#define DEBUG_xxx15			0x00010000  /* 65536 */
#define DEBUG_xxx16         		0x00020000  /* 131072 */
#define DEBUG_xxx17			0x00040000  /* 262144 */
#define DEBUG_xxx18			0x00080000  /* 524288 / (+ conv2 ) 589824 */

#ifdef DEBUG_LB
#define DEBUG_PRT(dbg,fmt,arg...) \
 if (ctl.debuglevel & dbg) util_print(QUIET,"Labrea_DEBUG: " fmt,##arg);
#else
#define DEBUG_PRT(dbg,fmt,arg...)

#endif

#endif /* DEBUG_H */
