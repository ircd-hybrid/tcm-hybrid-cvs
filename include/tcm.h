#ifndef __TCM_H
#define __TCM_H

/* $Id: tcm.h,v 1.48 2002/05/29 01:19:29 leeh Exp $ */

#include <sys/time.h>
#include "config.h"

extern time_t current_time;

#define MAX_ARGV	80

/* Buffer sizes */

/* Size of read buffer on DCC or server connections */
#define BUFFERSIZE     1024

/* scratch buffer size */
#define MAX_BUFF       512

/* maximum amount of actions */
#define MAX_ACTIONS	32

/* small scratch buffer size */
#define SMALL_BUFF	32

/* only used for formatting up kline reasons */
#define COMMENT_BUFF	64

#define DCCBUFF_SIZE   150
#define NOTICE_SIZE    150

#define MAX_NICK	10
#define MAX_CHANNEL	80
#define MAX_USER	11
#define MAX_HOST	80	
#define MAX_USERHOST	MAX_USER + MAX_HOST
#define MAX_REASON	120	/* should be quite long enough */
#define MAX_IP		20
#define MAX_CLASS       50

/* Macros for universal OS handling of signal vectors */
#define sysvhold notice

#define INVALID (-1)

#define YES 1
#define NO 0

#define FOREVER for(;;)	

extern unsigned long totalmem;
extern unsigned long numalloc;
extern unsigned long numfree;

/* XXX - this is in clones.c */
void init_clones(void);

/* XXX - this is in vclones.c */
void init_vclones(void);

/* Fixes for broken operating systems */
#ifndef HAVE_STRLCAT
size_t strlcat(char *, const char *, size_t);
#endif

#ifndef HAVE_STRLCPY
size_t strlcpy(char *, const char *, size_t);
#endif

#ifdef SERVICES
void init_services(void);
void check_services(void *);
#endif

void *xmalloc(size_t);
void xfree(void *);

#endif
