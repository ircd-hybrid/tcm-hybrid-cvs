#ifndef __TCM_H
#define __TCM_H

/* $Id: tcm.h,v 1.62 2004/06/15 22:36:31 bill Exp $ */

#include <sys/time.h>
#include "config.h"

extern time_t current_time;

#define MAX_ARGV	80

/* Buffer sizes */

/* Size of read buffer on DCC or server connections */
#define BUFFERSIZE     1024

/* scratch buffer size */
#define MAX_BUFF       512

/* small scratch buffer size */
#define SMALL_BUFF	32

/* only used for formatting up kline reasons */
#define COMMENT_BUFF	64

#define DCCBUFF_SIZE   150
#define NOTICE_SIZE    150

#define MAX_CONFIG	80
#define MAX_NICK	9
#define MAX_CHANNEL	80
#define MAX_USER	10
#define MAX_HOST	80	
#define MAX_USERHOST	MAX_USER + 1 + MAX_HOST
#define MAX_GECOS	55
#define MAX_REASON	100	/* should be quite long enough */
#ifdef IPV6
#define MAX_IP		50
#else
#define MAX_IP		20
#endif
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

void init_clones(void);
void init_vclones(void);
void init_commands(void);
void init_serv_commands(void);

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

#ifndef INADDR_NONE
/* Needed for Solaris, stolen from Hybrid 7 */
#define INADDR_NONE ((unsigned int) 0xffffffff)
#endif

#define  BadPtr(x) (!(x) || (*(x) == '\0'))

#endif
