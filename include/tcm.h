#ifndef __TCM_H
#define __TCM_H

/* $Id: tcm.h,v 1.41 2002/05/26 13:09:19 leeh Exp $ */

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
#define MAX_DOMAIN	80
#define MAX_REASON	120	/* should be quite long enough */
#define MAX_IP		20
#define MAX_CLASS       50

/* XXX not sure on this one yet -db */
#define MAX_WHO		(MAX_NICK+MAX_USER+MAX_HOST+5)

/* Macros for universal OS handling of signal vectors */
#define sysvhold notice

#define INVALID (-1)

#define YES 1
#define NO 0

#define SET_PRIVMSG	1	/* See privmsg's to the tcm */
#define SET_NOTICES	2	/* See some server notices, for remote users */


#define FOREVER for(;;)	

extern struct connection connections[MAXDCCCONNS+1];

time_t startup_time, oper_time;

char mychannel[MAX_CHANNEL];
char mynick[MAX_NICK];
char serverhost[MAX_HOST];
char ourhostname[MAX_HOST];

extern int incoming_connnum;
int amianoper;
int quit;			/* Quit when = YES */

int maxconns;

extern unsigned long totalmem;
extern unsigned long numalloc;
extern unsigned long numfree;

int add_action(char *name);
void set_action_time(int action, int klinetime);
void set_action_reason(int action, char *reason);
void set_action_method(int action, int method);
void set_action_strip(int action, int hoststrip);
int find_action(char *name);

/* Fixes for broken operating systems */
#ifndef HAVE_STRLCAT
size_t strlcat(char *, const char *, size_t);
#endif

#ifndef HAVE_STRLCPY
size_t strlcpy(char *, const char *, size_t);
#endif

#ifdef SERVICES
int act_drone, act_sclone;
void init_services(void);
void check_services(void *);
#endif

void *xmalloc(size_t);
void xfree(void *);

#endif
