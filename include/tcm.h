#ifndef __TCM_H
#define __TCM_H

/* $Id: tcm.h,v 1.29 2002/05/22 15:08:39 db Exp $ */

#include <sys/time.h>
#include "config.h"

extern time_t CurrentTime;

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

time_t startup_time, oper_time;

char mychannel[MAX_CHANNEL];
char mynick[MAX_NICK];
int amianoper;
int quit;			/* Quit when = YES */

fd_set readfds;

int maxconns;

#ifdef IRCD_HYBRID
#else
void m_unregistered(int connnum, int argc, char *argv[]);
void m_not_oper(int connnum, int argc, char *argv[]);
void m_not_admin(int connnum, int argc, char *argv[]);
#endif

void init_hash_tables(void);
int add_action(char *name);
void set_action_time(int action, int klinetime);
void set_action_reason(int action, char *reason);
void set_action_method(int action, int method);
void set_action_strip(int action, int hoststrip);
int find_action(char *name);

void expand_args(char *output, int maxlen, int argc, char *argv[]);
/* Fixes for broken operating systems */
#ifndef HAVE_STRLCAT
size_t strlcat(char *, const char *, size_t);
#endif

#ifndef HAVE_STRLCPY
size_t strlcpy(char *, const char *, size_t);
#endif

#endif
