#ifndef __TCM_H
#define __TCM_H

/* $Id: tcm.h,v 1.23 2002/05/03 22:49:43 einride Exp $ */

#include <sys/time.h>
#include "config.h"

#define MAX_ARGV	80

/* Buffer sizes */

/* Size of read buffer on DCC or server connections */
#define BUFFERSIZE     1024

/* scratch buffer size */
#define MAX_BUFF       512

/* maximum amount of actions */
#define MAX_ACTIONS	100

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
void set_action_time(int action, int time);
void set_action_reason(int action, char *reason);
void set_action_method(int action, int method);
void set_action_strip(int action, int hoststrip);

int find_action(char *name);

#endif
