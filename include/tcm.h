#ifndef __TCM_H
#define __TCM_H

#include <sys/time.h>
#include "config.h"

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

#ifdef DEBUGMODE
 char placef[16][30];
 int placel[16];
 #define placed { add_placed(__FILE__, __LINE__); }
#endif

#define SET_PRIVMSG	1	/* See privmsg's to the tcm */
#define SET_NOTICES	2	/* See some server notices, for remote users */


#define FOREVER for(;;)	

/*
 * retry time between attempts to re-init the TCM listen port
 */
#define REMOTE_TCM_CHECK_TIME 60

time_t startup_time, oper_time;

char mychannel[MAX_CHANNEL];
char mynick[MAX_NICK];
int amianoper;
int quit;			/* Quit when = YES */
int remote_tcm_socket;		/* listening socket */

fd_set readfds;

int maxconns;

#ifdef IRCD_HYBRID
#else
void m_unregistered(int connnum, int argc, char *argv[]);
void m_not_oper(int connnum, int argc, char *argv[]);
void m_not_admin(int connnum, int argc, char *argv[]);
#endif

#endif
