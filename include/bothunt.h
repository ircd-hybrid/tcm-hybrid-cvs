#ifndef __BOTHNUT_H
#define __BOTHUNT_H

/* $Id: bothunt.h,v 1.56 2002/08/10 21:08:09 bill Exp $ */


struct source_client;
struct connection;

/* reconnect clone detect */

struct reconnect_clone_entry
{
  char host [MAX_HOST];
  int count;
  time_t first;
};
extern struct reconnect_clone_entry reconnect_clone[];

/* XXXX */
void _config(int, int, char *argv[]);

#define MSG_CLIENT_CONNECTING	"Client connecting: "
#define MSG_CLIENT_EXITING	"Client exiting: "
#define MSG_UNAUTHORIZED	"Unauthorized client connection"
#define MSG_UNAUTHORISED	"Unauthorised client connection"
#define MSG_NICK_CHANGE		"Nick change:"
#define MSG_IDLE_TIME		"Idle time limit exceeded for "
#define MSG_LINKS		"LINKS "
#define MSG_KLINE		"KLINE "
#define MSG_STATS		"STATS "
#define MSG_GOT_SIGNAL		"Got signal"
#define MSG_NICK_COLLISION	"Nick collision on"
#define MSG_SEND_MESSAGE	"Send message"
#define MSG_GHOSTED		"Ghosted"
#define MSG_CONNECT_FAILURE	"connect failure"
#define MSG_INVISIBLE_CLIENT	"Invisible client count"
#define MSG_OPER_COUNT_OFF	"Oper count off by"
#define MSG_USER_COUNT_OFF	"User count off by"
#define MSG_LINK_WITH		"Link with"
#define MSG_SQUIT		"Received SQUIT"
#define MSG_MOTD		"motd requested by"
#define MSG_FLOODER		"Flooder"
#define MSG_USER		"User"
#define MSG_I_LINE_MASK		"I-line mask"
#define MSG_I_LINE_FULL		"I-line is full"
#define MSG_BANNED		"*** Banned: "
#define MSG_D_LINED		"*** You have been D-lined"
#define MSG_DRONE_FLOODER	"Possible Drone Flooder"
#define MSG_X_LINE		"X-line Rejecting"
#define MSG_INVALID_USERNAME	"Invalid username:"
#define MSG_SERVER		"Server"
#define MSG_FAILED_OPER		"Failed OPER attempt"
#define MSG_INFO_REQUESTED	"info requested by"
#define MSG_NO_ACONF		"No aconf found"
#define MSG_QUARANTINED		"Quaratined nick"

#define IGNORE		-1
#define CONNECT		 0
#define EXITING		 1
#define UNAUTHORIZED	 2
#define NICKCHANGE	 3
#define LINK_LOOK	 7
#define KLINE_ADD_REPORT 8	/* Toast */
#define STATS		 9
#define SIGNAL		10
#define LINKWITH	11
#define SQUITOF		19
#define MOTDREQ		20
#define FLOODER		21
#define SPAMBOT		22
#define ILINEFULL	23
#define BANNED		24
#define DRONE		26
#define XLINEREJ	27
#define INVALIDUH	28
#define SERVER		29
#define FAILEDOPER	30
#define INFOREQUESTED	31
#define NOACONFFOUND	32
#define QUARANTINE	33

#define CLONECONNECTCOUNT 3
#define CLONECONNECTFREQ  30

#define CLONERECONCOUNT   5	/* this many reconnects */
#define CLONERECONFREQ    15    /* in this many seconds */

void report_nick_flooders(struct connection *);
void init_link_look_table(void);
void init_bothunt(void);
void clear_bothunt(void);
void on_trace_user(int argc, char *argv[]);
void on_stats_i(int argc, char *argv[]);
void on_server_notice(struct source_client *, int argc, char *argv[]);
char *get_user_host(char **user_p, char **host_p, char *user_host);
extern struct s_testline testlines;
#endif
