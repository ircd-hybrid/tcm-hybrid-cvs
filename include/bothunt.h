#ifndef __BOTHUNT_H
#define __BOTHUNT_H

/* $Id: bothunt.h,v 1.52 2002/06/21 15:34:12 leeh Exp $ */

void report_mem(int);
void print_motd(int);		

struct source_client;

/* XXXX */
void _config(int, int, char *argv[]);

#define MSG_CLIENT_CONNECTING	"Client connecting: "
#define MSG_CLIENT_EXITING	"Client exiting: "
#define MSG_UNAUTHORIZED	"Unauthorized "
#define MSG_UNAUTHORISED	"Unauthorised client connection"
#define MSG_NICK_CHANGE		"Nick change:"
#define MSG_NICK_FLOODING	"Nick flooding detected by:"
#define MSG_REJECTING		"Rejecting "
#define MSG_CLONEBOT_KILLED	"Clonebot killed:"
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
#define CS_CLONES	 3	/* CSr notice */
#define NICKCHANGE	 5
#define CS_NICKFLOODING	 6	/* CSr notice */
#define CS_CLONEBOT_KILLED 8	/* CSr notice */
#define CS_IDLER	 9	/* CSr notice */
#define LINK_LOOK	10
#define KLINE_ADD_REPORT 11	/* Toast */
#define STATS		12
#define SIGNAL		13
#define LINKWITH	14
#define WRITEERR	15
#define SQUITOF		16
#define MOTDREQ		17
#define FLOODER		18
#define SPAMBOT		19
#define ILINEMASK	20
#define ILINEFULL	21
#define BANNED		22
#define DRONE		23
#define XLINEREJ	24
#define INVALIDUH	25
#define SERVER		26
#define FAILEDOPER	27
#define INFOREQUESTED	28
#define NOACONFFOUND	29
#define QUARANTINE	30

#define CLONECONNECTCOUNT 3
#define CLONECONNECTFREQ  30

#define CLONERECONCOUNT   5	/* this many reconnects */
#define CLONERECONFREQ    15    /* in this many seconds */

#define RECONNECT_CLONE_TABLE_SIZE 50

struct reconnect_clone_entry
{
  char host [MAX_HOST];
  int count;
  time_t first;
};

struct reconnect_clone_entry reconnect_clone[RECONNECT_CLONE_TABLE_SIZE];

#define LINK_LOOK_TABLE_SIZE 10

struct link_look_entry
{
  char user_host[MAX_USERHOST];
  int  link_look_count;
  time_t last_link_look;
};

struct link_look_entry link_look[LINK_LOOK_TABLE_SIZE];

#define CONNECT_FLOOD_TABLE_SIZE 30

struct connect_flood_entry
{
  char user[MAX_USER];
  char host[MAX_HOST];
  char ip[MAX_IP];
  int  connect_count;
  time_t last_connect;
};

void report_nick_flooders(int sock);
void init_link_look_table(void);
void init_bothunt(void);
void clear_bothunt(void);
void on_trace_user(int argc, char *argv[]);
void on_stats_i(int argc, char *argv[]);
void on_server_notice(struct source_client *, int argc, char *argv[]);
int  get_user_host(char **user_p, char **host_p, char *user_host);
extern struct s_testline testlines;
#endif
