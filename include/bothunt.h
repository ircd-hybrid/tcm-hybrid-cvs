#ifndef __BOTHUNT_H
#define __BOTHUNT_H

/* $Id: bothunt.h,v 1.38 2002/05/27 21:47:07 leeh Exp $ */

void report_mem(int);
void print_motd(int);		

/* XXX */
struct plus_c_info
{
  char *nick;
  char *user;
  char *host;
  char class[MAX_CLASS+1];
  char ip[MAX_IP+1];
};

/* XXXX */
void _config(int, int, char *argv[]);
void _reload_wingate(int, int, char *argv[]);

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
  char host [MAX_HOST+1];
  int count;
  time_t first;
};

struct reconnect_clone_entry reconnect_clone[RECONNECT_CLONE_TABLE_SIZE];

#define LINK_LOOK_TABLE_SIZE 10

struct link_look_entry
{
  char user_host[MAX_USER+MAX_HOST+2];
  int  link_look_count;
  time_t last_link_look;
};

struct link_look_entry link_look[LINK_LOOK_TABLE_SIZE];

#define CONNECT_FLOOD_TABLE_SIZE 30

struct connect_flood_entry
{
  char user_host[MAX_USER+MAX_HOST+2];
  char ip[18];
  int  connect_count;
  time_t last_connect;
};

extern int maxconns;

void report_clones(int);

void ilinemask(char *body);

void chopuh(int,char *,struct plus_c_info *);

#ifdef BOT_WARN
void bot_report_kline(char *,char *);
#endif

void report_nick_flooders(int);
void initopers(void);

void inithash(void);
void init_link_look_table(void);
void report_failures(int sock, int num);
void report_domains(int sock, int num);
void report_vbots(int sock,int nclones);
void kill_add_report(char *);
void report_vbots(int sock,int nclones);
void report_domains(int sock,int num);
void list_class(int sock,char *class_to_find,int total_only);

extern void init_bothunt(void);
extern void _reload_bothunt(int connnum, int argc, char *argv[]);
extern void _ontraceuser(int connnum, int argc, char *argv[]);
extern void _ontraceclass(int connnum, int argc, char *argv[]);
extern void on_stats_e(int connnum, int argc, char *argv[]);
extern void on_stats_i(int connnum, int argc, char *argv[]);
extern void onservnotice(int connnum, int argc, char *argv[]);
extern struct s_testline testlines;
extern int doingtrace;
extern char myclass[MAX_CLASS]; /* XXX ewww */

/* XXX candidates for hash.c/hash.h */
struct hashrec *find_nick(const char * nick);
struct hashrec *find_host(const char * host);
#endif
