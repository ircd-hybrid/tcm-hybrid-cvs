#ifndef __BOTHUNT_H
#define __BOTHUNT_H

/* $Id: bothunt.h,v 1.26 2002/05/22 22:03:27 leeh Exp $ */

void report_mem(int);
void print_motd(int);		

struct plus_c_info
{
  char *user;
  char *host;
  char class[100];
  char ip[16];
};

struct banned_info
{
  char user[MAX_USER+1];
  char host[MAX_HOST+1];
  char reason[MAX_REASON];
  char who[MAX_WHO];
  char server[MAX_DOMAIN+1];
  time_t when;
  struct banned_info *next;
};

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
int  makeconn(char *,char *,char *);
void m_gline(int connnum, int argc, char *argv[]);

extern void init_bothunt(void);

extern void _reload_bothunt(int connnum, int argc, char *argv[]);
extern void _ontraceuser(int connnum, int argc, char *argv[]);
extern void _ontraceclass(int connnum, int argc, char *argv[]);
extern void _onctcp(int connnum, int argc, char *argv[]);
extern void on_stats_o(int connnum, int argc, char *argv[]);
extern void on_stats_e(int connnum, int argc, char *argv[]);
extern void on_stats_i(int connnum, int argc, char *argv[]);
extern void onservnotice(int connnum, int argc, char *argv[]);

#endif
