#ifndef __BOTHUNT_H
#define __BOTHUNT_H

/* $Id: bothunt.h,v 1.19 2001/12/04 18:20:54 bill Exp $ */

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
    char *user;
    char *host;
    char *reason;
    time_t *when;
    int pending;
    int duration;
    struct banned_info *next;
  };

#define IGNORE		-1
#define CONNECT		 0
#define EXITING		 1
#define UNAUTHORIZED	 2
#define CS_CLONES	 3	/* CSr notice */
#define TOOMANY		 4
#define NICKCHANGE	 5
#define CS_NICKFLOODING	 6	/* CSr notice */
#define REJECTING	 7
#define CS_CLONEBOT_KILLED 8	/* CSr notice */
#define CS_IDLER	 9	/* CSr notice */
#define LINK_LOOK	10
#define KLINE_ADD_REPORT 11	/* Toast */
#define STATS		12

#define LINKWITH	13
#define WRITEERR	14
#define SQUITOF		15
#define MOTDREQ		16
#define FLOODER		17
#define SPAMBOT		18
#define ILINEMASK	19
#define ILINEFULL	20
#define BANNED		21
#define DRONE		22
#define XLINEREJ	23
#define INVALIDUH	24
#define SERVER		25
#define FAILEDOPER	26
#define INFOREQUESTED	27

#define CLONECONNECTCOUNT 3
#define CLONECONNECTFREQ  30

#define CLONERECONCOUNT   2	/* this many reconnects */
#define CLONERECONFREQ    15    /* in this many seconds */

extern int maxconns;

void list_nicks(int, char *);	
void list_class(int, char *, int);	

void list_virtual_users(int sock,char *);

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

#endif
