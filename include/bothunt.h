#ifndef __BOTHUNT_H
#define __BOTHUNT_H

void report_mem(int);
void print_motd(int);		

struct plus_c_info
  {
    char *user;
    char *host;
    char class[100];
    char ip[16];
  };

/* The code uses the index into the msgs_to_mon[] table as the
 * token value to hand to the switch.
 */

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
#define JOHBOT		13
#define EGGDROP		14
#define IGNORE1		15
#define IGNORE2		16
#define IGNORE3		17
#define IGNORE4		18
#define IGNORE5		19
#define IGNORE6		20
#define IGNORE7		21
#define LINKWITH	22
#define WRITEERR	23
#define SQUITOF		24
#define MOTDREQ		25
#define FLOODER		26
#define SPAMBOT		27
#define ILINEMASK	28
#define ILINEFULL	29

#define CLONECONNECTCOUNT 3
#define CLONECONNECTFREQ  30

extern int maxconns;

void list_nicks(int, char *);	
void list_class(int, char *, int);	

void kill_list_users(int sock, char *userhost, char *reason);
void list_users(int sock,char *userhost);
void list_virtual_users(int sock,char *);

void check_clones(void);
void report_clones(int);

void check_host_clones(char *);
void check_virtual_host_clones(char *);

void ilinemask(char *body);

void chopuh(int,char *,struct plus_c_info *);

#ifdef BOT_WARN
void bot_report_kline(char *,char *);
#endif

void report_nick_flooders(int);
void initopers(void);

#ifdef DETECT_DNS_SPOOFERS
void confirm_match_ip(char *,char *,char *);
#endif

void inithash(void);
void init_link_look_table(void);

void report_failures(int sock, int num);
void report_domains(int sock, int num);
void report_multi(int sock, int nclones);
void report_multi_host(int sock, int nclones);
void report_multi_user(int sock, int nclones);
void report_multi_virtuals(int sock, int nclones);
void report_vmulti(int sock,int nclones);

#endif
