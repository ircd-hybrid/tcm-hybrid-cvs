#ifndef __BOTHUNT_H
#define __BOTHUNT_H

/* maximum IP length in adduserhost() removeuserhost() */
#define MAX_IP 20

void freehash(void);
void init_hash_tables(void);
void init_nick_change_table();
void on_stats_o(char *);	
void on_stats_e(char *);	
void on_stats_i(char *);	
void on_stats_k(char *);	
void kfind(int socket, char *pattern);
void onservnotice(char *);
void print_help(int socket,char *help);

void onctcp(char *,char *,char *);
void report_mem(int);
void print_motd(int);		

struct userentry {
  char nick[MAX_NICK];
  char user[MAX_NICK+1];
  char host[MAX_HOST];
  char ip_host[MAX_IP];		/* host ip as string */
  char ip_class_c[MAX_IP];	/* /24 of host ip as string */
  char domain[MAX_DOMAIN];
  char link_count;
  char isoper;
  char class[100];  /* -1 if unknown */
  time_t connecttime;
  time_t reporttime;
  };

struct hashrec
  {
    struct userentry *info;
    struct hashrec *collision;
  };

struct plus_c_info
  {
    char *user;
    char *host;
    char class[100];
    char *ip;
  };

struct failrec
{
  char user[MAX_NICK+1];
  char host[MAX_HOST];
  int botcount;
  int failcount;
  struct failrec *next;
};

extern struct connection connections[];

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

#define HASHTABLESIZE 3001

#define CLONECONNECTCOUNT 3
#define CLONECONNECTFREQ  30

#define CLONEDETECTINC 15
#define MAXFROMHOST    50

extern int maxconns;

void list_nicks(int, char *);	
void list_class(int, char *, int);	

void kill_list_users(int socket, char *userhost, char *reason);
void list_users(int socket,char *userhost);
void list_virtual_users(int socket,char *);

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

void ontraceuser(char *traceline);
void ontraceclass(void);
void inithash(void);
void init_link_look_table(void);

void report_failures(int socket, int num);
void report_domains(int socket, int num);
void report_multi(int socket, int nclones);
void report_multi_host(int socket, int nclones);
void report_multi_user(int socket, int nclones);
void report_multi_virtuals(int socket, int nclones);

#endif
