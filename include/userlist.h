#ifndef __USERLIST_H
#define __USERLIST_H

/* $Id: userlist.h,v 1.51 2002/05/27 23:49:10 leeh Exp $ */

/* maximum IP length in adduserhost() removeuserhost() */
#define MAX_IP 20
#define MAX_CONFIG	80
#define HASHTABLESIZE 3001
#define MAXFROMHOST    50
#define CLONEDETECTINC 15
#define NICK_CHANGE_TABLE_SIZE 100

struct f_entry {
  int type;
  char uhost[MAX_NICK+2+MAX_HOST];
  struct f_entry *next;
};

struct failrec
{
  char user[MAX_NICK+1];
  char host[MAX_HOST];
  int botcount;
  int failcount;
  struct failrec *next;
};
struct failrec *failures;


struct config_list {
  int  hybrid;
  int  hybrid_version;
  char tcm_pid_file[MAX_CONFIG];
  char username_config[MAX_CONFIG];
  char virtual_host_config[MAX_CONFIG];
  char oper_nick_config[MAX_CONFIG];
  char oper_pass_config[MAX_CONFIG];
  char server_name[MAX_CONFIG];
  char rserver_name[MAX_CONFIG];
  char server_port[MAX_CONFIG];
  char server_pass[MAX_CONFIG];
  char port_config[MAX_CONFIG];
  char ircname_config[MAX_CONFIG];
  char email_config[MAX_CONFIG];
  char userlist_config[MAX_CONFIG];
  int  debug;
  char defchannel[MAX_CHANNEL];		/* Channel tcm will use. */
  char defchannel_key[MAX_CONFIG];	/* key for Channel tcm will use. */
  char defchannel_mode[MAX_CONFIG];     /* Default mode (not including the
                                        ** key) for the channel */
  char dfltnick[MAX_NICK];		/* Nickname tcm will use */
  int  channel_report;			/* bit map of flags */

  char statspmsg[MAX_CONFIG];

  int nofork;
  char *conffile;
};

/*
 * authentication structure set up in userlist.c
 * used for .register command
 */

struct auth_file_entry
{
  char user[MAX_NICK+1];
  char host[MAX_HOST];
  char usernick[MAX_NICK];
  char password[MAX_CONFIG];
  int type;
};

struct exception_entry
{
  char user[MAX_NICK+1];
  char host[MAX_HOST];
  int type;
};

int find_user_in_userlist(const char *);
int find_user_in_connections(const char *);
int get_umodes_from_prefs(int);
int get_umodes_current(int);

void set_umode(int, int, const char *);
void add_an_oper(int, char *argv[]);

int has_umode(int, int);

void load_userlist(void);
void load_config_file(char *);
void clear_userlist(void);
void ban_manipulate(int sock,char flag,char *userlist);
void save_prefs(void);
int  okhost(char *,char *,int);
int  str2type(char *);
char *type_show(unsigned long type);
int  wingate_class(char *class);

/* local_ip is clearly not going to be an unsigned long FIX THIS -db */
unsigned long local_ip(char *ourhostname);

extern struct auth_file_entry userlist[];
extern int user_list_index;

extern struct exception_entry hostlist[];	/* defined in userlist.c */
extern int host_list_index;

#ifdef DEBUGMODE
void exemption_summary();
#endif

#define TYPE_OPER		0x00001	/* user has registered as an oper */
#define TYPE_KLINE		0x00002 /* user has .kline privs */
#define TYPE_SERVERS            0x00008 /* user sees server intro/quits */
#define TYPE_PARTYLINE		0x00010	/* user wants to be on partyline */
#define TYPE_WARN		0x00080	/* user sees clone reports */
#define TYPE_INVS		0x00100	/* user is invisible to STATS p list */
#define TYPE_LOCOPS		0x00400 /* user sees LOCOPS */
#define TYPE_ADMIN		0x00800 /* user is an adminstrator */
#define TYPE_DLINE		0x02000 /* user has .dline privs */
#define TYPE_SPY		0x04000 /* links, motd, info requests */
#define TYPE_VIEW_KLINES	0x20000 /* user see's klines/unklines */
#define TYPE_SUSPENDED		0x40000 /* user is suspended */
#ifdef ENABLE_W_FLAG
#define TYPE_WALLOPS		0x80000 /* user can see OPERWALL */
#endif

int isoper(char *user, char *host);
void init_userlist(void);
void reload_user_list(int sig);

struct config_list config_entries;

/* channel_report flags */
#define CHANNEL_REPORT_CLONES	0x0001
#define CHANNEL_REPORT_VCLONES	0x0002
#define CHANNEL_REPORT_SCLONES  0x0004
#define CHANNEL_REPORT_FLOOD	0x0008
#define CHANNEL_REPORT_LINK	0x0020
#define CHANNEL_REPORT_WINGATE	0x0040
#define CHANNEL_REPORT_SOCKS	0x0080
#define CHANNEL_REPORT_DRONE	0x0100
#define CHANNEL_REPORT_ROUTINE	0x0200
#define CHANNEL_REPORT_BOT	0x0400
#define CHANNEL_REPORT_SPAMBOT	0x0800
#define CHANNEL_REPORT_CFLOOD	0x1000

#endif


