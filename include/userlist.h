#ifndef __USERLIST_H
#define __USERLIST_H

/* $Id: userlist.h,v 1.71 2002/06/21 14:59:06 leeh Exp $ */

/* maximum IP length in adduserhost() removeuserhost() */
#define MAX_IP 20
#define MAX_CONFIG	80
#define MAXFROMHOST    50
#define CLONEDETECTINC 15
#define NICK_CHANGE_TABLE_SIZE 100

#define UMODE_SAVE_TIME 30*60

struct f_entry {
  int type;
  char uhost[MAX_USERHOST];
  struct f_entry *next;
};

struct failrec
{
  char user[MAX_NICK];
  char host[MAX_HOST];
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
  char server_port[MAX_CONFIG];
  char server_pass[MAX_CONFIG];
  char port_config[MAX_CONFIG];
  char ircname_config[MAX_CONFIG];
  char email_config[MAX_CONFIG];
  char userlist_config[MAX_CONFIG];
  int  debug;
  char channel[MAX_CHANNEL];		/* Channel tcm will use. */
  char channel_key[MAX_CONFIG];		/* key for Channel tcm will use. */
  char dfltnick[MAX_NICK];		/* Nickname tcm will use */

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
  char user[MAX_NICK];
  char host[MAX_HOST];
  char usernick[MAX_NICK];
  char password[MAX_CONFIG];
  int type;
  int changed;
};

struct exception_entry
{
  char user[MAX_NICK];
  char host[MAX_HOST];
  unsigned int type;
};

int find_user_in_userlist(const char *);
int get_umodes_from_prefs(int);
void list_connections(int sock);
void show_stats_p(const char *nick);

void save_umodes(void *);
void set_umode(int, int, const char *);
void add_an_oper(int, char *argv[]);

int has_umode(int, int);
int get_umode(int);

void add_exemption(char *, char *, int);

void load_userlist(void);
void init_userlist_handlers(void);
void load_config_file(char *);
void clear_userlist(void);
void save_prefs(void);
int  ok_host(char *,char *,int);
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

/* privs first */
#define FLAGS_OPER		0x000001 /* user has registered as an oper */
#define FLAGS_KLINE		0x000002 /* user has .kline privs */
#define FLAGS_INVS		0x000004 /* user is invisible to STATS p list */
#define FLAGS_PARTYLINE		0x000008 /* user wants to be on partyline */
#define FLAGS_DLINE		0x000010 /* user has .dline privs */
#define FLAGS_SUSPENDED		0x000020 /* user is suspended */

/* send second */
#define FLAGS_ALL		0x000100 /* notices destined for all users */
#define FLAGS_SERVERS           0x000200 /* user sees server intro/quits */
#define FLAGS_PRIVMSG		0x000400 /* user wants to see privmsgs */
#define FLAGS_NOTICE		0x000800 /* user wants to see notices */
#define FLAGS_WARN		0x001000 /* user sees clone reports */
#define FLAGS_LOCOPS		0x002000 /* user sees LOCOPS */
#define FLAGS_ADMIN		0x004000 /* user is an adminstrator */
#define FLAGS_SPY		0x008000 /* links, motd, info requests */
#define FLAGS_VIEW_KLINES	0x010000 /* user see's klines/unklines */
#define FLAGS_WALLOPS		0x020000 /* user can see OPERWALL */

#define FLAGS_VALID		0x200000 /* valid userfile */


int  is_an_oper(char *user, char *host);
void reload_user_list(int sig);

struct config_list config_entries;

#endif


