#ifndef __USERLIST_H
#define __USERLIST_H

/* $Id: userlist.h,v 1.99 2004/06/15 22:36:31 bill Exp $ */

#include "setup.h"
#include "tools.h"

#define MAXFROMHOST	50
#define CLONEDETECTINC	15
#define NICK_CHANGE_TABLE_SIZE	100
#define JUPE_JOIN_TABLE_SIZE	100

#define UMODE_SAVE_TIME 30*60

struct f_entry {
  int type;
  char uhost[MAX_USERHOST+1];
  struct f_entry *next;
};

struct failrec
{
  char username[MAX_USER+1];
  char host[MAX_HOST+1];
  int failcount;
  struct failrec *next;
};
struct failrec *failures;


struct config_list {
  int  hybrid;
  int  hybrid_version;
  char tcm_pid_file[MAX_CONFIG+1];
  char username_config[MAX_CONFIG+1];
  char virtual_host_config[MAX_CONFIG+1];
  char oper_nick_config[MAX_CONFIG+1];
  char oper_pass_config[MAX_CONFIG+1];
#ifndef NO_SSL
  char oper_keyfile[MAX_CONFIG+1];	/* CHALLENGE support.  e? */
  char oper_keyphrase[MAX_CONFIG+1];
#endif
  char server_name[MAX_CONFIG+1];
  char server_pass[MAX_CONFIG+1];
  int  server_port;
  char ircname_config[MAX_CONFIG+1];
  char email_config[MAX_CONFIG+1];
  char userlist_config[MAX_CONFIG+1];
  char dynamic_config[MAX_CONFIG+1];
  int  debug;
  char channel[MAX_CHANNEL+1];		/* Channel tcm will use. */
  char channel_key[MAX_CONFIG+1];		/* key for Channel tcm will use. */
  char dfltnick[MAX_NICK+1];		/* Nickname tcm will use */
  char testline_umask[MAX_USERHOST+1];
  struct connection *testline_cnctn;

  char statspmsg[MAX_CONFIG+1];

  int nofork;
  char *conffile;
};

/*
 * authentication structure set up in userlist.c
 * used for .register command
 */

struct oper_entry
{
  char username[MAX_NICK+1];
  char host[MAX_HOST+1];
  char usernick[MAX_NICK+1];
  char password[MAX_CONFIG+1];
  int type;
};

struct exempt_entry
{
  char username[MAX_NICK+1];
  char host[MAX_HOST+1];
  unsigned int type;
};

struct oper_entry *find_user_in_userlist(const char *);

void add_oper(char *, char *, char *, char *, int);
void show_stats_p(const char *nick);
void set_umode(struct oper_entry *, int, const char *);
void on_stats_o(int, char *argv[]);
void add_exempt(char *, char *, int);
void load_userlist(void);
void reload_userlist(void);
void init_userlist_handlers(void);
void load_config_file(char *);
void clear_userlist(void);
void save_umodes(const char *);
int  ok_host(char *,char *,int);
char *type_show(unsigned long type);
int  is_an_oper(char *user, char *host);

/* local_ip is clearly not going to be an unsigned long FIX THIS -db */
unsigned long local_ip(char *ourhostname);

struct dlink_list;
dlink_list exempt_list;
dlink_list user_list;

#ifdef DEBUGMODE
void exempt_summary();
#endif

/* privs first */
#define FLAGS_OPER		0x000001 /* user has registered as an oper */
#define FLAGS_KLINE		0x000002 /* user has .kline privs */
#define FLAGS_INVS		0x000004 /* user is invisible to STATS p list */
#define FLAGS_PARTYLINE		0x000008 /* user wants to be on partyline */
#define FLAGS_DLINE		0x000010 /* user has .dline privs */
#define FLAGS_SUSPENDED		0x000020 /* user is suspended */
#define FLAGS_XLINE		0x000040 /* user has .xline privs */
#define FLAGS_JUPE		0x000080 /* user has .jupe privs */

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
#define FLAGS_OPERWALL		0x020000 /* user can see OPERWALL */

#define FLAGS_VALID		0x200000 /* valid userfile */
#define FLAGS_CHANGED		0x400000 /* changed and needs saving */

struct config_list config_entries;

#endif


