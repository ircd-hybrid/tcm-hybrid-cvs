#ifndef __USERLIST_H
#define __USERLIST_H

/* $Id: userlist.h,v 1.30 2002/05/18 02:21:08 wcampbel Exp $ */

/* maximum IP length in adduserhost() removeuserhost() */
#define MAX_IP 20
#define MAX_CONFIG	80
#define HASHTABLESIZE 3001
#define MAXFROMHOST    50
#define CLONEDETECTINC 15
#define NICK_CHANGE_TABLE_SIZE 100


// Defines for an actions hoststrip field

// Mask for the host-only method
#define HOSTSTRIP_HOST               0x000F
// Use the full host
#define HOSTSTRIP_HOST_AS_IS         0x0001 
// Replace first field of host (or last field of ip) with *
#define HOSTSTRIP_HOST_BLOCK         0x0002 

// Mask for the "if idented" method
#define HOSTSTRIP_IDENT              0x00F0
// Use ident as is
#define HOSTSTRIP_IDENT_AS_IS        0x0010 
// Use ident as is but prefix with *
#define HOSTSTRIP_IDENT_PREFIXED     0x0020
// Replace ident with *
#define HOSTSTRIP_IDENT_ALL          0x0030

// Mask for the "if not idented" method
#define HOSTSTRIP_NOIDENT            0x0F00
// Use *~*
#define HOSTSTRIP_NOIDENT_UNIDENTED  0x0100 
// Use *username
#define HOSTSTRIP_NOIDENT_PREFIXED   0x0200
// Use *
#define HOSTSTRIP_NOIDENT_ALL        0x0300

// Methods of handling an event
#define METHOD_DCC_WARN              0x0001
#define METHOD_IRC_WARN              0x0002
#define METHOD_TKLINE                0x0004
#define METHOD_KLINE                 0x0008
#define METHOD_DLINE                 0x0010


// Default HOSTSTRIPs
#define HS_DEFAULT  (HOSTSTRIP_HOST_AS_IS | HOSTSTRIP_IDENT_PREFIXED | HOSTSTRIP_NOIDENT_ALL)

#define HS_CFLOOD   HS_DEFAULT
#define HS_VCLONE   (HOSTSTRIP_HOST_BLOCK | HOSTSTRIP_IDENT_PREFIXED | HOSTSTRIP_NOIDENT_ALL)
#define HS_FLOOD    (HOSTSTRIP_HOST_AS_IS | HOSTSTRIP_IDENT_ALL | HOSTSTRIP_NOIDENT_ALL)
#define HS_LINK     HS_DEFAULT
#define HS_BOT      HS_DEFAULT
#define HS_SPAMBOT  HS_DEFAULT
#define HS_CLONE    HS_DEFAULT
#define HS_RCLONE   HS_DEFAULT
#define HS_SCLONE   HS_DEFAULT
#define HS_DRONE    HS_DEFAULT
#define HS_WINGATE  (HOSTSTRIP_HOST_AS_IS | HOSTSTRIP_IDENT_ALL | HOSTSTRIP_NOIDENT_ALL)
#define HS_SOCKS    (HOSTSTRIP_HOST_AS_IS | HOSTSTRIP_IDENT_ALL | HOSTSTRIP_NOIDENT_ALL)


struct f_entry {
  int type;
  char uhost[MAX_NICK+2+MAX_HOST];
  struct f_entry *next;
};

struct sortarray
{
  struct userentry *domainrec;
  int count;
};

struct a_entry {
  char name[MAX_CONFIG];
  char reason[MAX_CONFIG];
  int method;
  int hoststrip, klinetime;
};

struct a_entry actions[MAX_ACTIONS+1];

struct nick_change_entry
{
  char user_host[MAX_USER+MAX_HOST];
  char last_nick[MAX_NICK];
  int  nick_change_count;
  time_t first_nick_change;
  time_t last_nick_change;
  int noticed;
};
struct nick_change_entry nick_changes[NICK_CHANGE_TABLE_SIZE];

struct failrec
{
  char user[MAX_NICK+1];
  char host[MAX_HOST];
  int botcount;
  int failcount;
  struct failrec *next;
};
struct failrec *failures;

struct userentry {
  char nick[MAX_NICK];
  char user[MAX_NICK+1];
  char host[MAX_HOST];
  char ip_host[MAX_IP];         /* host ip as string */
#ifdef VIRTUAL
  char ip_class_c[MAX_IP];      /* /24 of host ip as string */
#endif
  char domain[MAX_DOMAIN];
  char link_count;
  char isoper;
  char class[100];		/* -1 if unknown */
  time_t connecttime;
  time_t reporttime;
};

struct hashrec {
  struct userentry *info;
  struct hashrec *collision;
};

struct config_list {
  int  hybrid;
  int  hybrid_version;
  int  opers_only;
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
  unsigned long type;
};

struct tcm_file_entry
{
  char host[MAX_HOST];
  char theirnick[MAX_NICK];
  char password[MAX_CONFIG];
  int  port;
};

struct exception_entry
{
  char user[MAX_NICK+1];
  char host[MAX_HOST];
  int type;
};

void load_userlist(void);
void load_config_file(char *);
void clear_userlist(void);
int  wingate_class(char *class);
void ban_manipulate(int sock,char flag,char *userlist);
void save_prefs(void);
int  okhost(char *,char *,int);
int  str2type(char *);
char *type_show(unsigned long type);

extern struct auth_file_entry userlist[];
extern int user_list_index;

extern struct exception_entry banlist[];
extern int ban_list_index;

extern struct exception_entry hostlist[];	/* defined in userlist.c */
extern int host_list_index;

#ifdef DEBUGMODE
void exemption_summary();
#endif

extern struct tcm_file_entry tcmlist[];
extern int tcm_list_index;

#define TYPE_OPER		0x00001	/* user has .bots privs etc. */
#define TYPE_REGISTERED		0x00002	/* user has .kline privs etc. */
#define TYPE_GLINE		0x00004	/* user has .gline privs */ 
#define TYPE_PARTYLINE		0x00010	/* user wants to be on partyline */
#define TYPE_STAT		0x00040	/* user sees STAT requests */
#define TYPE_WARN		0x00080	/* user sees clone reports */
#define TYPE_INVS		0x00100	/* user is invisible to STATS p list */
#define TYPE_PENDING		0x00200
#define TYPE_LOCOPS		0x00400 /* user sees LOCOPS */
#define TYPE_ADMIN		0x00800 /* user is an adminstrator */
#define TYPE_INVM		0x01000 /* user is invisible to STATS p list */
#define TYPE_DLINE		0x02000 /* user has .dline privs */
#define TYPE_LINK		0x04000 /* user sees link requests */
#define TYPE_MOTD		0x08000 /* user sees MOTD requests */
#define TYPE_ECHO		0x10000 /* user is echo'ed */
#define TYPE_KLINE		0x20000 /* user see's klines/unklines */
#define TYPE_SUSPENDED		0x40000 /* user is suspended */
#ifdef ENABLE_W_FLAG
#define TYPE_OPERWALL		0x80000 /* user can see OPERWALL */
#endif

int isoper(char *user, char *host);
int islinkedbot(int connnum, char *botname, char *password);
void init_userlist(void);
void reload_user_list(int sig);

struct hashrec *usertable[HASHTABLESIZE];
struct hashrec *hosttable[HASHTABLESIZE];
struct hashrec *domaintable[HASHTABLESIZE];
struct hashrec *iptable[HASHTABLESIZE];
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


