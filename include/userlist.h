#ifndef __USERLIST_H
#define __USERLIST_H

#define MAX_CONFIG	80

struct f_entry {
  int type;
  char uhost[MAX_NICK+2+MAX_HOST];
  struct f_entry *next;
};

struct config_list {
  int  hybrid;
  int  hybrid_version;
  int  autopilot;
  int  opers_only;
  char tcm_pid_file[MAX_CONFIG];
  char username_config[MAX_CONFIG];
  char virtual_host_config[MAX_CONFIG];
  char oper_nick_config[MAX_CONFIG];
  char oper_pass_config[MAX_CONFIG];
  char server_config[MAX_CONFIG];
  char server_name[MAX_CONFIG];
  char rserver_name[MAX_CONFIG];
  char server_port[MAX_CONFIG];
  char server_pass[MAX_CONFIG];
  char port_config[MAX_CONFIG];
  char ircname_config[MAX_CONFIG];
  char email_config[MAX_CONFIG];
  char userlist_config[MAX_CONFIG];
  int  tcm_port;
  int  debug;
  char defchannel[MAX_CHANNEL];		/* Channel tcm will use. */
  char defchannel_key[MAX_CONFIG];	/* key for Channel tcm will use. */
  char dfltnick[MAX_NICK];		/* Nickname tcm will use */
  char clone_act[MAX_CONFIG];
  char clone_reason[MAX_CONFIG];
  char vclone_act[MAX_CONFIG];
  char vclone_reason[MAX_CONFIG];
  char sclone_act[MAX_CONFIG];		/* services clone action */
  char sclone_reason[MAX_CONFIG];	
  char cflood_act[MAX_CONFIG];		/* connect drone action */
  char cflood_reason[MAX_CONFIG];
  char flood_act[MAX_CONFIG];
  char flood_reason[MAX_CONFIG];
  char ctcp_act[MAX_CONFIG];		/* ctcp flood action */
  char ctcp_reason[MAX_CONFIG];
  char link_act[MAX_CONFIG];
  char link_reason[MAX_CONFIG];
  int  channel_report;			/* bit map of flags */
  char bot_act[MAX_CONFIG];
  char bot_reason[MAX_CONFIG];
  char spoof_act[MAX_CONFIG];
  char spoof_reason[MAX_CONFIG];
  char spambot_act[MAX_CONFIG];
  char spambot_reason[MAX_CONFIG];

#ifdef DETECT_WINGATE
  char wingate_act[MAX_CONFIG];
  char wingate_reason[MAX_CONFIG];
#endif

#ifdef DETECT_SOCKS
  char socks_act[MAX_CONFIG];
  char socks_reason[MAX_CONFIG];
#endif

#ifdef SERVICES_DRONES
  char drones_act[MAX_CONFIG];
  char drones_reason[MAX_CONFIG];
#endif

  char statspmsg[MAX_CONFIG];
}CONFIG_LIST;

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
};

void load_userlist(void);
void load_config_file(char *);
void clear_userlist(void);
int  wingate_class(int class);
void ban_manipulate(int sock,char flag,char *userlist);
void load_prefs(void);
void save_prefs(void);
int  islegal_pass(int connect_id,char *password);
int  okhost(char *,char *);
int  str2type(char *);
char *type_show(unsigned long type);

extern struct config_list config_entries;

extern struct auth_file_entry userlist[];
extern int user_list_index;

extern struct exception_entry banlist[];
extern int ban_list_index;

extern struct exception_entry hostlist[];	/* defined in userlist.c */
extern int host_list_index;

extern struct tcm_file_entry tcmlist[];
extern int tcm_list_index;

#define TYPE_OPER		0x00001	/* user has .bots privs etc. */
#define TYPE_REGISTERED		0x00002	/* user has .kline privs etc. */
#define TYPE_GLINE		0x00004	/* user has .gline privs */ 
#define TYPE_CAN_REMOTE		0x00008	/* user has remote .kline privs etc. */
#define TYPE_PARTYLINE		0x00010	/* user wants to be on partyline */
#define TYPE_TCM		0x00020
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

int isoper(char *user, char *host);
void init_userlist(void);
int islinkedbot(int connnum, char *botname, char *password);

/* channel_report flags */
#define CHANNEL_REPORT_CLONES	0x0001
#define CHANNEL_REPORT_VCLONES	0x0002
#define CHANNEL_REPORT_SCLONES  0x0004
#define CHANNEL_REPORT_FLOOD	0x0008
#define CHANNEL_REPORT_CTCP	0x0010
#define CHANNEL_REPORT_LINK	0x0020
#define CHANNEL_REPORT_WINGATE	0x0040
#define CHANNEL_REPORT_SOCKS	0x0080
#define CHANNEL_REPORT_DRONE	0x0100
#define CHANNEL_REPORT_ROUTINE	0x0200
#define CHANNEL_REPORT_SPOOF	0x0400
#define CHANNEL_REPORT_BOT	0x0800
#define CHANNEL_REPORT_SPAMBOT	0x1000
#define CHANNEL_REPORT_CFLOOD	0x2000

#endif


