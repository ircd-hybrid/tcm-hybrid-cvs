/*
 *
 *  - added clear_userlist()
 *  - make it actually use MAXUSERS defined in config.h
 *  - added config file for bot nick, channel, server, port etc.
 *  - rudimentary remote tcm linking added
 */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "config.h"
#include "token.h"
#include "tcm.h"
#include "serverif.h"
#include "userlist.h"
#include "logging.h"
#include "stdcmds.h"
#include "wild.h"
#include "abuse.h"

#ifdef DMALLOC
#include "dmalloc.h"
#endif

static char *version="$Id: userlist.c,v 1.4 2000/12/08 23:22:31 bill Exp $";

#ifdef NEXT
char *strdup(char *);
#endif

struct config_list config_entries;
struct auth_file_entry userlist[MAXUSERS];
struct tcm_file_entry tcmlist[MAXTCMS];
struct exception_entry hostlist[MAXHOSTS];
struct exception_entry banlist[MAXBANS];

#if defined(DETECT_WINGATE)||defined(DETECT_SOCKS)
char wingate_class_list[MAXWINGATES][100];
int  wingate_class_list_index;
#endif

int  user_list_index;
int  tcm_list_index;
int  host_list_index;
int  ban_list_index;

#ifdef DETECT_WINGATE
extern struct wingates wingate[];
#endif

#ifdef DETECT_SOCKS
extern struct wingates socks[];
#endif

static void load_a_ban(char *);
static void load_a_user(char *,int);
static void load_a_tcm(char *);
static void load_a_host(char *);
static void load_f_line(char *);
static void load_a_wingate_class(char *class);
static void add_action(char *value, char *action, char *reason,int message);

struct f_entry *flines;

/*
 * load_config_file
 * 
 * inputs	- NONE
 * output	- NONE
 * side effects	- configuration items needed for tcm are loaded
 *	  from CONFIG_FILE
 *	  rudimentary error checking in config file are reported
 *	  and if any found, tcm is terminated...
 */

void load_config_file(char *file_name)
{
  FILE *fp;
  char line[MAX_BUFF];
  char *key;			/* key/value pairs as found in config file */
  char *value;
  char *action;
  char *reason;
  char *message_ascii;
  int  message;
  char *p;
  char *q;
  int error_in_config;		/* flag if error was found in config file */

  error_in_config = NO;

  config_entries.hybrid = NO;
  config_entries.hybrid_version = 0;

  config_entries.tcm_pid_file[0] = '\0';
  config_entries.username_config[0] = '\0';
  config_entries.virtual_host_config[0] = '\0';
  config_entries.oper_nick_config[0] = '\0';
  config_entries.oper_pass_config[0] = '\0';
  config_entries.server_config[0] = '\0';
  config_entries.server_pass[0] = '\0';
  config_entries.ircname_config[0] = '\0';
  config_entries.defchannel[0] = '\0';
  config_entries.dfltnick[0] = '\0';
  config_entries.email_config[0] = '\0';

  config_entries.channel_report = 
    CHANNEL_REPORT_ROUTINE | CHANNEL_REPORT_CLONES;

  strcpy(config_entries.cflood_act, "dline");
  strncpy(config_entries.cflood_reason, REASON_KDRONE,
	  sizeof(config_entries.cflood_reason) - 1);

  strcpy(config_entries.sclone_act, "kline 60");
  strncpy(config_entries.sclone_reason, REASON_AUTO_MULTI_SERVER_CLONES,
	  sizeof(config_entries.sclone_reason) - 1);

  config_entries.vclone_act[0] = '\0';
  config_entries.vclone_reason[0] = '\0';

  strcpy(config_entries.clone_act, "kline 60");
  strncpy(config_entries.clone_reason,REASON_KCLONE,
	  sizeof(config_entries.clone_reason) - 1);

  strcpy(config_entries.flood_act,"kline 60");
  strncpy(config_entries.flood_reason,REASON_KFLOOD,
	  sizeof(config_entries.flood_reason) - 1 );

  strcpy(config_entries.ctcp_act,"kline 60");
  strncpy(config_entries.ctcp_reason,REASON_CTCP,
	  sizeof(config_entries.flood_reason) - 1 );

  strcpy(config_entries.link_act,"kline 60");
  strncpy(config_entries.link_reason,REASON_LINK,
	  sizeof(config_entries.link_reason) - 1 );

  strcpy(config_entries.bot_act,"kline");
  strncpy(config_entries.bot_reason,REASON_KBOT,
	  sizeof(config_entries.bot_reason) - 1 );

  strcpy(config_entries.spoof_act,"kline 60");
  strncpy(config_entries.spoof_reason,"spoofer",
	  sizeof(config_entries.spoof_reason) - 1 );

  config_entries.spambot_act[0] = '\0';
  config_entries.spambot_reason[0] = '\0';

#ifdef DETECT_WINGATE
  strcpy(config_entries.wingate_act,"kline 60");
  strncpy(config_entries.wingate_reason,REASON_WINGATE,
	 sizeof(config_entries.wingate_reason) - 1 );
#endif

#ifdef DETECT_SOCKS
  strcpy(config_entries.socks_act,"kline 60");
  strncpy(config_entries.socks_reason,REASON_SOCKS,
	 sizeof(config_entries.socks_reason) - 1 );
#endif

#ifdef SERVICES_DRONES
  config_entries.drones_act[0] = '\0';
  strncpy(config_entries.drones_reason,REASON_DRONES,
	 sizeof(config_entries.drones_reason) - 1 );
#endif

  strncpy(config_entries.userlist_config,USERLIST_FILE,MAX_CONFIG-1);

  if( !(fp = fopen(file_name,"r")) )
    {
      fprintf(stderr,"GACK! I don't know who I am or anything!!\n");
      fprintf(stderr,"tcm can't find %s file\n",file_name);
      exit(1);
    }

  config_entries.tcm_port = TCM_PORT;

  while(fgets(line, MAX_BUFF-1,fp))
    {
      if(line[0] == '#')
	continue;

      if( !(key = strtok(line,":")) )
	continue;

      if( !(value = strtok((char *)NULL,"\r\n")) )
	continue;

      switch(*key)
	{
	case 'e':case 'E':
	  if(config_entries.debug && outfile)
	    {
	      (void)fprintf(outfile, "email address = [%s]\n", value );
	    }
          strncpy(config_entries.email_config,value,MAX_CONFIG-1);
	break;

	case 'f':case 'F':
	  if(config_entries.debug && outfile)
	    {
	      (void)fprintf(outfile, "tcm.pid file name = [%s]\n",
			    config_entries.tcm_pid_file);
	    }
	  strncpy(config_entries.tcm_pid_file,value,MAX_CONFIG-1);
	  break;

	case 'l':case 'L':
	  if(config_entries.debug && outfile)
	    {
	      fprintf(outfile, "userlist = [%s]\n", value );
	    }
	  strncpy(config_entries.userlist_config,value,MAX_CONFIG-1);
	  break;

	case 'm':case 'M':
	    strncpy(config_entries.statspmsg,
		    value,sizeof(config_entries.statspmsg));
	    break;

	case 'a':case 'A':
	    action = splitc(value, ':');
	    if(!action)
	      {
		/* missing action */
		break;
	      }
	    reason = splitc( action, ':');

	    message = 0;

	    if(reason)
	      {
		message_ascii = splitc( reason, ':');
		if(message_ascii)
		  {
		    if(!strcasecmp(message_ascii,"yes"))
		      {
			message = 1;
		      }
		    else if(!strcasecmp(message_ascii,"no"))
		      {
			message = -1;
		      }
		  }
	      }

	    add_action(value, action, reason, message);
	    break;

	case 'o':case 'O':
	  {
	    char *oper_nick;
	    char *oper_pass;

	    if( !(oper_nick = strtok(value,":\r\n")) )
	      continue;

	    if( !(oper_pass = strtok((char *)NULL,":\r\n")) )
	      continue;

	    strncpy(config_entries.oper_nick_config,oper_nick,MAX_NICK);
	    strncpy(config_entries.oper_pass_config,oper_pass,MAX_CONFIG-1);
	  }
	  break;

	case 'p':case 'P':
	  config_entries.tcm_port = atoi(value);
	  break;

	case 'u':case 'U':
	  if(config_entries.debug && outfile)
	    {
	      fprintf(outfile, "user name = [%s]\n", value );
	    }
	  strncpy(config_entries.username_config,value,MAX_CONFIG-1);
	  break;

	case 'v':case 'V':
	  if(config_entries.debug && outfile)
	    {
	      fprintf(outfile, "virtual host name = [%s]\n", value );
	    }
	  strncpy(config_entries.virtual_host_config,value,MAX_CONFIG-1);
	  break;

#ifdef DETECT_WINGATE
	case 'w': case 'W':
	  load_a_wingate_class(value);
	  break;
#endif

	case 's':case 'S':
	  if(config_entries.debug && outfile)
	    {
	      fprintf(outfile, "server = [%s]\n", value);
	    }
	  strncpy(config_entries.server_config,value,MAX_CONFIG-1);
	  break;

	case 'n':case 'N':
	  if(config_entries.debug && outfile)
	    {
	      fprintf(outfile, "nick for tcm = [%s]\n", value );
	    }
	  strncpy(config_entries.dfltnick,value,MAX_NICK-1);
	  break;

	case 'i':case 'I':
	  if(config_entries.debug && outfile)
	    {
	      fprintf(outfile, "IRCNAME = [%s]\n", value );
	    }
	  strncpy(config_entries.ircname_config,value,MAX_CONFIG-1);
	  break;

	case 'c':case 'C':
	  if(config_entries.debug && outfile)
	    {
	      fprintf(outfile, "Channel = [%s]\n", value);
	    }

	  if((p = strchr(value,':')))
	    {
	      *p = '\0';
	      p++;
	      strncpy(config_entries.defchannel_key,p,MAX_CONFIG-1);
	    }
	  else
	    config_entries.defchannel_key[0] = '\0';

	  strncpy(config_entries.defchannel,value,MAX_CHANNEL-1);
	  break;

	default:
	  break;
	}
    }

  if(!config_entries.clone_act[0])
    {
      /* "warn" is absolutely way below length of clone_act */
      strcpy(config_entries.clone_act, "warn" );
    }
  if(config_entries.username_config[0] == '\0')
    {
      fprintf(stderr,"I need a username (U:) in %s\n",CONFIG_FILE);
      error_in_config = YES;
    }

  if(config_entries.oper_nick_config[0] == '\0')
    {
      fprintf(stderr,"I need an opernick (O:) in %s\n",CONFIG_FILE);
      error_in_config = YES;
    }

  if(config_entries.oper_pass_config[0] == '\0')
    {
      fprintf(stderr,"I need an operpass (O:) in %s\n",CONFIG_FILE);
      error_in_config = YES;
    }

  if(config_entries.server_config[0] == '\0')
    {
      fprintf(stderr,"I need a server (S:) in %s\n",CONFIG_FILE);
      error_in_config = YES;
    }

  strcpy(config_entries.server_name,config_entries.server_config);

  if( (p = strchr(config_entries.server_name,':')) )
    {
      *p = '\0';
      p++;
      if( (q = strchr(p,':')) )
	{
	  *q = '\0';
	  q++;
	  strncpy(config_entries.server_pass,q,MAX_CONFIG);
	}
      strncpy(config_entries.server_port,p,MAX_CONFIG);
    }
  else
    {
      fprintf(stderr,"I need a port in the server line (S:) in %s\n",
	      CONFIG_FILE);
      error_in_config = YES;
    }

  if(config_entries.ircname_config[0] == '\0')
    {
      fprintf(stderr,"I need an ircname (I:) in %s\n",CONFIG_FILE);
      error_in_config = YES;
    }

  if(config_entries.dfltnick[0] == '\0')
    {
      fprintf(stderr,"I need a nick (N:) in %s\n", CONFIG_FILE);
      error_in_config = YES;
    }

  if(error_in_config)
    exit(1);
}

/*
 * load_prefs
 *
 * inputs	- NONE
 * output	- NONE
 * side effects - action table is affected
 */
void load_prefs(void)
{
  FILE *fp;
  char line[MAX_BUFF];
  char *key;
  char *value;
  char *action;
  char *reason;
  char *message_ascii;
  int  message;

  if( !(fp = fopen(PREF_FILE,"r")) )
    {
      return;
    }

  while(fgets(line, MAX_BUFF-1,fp))
    {
      if(line[0] == '#')
	continue;

      if( !(key = strtok(line,":")) )
	continue;
      
      if( !(value = strtok((char *)NULL,"\r\n")) )
	continue;

      switch(*key)
	{
	case 'a':case 'A':
	  action = splitc(value, ':');
	  if(!action)
	    {
	      /* missing action */
	      break;
	    }
	  reason = splitc( action, ':');
	  message = 0;

	  if(reason)
	    {
	      message_ascii = splitc( reason, ':');
	      if(message_ascii)
		{
		  message = atoi(message_ascii);
		}
	    }

	  add_action(value, action, reason, message);
	  break;

	  break;
	default:
	  break;
	}
    }

  (void)fclose(fp);

  config_entries.channel_report |= CHANNEL_REPORT_ROUTINE;
}

/*
 * save_prefs
 *
 * inputs	- NONE
 * output	- NONE
 * side effects - action table is affected
 */
void save_prefs(void)
{
  FILE *fp;

  if( !(fp = fopen(PREF_FILE,"w")) )
    {
      sendtoalldcc(SEND_ALL_USERS, "Couldn't open %s\n", PREF_FILE );
      return;
    }

  if(config_entries.clone_act[0])
    fprintf(fp,"A:clone:%s:%s:%d\n",
	    config_entries.clone_act,config_entries.clone_reason,
	    config_entries.channel_report&CHANNEL_REPORT_CLONES?1:-1);

#ifdef AUTO_DLINE
  if(config_entries.vclone_act[0])
    fprintf(fp,"A:vclone:%s:%s:%d\n",
	    config_entries.vclone_act,config_entries.vclone_reason,
	    config_entries.channel_report&CHANNEL_REPORT_VCLONES?1:-1);
#endif

  if(config_entries.cflood_act[0])
    fprintf(fp,"A:cflood:%s:%s:%d\n",
	    config_entries.cflood_act,config_entries.cflood_reason,
	    config_entries.channel_report&CHANNEL_REPORT_CFLOOD?1:-1);

  if(config_entries.sclone_act[0])
    fprintf(fp,"A:sclone:%s:%s:%d\n",
	    config_entries.sclone_act,config_entries.sclone_reason,
	    config_entries.channel_report&CHANNEL_REPORT_SCLONES?1:-1);

  if(config_entries.flood_act[0])
    fprintf(fp,"A:flood:%s:%s:%d\n",
	    config_entries.flood_act,config_entries.flood_reason,
	    config_entries.channel_report&CHANNEL_REPORT_FLOOD?1:-1);

  if(config_entries.link_act[0])
    fprintf(fp,"A:link:%s:%s:%d\n",
	    config_entries.link_act,config_entries.link_reason,
	    config_entries.channel_report&CHANNEL_REPORT_LINK?1:-1);

  if(config_entries.bot_act[0])
    fprintf(fp,"A:bot:%s:%s:%d\n",
	    config_entries.bot_act,config_entries.bot_reason,
	    config_entries.channel_report&CHANNEL_REPORT_BOT?1:-1);

#ifdef DETECT_WINGATE
  if(config_entries.wingate_act[0])
    fprintf(fp,"A:wingate:%s:%s:%d\n",
	    config_entries.wingate_act,config_entries.wingate_reason,
	    config_entries.channel_report&CHANNEL_REPORT_WINGATE?1:-1);
#endif

#ifdef DETECT_SOCKS
  if(config_entries.socks_act[0])
    fprintf(fp,"A:socks:%s:%s:%d\n",
	    config_entries.socks_act,config_entries.socks_reason,
	    config_entries.channel_report&CHANNEL_REPORT_SOCKS?1:-1);
#endif

#ifdef SERVICES_DRONES
  if(config_entries.drones_act[0])
    fprintf(fp,"A:drones:%s:%s:%d\n",
	    config_entries.drones_act,config_entries.drones_reason,
	    config_entries.channel_report&CHANNEL_REPORT_DRONE?1:-1);
#endif

  if(config_entries.spambot_act[0])
    fprintf(fp,"A:spambot:%s:%s:%d\n",
	    config_entries.spambot_act,config_entries.spambot_reason,
	    config_entries.channel_report&CHANNEL_REPORT_SPAMBOT?1:-1);

  (void)fclose(fp);
}

/*
 * add_action
 *
 * inputs	- pointer to keyword ("clone" "sclone" etc.)
 *		- pointer to action
 * 		- pointer to reason to associate with action
 *		- int flagging message to channel or not
 *		  -1 NO +1 YES 0 don't change
 * output	- none
 * side effects -
 */

static void add_action(char *value, char *action, char *reason, int message)
{

  if (!strcasecmp(value, "clone"))
    {
	strncpy(config_entries.clone_act, action, 
		sizeof(config_entries.clone_act));
      
      if(reason)
	strncpy(config_entries.clone_reason, reason, 
		sizeof(config_entries.clone_reason));

      if(message > 0)
	config_entries.channel_report |= CHANNEL_REPORT_CLONES;
      else if(message <= 0)
	config_entries.channel_report &= ~CHANNEL_REPORT_CLONES;

    }
#ifdef AUTO_DLINE
  else if (!strcasecmp(value, "vclone"))
    {
	strncpy(config_entries.clone_act, action, 
		sizeof(config_entries.vclone_act));
      
      if(reason)
	strncpy(config_entries.clone_reason, reason, 
		sizeof(config_entries.vclone_reason));

      if(message > 0)
	config_entries.channel_report |= CHANNEL_REPORT_VCLONES;
      else if(message <= 0)
	config_entries.channel_report &= ~CHANNEL_REPORT_VCLONES;
    }
#endif
  else if (!strcasecmp(value, "cflood"))
    {
        strncpy(config_entries.cflood_act, action,
		sizeof(config_entries.cflood_act));

	if(reason)
	  strncpy(config_entries.cflood_reason, reason,
		  sizeof(config_entries.cflood_reason));
	if(message > 0)
	  config_entries.channel_report |= CHANNEL_REPORT_CFLOOD;
	else
	  config_entries.channel_report &= ~CHANNEL_REPORT_CFLOOD;
    }
  else if (!strcasecmp(value, "sclone"))
    {
	strncpy(config_entries.sclone_act, action, 
		sizeof(config_entries.sclone_act));
      
      if(reason)
	strncpy(config_entries.sclone_reason, reason, 
		sizeof(config_entries.sclone_reason));

      if(message > 0)
	config_entries.channel_report |= CHANNEL_REPORT_SCLONES;
      else if(message <= 0)
	config_entries.channel_report &= ~CHANNEL_REPORT_SCLONES;
    }
  else if (!strcasecmp(value, "flood"))
    {
	strncpy(config_entries.flood_act, action, 
		sizeof(config_entries.flood_act));
      
      if(reason)
	strncpy(config_entries.flood_reason, reason, 
		sizeof(config_entries.flood_reason));

      if(message > 0)
	config_entries.channel_report |= CHANNEL_REPORT_FLOOD;
      else if(message <= 0)
	config_entries.channel_report &= ~CHANNEL_REPORT_FLOOD;
    }
  else if (!strcasecmp(value, "ctcp"))
    {
	strncpy(config_entries.ctcp_act, action, 
		sizeof(config_entries.ctcp_act));
      
      if(reason)
	strncpy(config_entries.ctcp_reason, reason, 
		sizeof(config_entries.ctcp_reason));

      if(message > 0)
	config_entries.channel_report |= CHANNEL_REPORT_CTCP;
      else if(message <= 0)
	config_entries.channel_report &= ~CHANNEL_REPORT_CTCP;
    }
  else if (!strcasecmp(value, "link"))
    {
	strncpy(config_entries.link_act, action, 
		sizeof(config_entries.link_act));
      
      if(reason)
	strncpy(config_entries.link_reason, reason, 
		sizeof(config_entries.link_reason));

      if(message > 0)
	config_entries.channel_report |= CHANNEL_REPORT_LINK;
      else if(message <= 0)
	config_entries.channel_report &= ~CHANNEL_REPORT_LINK;
    }
  else if (!strcasecmp(value, "bot"))
    {
	strncpy(config_entries.bot_act, action, 
		sizeof(config_entries.bot_act));
      
      if(reason)
	strncpy(config_entries.bot_reason, reason, 
		sizeof(config_entries.bot_reason));

      if(message > 0)
	config_entries.channel_report |= CHANNEL_REPORT_BOT;
      else if(message <= 0)
	config_entries.channel_report &= ~CHANNEL_REPORT_BOT;
    }
  else if (!strcasecmp(value, "spoof"))
    {
	strncpy(config_entries.spoof_act, action, 
		sizeof(config_entries.spoof_act));
      
      if(reason)
	strncpy(config_entries.spoof_reason, reason, 
		sizeof(config_entries.spoof_reason));

      if(message > 0)
	config_entries.channel_report |= CHANNEL_REPORT_SPOOF;
      else if(message <= 0)
	config_entries.channel_report &= ~CHANNEL_REPORT_SPOOF;
    }
  else if (!strcasecmp(value, "spambot"))
    {
	strncpy(config_entries.spambot_act, action, 
		sizeof(config_entries.spambot_act));

      if(reason)
	strncpy(config_entries.spambot_reason, reason, 
		sizeof(config_entries.spambot_reason));

      if(message > 0)
	config_entries.channel_report |= CHANNEL_REPORT_SPAMBOT;
      else if(message <= 0)
	config_entries.channel_report &= ~CHANNEL_REPORT_SPAMBOT;
    }
#ifdef DETECT_WINGATE
  else if (!strcasecmp(value, "wingate"))
    {
	strncpy(config_entries.wingate_act, action, 
		sizeof(config_entries.wingate_act));
      
      if(reason)
	strncpy(config_entries.wingate_reason, reason, 
		sizeof(config_entries.wingate_reason));

      if(message > 0)
	config_entries.channel_report |= CHANNEL_REPORT_WINGATE;
      else if(message <= 0)
	config_entries.channel_report &= ~CHANNEL_REPORT_WINGATE;
    }
#endif
#ifdef DETECT_SOCKS
  else if (!strcasecmp(value, "socks"))
    {
	strncpy(config_entries.socks_act, action,
		sizeof(config_entries.socks_act));
      
      if(reason)
	strncpy(config_entries.socks_reason, reason, 
		sizeof(config_entries.socks_reason));

      if(message > 0)
	config_entries.channel_report |= CHANNEL_REPORT_SOCKS;
      else if(message <= 0)
	config_entries.channel_report &= ~CHANNEL_REPORT_SOCKS;
    }
#endif
#ifdef SERVICES_DRONES
  else if (!strcasecmp(value, "drones"))
    {
	strncpy(config_entries.drones_act, action,
		sizeof(config_entries.drones_act));
      if(reason)
	strncpy(config_entries.drones_reason, reason, 
		sizeof(config_entries.drones_reason));

      if(message > 0)
	config_entries.channel_report |= CHANNEL_REPORT_DRONE;
      else if(message <= 0)
	config_entries.channel_report &= ~CHANNEL_REPORT_DRONE;
    }
#endif
}

/*
 * load_userlist
 * 
 * inputs	- NONE
 * output	- NONE
 * side effects	- first part of oper list is loaded from file
 */

void load_userlist()
{
  FILE *userfile;
  char line[MAX_BUFF];

  if ( !(userfile = fopen(config_entries.userlist_config,"r")) )
    {
      fprintf(stderr,"Cannot read %s\n",config_entries.userlist_config);
      return;
    }

/*
 * 
 * userlist.load looks like now
 * u@h:nick:password:ok o for opers, k for remote kline
 *
 * - or you can use a number 1 for opers, 2 for remote kline -
 * i.e.
 *  u@h:nick:password:3 for opers
 *
 * h:nick:password:okb o for opers, 2 for remote kline, b for bot
 *
 * - 4 is for bot -
 * i.e.
 *  h:nick:password:7   for remote tcm's
 *
 */

  while (fgets(line, MAX_BUFF-1, userfile) )
    {
      char op_char;

      line[strlen(line)-1] = 0;
      if(line[0] == '#')
	continue;
      
      op_char = line[0];

      if(line[1] == ':')
	{
	  switch(op_char)
	    {
	    case 'B':		/* ban this host from tcmconn */
	      load_a_ban(line+2);
	      break;

	    case 'C':
	      load_a_tcm(line+2);
	      break;

	    case 'E':
	      load_a_host(line+2);
	      break;

	    case 'F':
	      load_f_line(line+2);
	      break;

	    case 'N':
	      load_a_user(line+2,1);
	      break;

	    case 'O':
	      load_a_user(line+2,0);
	      break;

	    default:
	      break;
	    }
	}
      
    }
}

/*
 * load_a_ban()
 * inputs	- rest of line past the 'B:' or 'b:'
 * output	- NONE
 * side effects	- banlist is updated
 */

void load_a_ban(char *line)
  {
    char *host;
    char *user;
    char *p;

    if(config_entries.debug && outfile)
      {
	fprintf(outfile, "load_a_ban() line =[%s]\n",line);
      }

    if( ban_list_index == (MAXBANS - 1))
	return;
    
    if( (p = strchr(line,'\n')) )
      *p = '\0';

    if( !(user = strtok(line,"@")) )
      return;
    
    if( !(host = strtok((char *)NULL,"")) )
      return;

    strncpy(banlist[ban_list_index].user, user,
	    sizeof(banlist[ban_list_index].user));

    strncpy(banlist[ban_list_index].host, host,
	     sizeof(banlist[ban_list_index].host));

    ban_list_index++;
    banlist[ban_list_index].user[0] = '\0';
    banlist[ban_list_index].host[0] = '\0';
}

/*
 * load_a_user()
 * inputs	- rest of line past the 'O:' or 'o:'
 *		  link_tcm is 1 if its a linked tcm incoming
 * output	- NONE
 * side effects	- userlist is updated
 */

/*
 * made this into a nice, pretty, less memory managing function
 * more efficient now, and a less chance of mem leaks.
 *	-pro
 */

static void load_a_user(char *line,int link_tcm)
  {
    char *userathost;
    char *user;
    char *host;
    char *usernick;
    char *password;
    char *type;
    char *p;

    if(config_entries.debug && outfile)
      {
	fprintf(outfile, "load_a_user() line =[%s]\n",line);
      }

    if( user_list_index == (MAXUSERS - 1))
	return;

    if ( !(userathost = strtok(line,":")) )
      return;

    user = userathost;
    if( (p = strchr(userathost,'@')) )
      {
	*p = '\0';
	p++;
	host = p;
      }
    else
      {
	user = "*";
	host = userathost;
      }

    if( (p = strchr(host,' ')) )
      *p = '\0';

    userlist[user_list_index].usernick[0] = 0;
    userlist[user_list_index].password[0] = 0;

    strncpy(userlist[user_list_index].user, user, 
	    sizeof(userlist[user_list_index].user));

    strncpy(userlist[user_list_index].host, host, 
	    sizeof(userlist[user_list_index].host));

    usernick = strtok((char *)NULL,":");
    
    if(usernick)
      strncpy(userlist[user_list_index].usernick, usernick, 
	      sizeof(userlist[user_list_index].usernick));

    password = strtok((char *)NULL,":");

    if(password)
      strncpy(userlist[user_list_index].password, password, 
	      sizeof(userlist[user_list_index].password));

    type = strtok((char *)NULL,":");

    if(type)
      {
	unsigned long type_int;
	char *p;
	p = type;

	type_int = TYPE_ECHO;

	while(*p)
	  {
	    switch(*p)
	      {
	      case 's':
		type_int |= TYPE_STAT;
		break;
	      case 'w':
		type_int |= TYPE_WARN;
		break;
	      case 'k':
		type_int |= TYPE_KLINE;
		break;
	      case 'i':
		type_int |= TYPE_INVS;
		break;
	      case 'o':
		type_int |= TYPE_LOCOPS;
		break;
	      case 'M':
		type_int |= TYPE_ADMIN;
		break;
	      case 'I':
		type_int |= TYPE_INVM;
		break;
	      case 'D':
		type_int |= TYPE_DLINE;
		break;
	      case 'l':
		type_int |= TYPE_LINK;
		break;
	      case 'm':
		type_int |= TYPE_MOTD;
		break;
	      case 'p':
		type_int |= TYPE_PARTYLINE;
		break;
	      case 'O':
		type_int |= TYPE_OPER;
		break;
	      case 'G':
		type_int |= (TYPE_GLINE|TYPE_CAN_REMOTE|TYPE_REGISTERED);
		break;
	      case 'K':
		type_int |= TYPE_REGISTERED;
		break;
	      case 'R':
		type_int |= (TYPE_CAN_REMOTE|TYPE_REGISTERED);
		break;
	      case 'B':
	      case 'T':
		type_int |= TYPE_TCM;
		break;

	      default:
		break;
	      }
	    p++;
	  }

	if(link_tcm)
	  type_int |= TYPE_TCM;

	userlist[user_list_index].type = type_int;
      }

    user_list_index++;

    userlist[user_list_index].user[0] = 0;
    userlist[user_list_index].host[0] = 0;
    userlist[user_list_index].usernick[0] = 0;
    userlist[user_list_index].password[0] = 0;
    userlist[user_list_index].type = 0;
}

#ifdef DETECT_WINGATE

/*
 * load_a_wingate_class()
 * inputs	- rest of line past the 'W:' or 'w:'
 * output	- NONE
 * side effects	- userlist is updated
 */

static void load_a_wingate_class(char *class)
  {
    if( wingate_class_list_index == (MAXWINGATES - 1))
	return;

    snprintf(wingate_class_list[wingate_class_list_index++], sizeof(wingate_class_list[wingate_class_list_index]), "%s", class);
    snprintf(wingate_class_list[wingate_class_list_index], sizeof(wingate_class_list[wingate_class_list]), "unknown");
  }
#endif

/*
 * load_a_tcm
 *
 * inputs	- NONE
 * output	- NONE
 * side effects	- tcm list
 */

static void load_a_tcm(char *line)
{
/*
 *
 *  userlist.cf looks like now
 *  C:host:theirnick:password:port   for remote tcm's
 */
  char *host;
  char *theirnick;
  char *password;
  char *port_string;
  int  port;

  if( tcm_list_index == (MAXTCMS - 1))
    return;

  if( !(host = strtok(line,":")) )
    return;

  tcmlist[tcm_list_index].theirnick[0] = 0;
  tcmlist[tcm_list_index].password[0] = 0;

  strncpy(tcmlist[tcm_list_index].host, host,
	  sizeof(tcmlist[tcm_list_index].host));

  theirnick = strtok((char *)NULL,":");

  if(theirnick)
    strncpy(tcmlist[tcm_list_index].theirnick, theirnick,
	    sizeof(tcmlist[tcm_list_index].theirnick));

  password = strtok((char *)NULL,":");

  if(password)
    strncpy(tcmlist[tcm_list_index].password, password,
	    sizeof(tcmlist[tcm_list_index].password));

  port_string = strtok((char *)NULL,":");
  port = TCM_PORT;

  if(port_string)
    {
      if(isdigit(*port_string))
	{
	  port = atoi(port_string);
	}
    }

  tcmlist[tcm_list_index].port = port;

  tcm_list_index++;

  tcmlist[tcm_list_index].host[0] = '\0';
  tcmlist[tcm_list_index].theirnick[0] = '\0';
  tcmlist[tcm_list_index].password[0] = '\0';
  tcmlist[tcm_list_index].port = 0;
}

int str2type(char *vltn) {
  if (!strcasecmp(vltn, "clone")) return R_CLONES;
  else if (!strcasecmp(vltn, "sclone")) return R_SCLONES;
  else if (!strcasecmp(vltn, "flood")) return R_FLOOD;
  else if (!strcasecmp(vltn, "ctcp")) return R_CTCP;
  else if (!strcasecmp(vltn, "link")) return R_LINK;
  else if (!strcasecmp(vltn, "bot")) return R_BOTS;
  else if (!strcasecmp(vltn, "wingate")) return R_WINGATE;
  else if (!strcasecmp(vltn, "socks")) return R_SOCKS;
  else if (!strcasecmp(vltn, "spoof")) return R_SPOOF;
  else if (!strcasecmp(vltn, "spambot")) return R_SPAMBOT;
  else return 0;
}

/*
 * NEW!  F lines
 *
 *	Quick description:	F lines are like E lines, except they are
 *				violation specific, say you want to make a
 *				host exempt from cloning, but not spamming,
 *				you would use an F line.
 *
 *	  -pro
 */

static void load_f_line(char *line) {
  char *vltn, *p, *uhost;
  struct f_entry *temp, *f = flines, *old = NULL;
  int type=0;
  placed;

  if (!(p = strchr(line, ':'))) return;
  if (!(temp = (struct f_entry *)malloc(sizeof(struct f_entry)))) return;
  temp->next = NULL;
  vltn = line;
  uhost = p+1;
  *p = '\0';
  snprintf(temp->uhost, sizeof(temp->uhost), "%s", uhost);
  if (!strcmp(vltn, "*")) temp->type = -1;
  else {
    while (occurance(vltn, ' ') || occurance(vltn, ',')) {
      if (!(p = strchr(vltn, ' '))) p = strchr(vltn, ',');
      if (p == NULL) break;
      uhost = p+1;
      *p = '\0';
      type |= str2type(vltn);
      vltn = uhost;
    }
    type |= str2type(vltn);
    temp->type = type;
  }
  while (f != NULL) {
    old = f;
    f = f->next;
  }
  if (old != NULL) old->next = temp;
  else flines = temp;
}


/* Added Allowable hostlist for autokline. Monitor checks allowed hosts
 * before adding kline, if it matches, it just returns dianoras
 * suggested kline.  Phisher dkemp@frontiernet.net
 *
 *
 * okhost() is now called on nick floods etc. to mark whether a user
 * should be reported or not.. hence its not just for AUTO_KLINE now
 *
 */

static void load_a_host(char *line)
{
  char *host;
  char *user;
  char *p;
  placed;

  if(host_list_index == MAXHOSTS)
    return;

  if( (p = strchr(line,'\n')) )
    *p = '\0';

  if( (p = strchr(line,'@')) )
    {
      user = line;
      *p = '\0';
      p++;
      host = p;
    }
  else
    {
      host = line;
      user = "*";
    }

  if( (p = strchr(host, ' ')) )
    *p = '\0';

  strncpy(hostlist[host_list_index].host, host, 
	  sizeof(hostlist[host_list_index].host));

  strncpy(hostlist[host_list_index].user, user,
	  sizeof(hostlist[host_list_index].user));

  host_list_index++;
  hostlist[host_list_index].user[0] = '\0';
  hostlist[host_list_index].host[0] = '\0';
}

/*
 * clear_userlist
 *
 * input	- NONE
 * output	- NONE
 * side effects - user list is cleared out prepatory to a userlist reload
 *
 */

void clear_userlist()
{
  int cnt;
  user_list_index = 0;
  tcm_list_index = 0;
  host_list_index = 0;

#ifdef DETECT_WINGATE
  wingate_class_list_index = 0;
#endif

  for(cnt = 0; cnt < MAXUSERS; cnt++)
    {
      userlist[cnt].user[0]='\0';
      userlist[cnt].host[0] = '\0';
      userlist[cnt].usernick[0] = '\0';
      userlist[cnt].password[0] = '\0';
      userlist[cnt].type = 0;
    }

  for(cnt = 0; cnt < MAXTCMS; cnt++)
    {
      tcmlist[cnt].host[0] = '\0';
      tcmlist[cnt].theirnick[0] = '\0';
      tcmlist[cnt].password[0] = '\0';
      tcmlist[cnt].port = '\0';
    }

  for(cnt = 0; cnt < MAXHOSTS; cnt++)
    {
      hostlist[cnt].user[0] = '0';
      hostlist[cnt].host[0] = '\0';
    }

  for(cnt = 0; cnt < MAXBANS; cnt++)
    {
      banlist[cnt].user[0] = '\0';
      banlist[cnt].host[0] = '\0';
    }

#ifdef DETECT_WINGATE
  for(cnt = 0; cnt < MAXWINGATES; cnt++)
    {
      if(wingate[cnt].socket != INVALID)
	{
	  (void)close(wingate[cnt].socket);
	}
      wingate[cnt].socket = INVALID;
      wingate[cnt].user[0] = '\0';
      wingate[cnt].host[0] = '\0';
      wingate[cnt].state = 0;
      wingate[cnt].nick[0] = '\0';
    }
#endif

#ifdef DETECT_SOCKS
  for(cnt = 0; cnt < MAXSOCKS; cnt++)
    {
      if(socks[cnt].socket != INVALID)
	{
	  (void)close(socks[cnt].socket);
	}
      socks[cnt].socket = INVALID;
      socks[cnt].user[0] = '\0';
      socks[cnt].host[0] = '\0';
      socks[cnt].state = 0;
      socks[cnt].nick[0] = '\0';
    }
#endif
}

/*
 * init_userlist
 *
 * input	- NONE
 * output	- NONE
 * side effects -
 *	  user list is cleared 
 *
 */

void init_userlist()
{
  int cnt;
  user_list_index = 0;
  tcm_list_index = 0;
  host_list_index = 0;
  ban_list_index = 0;

#ifdef DETECT_WINGATE
  wingate_class_list_index = 0;
#endif

  for(cnt = 0; cnt < MAXUSERS; cnt++)
    {
      userlist[cnt].user[0] = 0;
      userlist[cnt].host[0] = 0;
      userlist[cnt].usernick[0] = 0;
      userlist[cnt].password[0] = 0;
      userlist[cnt].type = 0;
    }

    for(cnt = 0; cnt < MAXTCMS; cnt++)
      {
	tcmlist[cnt].host[0] = 0;
	tcmlist[cnt].theirnick[0] = 0;
	tcmlist[cnt].password[0] = 0;
	tcmlist[cnt].port = 0;
      }

    for(cnt = 0; cnt < MAXHOSTS; cnt++)
      {
	hostlist[cnt].user[0] = 0;
	hostlist[cnt].host[0] = 0;
      }

    for(cnt = 0; cnt < MAXBANS; cnt++)
      {
	banlist[cnt].user[0] = 0;
	banlist[cnt].host[0] = 0;
      }

#ifdef DETECT_WINGATE
    for(cnt = 0; cnt < MAXWINGATES; cnt++)
      {
	wingate[cnt].socket = INVALID;
      }
#endif
}

/*
 * isoper()
 *
 * inputs	- user name
 * 		- host name
 * output	- TYPE_OPER if oper, 0 if not
 * side effects	- NONE
 */

int isoper(char *user,char *host)
{
  int i;

  for(i=0;userlist[i].user[0];i++)
    {
      if((userlist[i].type & TYPE_TCM) == 0)
	if ((!wldcmp(userlist[i].user,user)) &&
	    (!wldcmp(userlist[i].host,host)))
	  return(TYPE_OPER);
    }
  return(0);
}

/*
 * isbanned()
 * 
 * inputs	- user name
 * 		- host name
 * output	- 1 if banned, 0 if not
 * side effects	- NONE
 */

int isbanned(char *user,char *host)
{
  int i;

  for(i=0;banlist[i].user[0];i++)
    {
      if ((!wldcmp(banlist[i].user,user)) &&
	  (!wldcmp(banlist[i].host,host)))
	return(1);
    }
  return(0);
}

/*
 * ban_manipulate()
 *
 * inputs	- socket to return result on
 *		- add or delete flag
 *		- user@host to add or delete
 * output	- NONE
 * side effects
 */

void ban_manipulate(int socket,char flag,char *userhost)
{
  char *user;
  char *host;
  int  i;
  placed;

  if( !(user = strtok(userhost,"@")) )
    return;

  if( !(host = strtok((char *)NULL,"")))
    return;

  if(flag == '+')
    {
      if(isbanned(user,host))
	{
	  prnt(socket,"%s@%s is already banned.\n",user,host);
	  return;
	}
      for(i=0; i < MAXBANS; i++)
	{
	  if(!banlist[i].host[0])
	    break;
	  if(!banlist[i].user[0])
	    break;

	  if(banlist[i].user[0] == '\0')
	    {
	      banlist[i].user[0] = 0;
	      if(banlist[i].host) banlist[i].host[0] = 0;
	      break;
	    }
	}

      if(i < MAXBANS)
	{
	  strncpy(banlist[i].user, user, sizeof(banlist[i].user));
	  strncpy(banlist[i].host, host, sizeof(banlist[i].host));
	}

      prnt(socket,"%s@%s now banned.\n", user, host);
    }
  else
    {
      for(i=0; i < MAXBANS; i++)
	{
	  if(!banlist[i].host[0]) break;
	  if(!banlist[i].user[0]) break;
	  if((!wldcmp(banlist[i].user,user)) &&
	     (!wldcmp(banlist[i].host,host)))
	    {
	      banlist[i].user[0] = 0;
	      banlist[i].host[0] = 0;
	      prnt(socket, "%s@%s is removed.\n", user, host);
	    }
	}
    }
}

/*
 * flags_by_userhost()
 *
 * inputs	- user
 *		- host
 * outputs	- type of user by hostmask provided
 * side effects	- NONE
 */

int flags_by_userhost(char *user, char *host)
{
  int i;

  for(i = 0; userlist[i].user; i++)
    {
      if (userlist[i].type & TYPE_TCM)
	continue;

      if ((!wldcmp(userlist[i].user,user)) &&
	  (!wldcmp(userlist[i].host,host)))
	return( userlist[i].type);
    }
  return 0;
}

/*
 * islegal_pass()
 *
 * inputs	- user
 * 		- host
 *		- password
 *		- int connect id
 * output	- YES if legal NO if not
 * side effects	- NONE
 */

int islegal_pass(int connect_id,char *password)
{
  int i;

  for(i=0;userlist[i].user;i++)
    {
      if(userlist[i].type & TYPE_TCM)
	continue;

      if ((!wldcmp(userlist[i].user,connections[connect_id].user)) &&
	  (!wldcmp(userlist[i].host,connections[connect_id].host)))
	{
	  if(userlist[i].password)
	    {
#ifdef USE_CRYPT
	      if(!strcmp((char*)crypt(password,userlist[i].password),
			 userlist[i].password))
		{
		  strncpy(connections[connect_id].registered_nick,
			  userlist[i].usernick,
			  MAX_NICK);
		  connections[connect_id].type = userlist[i].type;
		  return userlist[i].type;
		}
	      else
		return 0;
#else
	      if(!strcmp(userlist[i].password,password))
		{
		  strncpy(connections[connect_id].registered_nick,
			  userlist[i].usernick,
			  MAX_NICK);
		  connections[connect_id].type = userlist[i].type;
		  return(userlist[i].type);
		}
	      else
		return(0);
#endif
	    }
	}
    }
  return(0);
}

/*
 * islinkedbot()
 *
 * inputs	- connection number, botname, password
 * output		- privs if linkedbot 0 if not
 * side effects	- NONE
 */

int islinkedbot(int connnum, char *botname, char *password)
{
  int i = 0;
  int j;

  while ((userlist[i].user[0]) && (i < (MAXDCCCONNS -1)) )
    {
      if (
	  (userlist[i].type & TYPE_TCM) && /* if its a tcm */
	  (
	   (!wldcmp(userlist[i].user,connections[connnum].user)) &&
	   (!wldcmp(userlist[i].host,connections[connnum].host))
	  )
	 )
	{
	  if(!userlist[i].usernick[0]) continue;
	  if(!userlist[i].password[0]) continue;

	  if( (strcasecmp(botname,userlist[i].usernick) == 0 ) &&
	     (strcmp(password,userlist[i].password) == 0 ) )
	    {
	      /* 
		 Close any other duplicate connections using same botnick
	       */

	      for(j = 0; j < MAXDCCCONNS+1; j++)
		{
		  if(connections[j].user)
		     {
		       if(!strcasecmp(connections[j].nick,botname))
			 {
			   closeconn(j);
			 }
		     }
		}

	      strcpy(connections[connnum].nick,botname);
	      return(userlist[i].type);
	    }
	}
      i++;
    }
  return(0);
}

int f_lined(char *user, char *host, int type) {
  struct f_entry *temp;
  char uhost[MAX_NICK+2+MAX_HOST];
  snprintf(uhost, sizeof(uhost), "%s@%s", user, host);

  temp = flines;
  while (temp != NULL) {
    if (wldcmp(temp->uhost, uhost) && (temp->type & type || temp->type == -1)) return 1;
    temp = temp->next;
  }
  return 0;
}

/* Checks for ok hosts to block auto-kline - Phisher */
/*
 * okhost()
 * 
 * inputs	- user
 * 		- host
 * output	- if this user@host is in the exception list or not
 * side effects	- none
 */

int okhost(char *user,char *host)
{
  int i;

  for(i=0;hostlist[i].user[0];i++)
    {
      if ((!wldcmp(hostlist[i].user,user)) &&
	  (!wldcmp(hostlist[i].host,host)))
      return(YES);
    }
  return(NO);
}

#if defined(DETECT_WINGATE) || defined(DETECT_SOCKS)
/*
 * wingate_class
 * 
 * inputs	- class
 * output	- if this class is a wingate class to check
 * side effects	- none
 */

int wingate_class(char *class)
{
  int i;

  for(i=0; (strlen(wingate_class_list[i]) > 0) ;i++)
    {
      if(!strcasecmp(wingate_class_list[i], class))
	{
	  return YES;
	}
    }
  return(NO);
}
#endif

/*
 * type_show()
 * 
 * inputs	- unsigned int type
 * output	- pointer to a static char * showing the char types
 * side effects	-
 */

char *type_show(unsigned long type)
{
  static char type_string[SMALL_BUFF];
  char *p;

  bzero(&type_string, sizeof(type_string));
  p = type_string;
  if(type&TYPE_OPER)*p++ = 'O';
  if(type&TYPE_REGISTERED)*p++ = 'K';
  if(type&TYPE_GLINE)*p++ = 'G';
  if(type&TYPE_SUSPENDED)*p++ = 'S';
  if(type&TYPE_TCM)*p++ = 'T';
  if(type&TYPE_CAN_REMOTE)*p++ = 'R';
  if(type&TYPE_ADMIN)*p++ = 'M';
  if(type&TYPE_INVM)*p++ = 'I';
  if(type&TYPE_DLINE)*p++ = 'D';
  if(type&TYPE_PARTYLINE)*p++ = 'p';
  if(type&TYPE_STAT)*p++ = 's';
  if(type&TYPE_WARN)*p++ = 'w';
  if(type&TYPE_ECHO)*p++ = 'e';
  if(type&TYPE_INVS)*p++ = 'i';
  if(type&TYPE_LOCOPS)*p++ = 'o';
  if(type&TYPE_KLINE)*p++ = 'k';
  if(type&TYPE_LINK)*p++ = 'l';
  if(type&TYPE_MOTD)*p++ = 'm';
  *p = '\0';
  return(type_string);
}
