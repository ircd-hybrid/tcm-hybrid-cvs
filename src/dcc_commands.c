/* $Id: dcc_commands.c,v 1.36 2002/03/06 05:16:21 bill Exp $ */

#include "setup.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <signal.h>
#include <sys/errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <stdarg.h>
#include <time.h>

#ifdef HAVE_SYS_STREAM_H
# include <sys/stream.h>
#endif

#ifdef HAVE_SYS_SOCKETVAR_H
# include <sys/socketvar.h>
#endif

#ifdef AIX
# include <sys/select.h>
#endif

#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <fcntl.h>
#include "config.h"
#include "tcm.h"
#include "token.h"
#include "bothunt.h"
#include "userlist.h"
#include "serverif.h"
#include "logging.h"
#include "commands.h"
#include "stdcmds.h"
#include "modules.h"
#include "wild.h"

#ifdef DMALLOC
#include "dmalloc.h"
#endif

char *_version="20012009";

static int is_kline_time(char *p);
static void set_actions(int sock, char *key, char *act, int duration, char *reason);
static void save_umodes(char *registered_nick, unsigned long type);
static void load_umodes(int connect_id);
static unsigned long find_user_umodes(char *nick);
static void set_umode(int connnum, char *flags, char *registered_nick);
static void show_user_umodes(int sock, char *registered_nick);
static void not_authorized(int sock);
static void register_oper(int connnum, char *password, char *who_did_command);
static void list_opers(int sock);
static void list_connections(int sock);
static void list_exemptions(int sock);
static void handle_disconnect(int sock,char *param2,char *who_did_command);
static void handle_save(int sock,char *nick);
static void report_multi(int sock, int nclones);
static void report_multi_host(int sock, int nclones);
static void report_multi_user(int sock, int nclones);
static void report_multi_virtuals(int sock, int nclones);
static int  islegal_pass(int connect_id,char *password);
static void print_help(int sock,char *text);
static void kill_list_users(int sock, char *userhost, char *reason);
static void list_users(int sock,char *userhost);

void _modinit();

extern struct connection connections[];
extern struct s_testline testlines;

void m_uptime(int connnum, int argc, char *argv[])
{
  report_uptime(connections[connnum].socket);
}

void m_mem(int connnum, int argc, char *argv[])
{
  report_mem(connections[connnum].socket);
}

void m_clones(int connnum, int argc, char *argv[])
{
  report_clones(connections[connnum].socket);
}

void m_nflood(int connnum, int argc, char *argv[])
{
  report_nick_flooders(connections[connnum].socket);
}

void m_rehash(int connnum, int argc, char *argv[])
{
  sendtoalldcc(SEND_ALL_USERS, "*** rehash requested by %s", 
               connections[connnum].registered_nick[0] ?
               connections[connnum].registered_nick :
               connections[connnum].nick);

  if (config_entries.hybrid && (config_entries.hybrid_version >= 6))
    toserv("STATS I\nSTATS Y\n");
  else
    toserv("STATS E\nSTATS F\nSTATS Y\n");

  initopers();
}

void m_trace(int connnum, int argc, char *argv[])
{
  sendtoalldcc(SEND_OPERS_ONLY, "Trace requested by %s",
               connections[connnum].registered_nick[0] ?
               connections[connnum].registered_nick :
               connections[connnum].nick);

  inithash();
  toserv("STATS Y\n");
}

void m_failures(int connnum, int argc, char *argv[])
{
  if (argc < 2)
    report_failures(connections[connnum].socket, 7);
  else if (atoi(argv[1]) < 1)
    prnt(connections[connnum].socket, "Usage: .%s [min failures]\n", argv[0]);
  else
    report_failures(connections[connnum].socket, atoi(argv[1]));
}

void m_domains(int connnum, int argc, char *argv[])
{
  if (argc < 2)
    report_domains(connections[connnum].socket, 5);
  else if (atoi(argv[1]) < 1)
    prnt(connections[connnum].socket, "Usage: .%s [min users]\n", argv[0]);
  else
    report_domains(connections[connnum].socket, atoi(argv[1]));
}

void m_bots(int connnum, int argc, char *argv[])
{
  if (argc >= 2)
    report_multi(connections[connnum].socket, atoi(argv[1]));
  else
    report_multi(connections[connnum].socket, 3);
}

void m_vmulti(int connnum, int argc, char *argv[])
{
  if (argc >= 2)
    report_multi_virtuals(connections[connnum].socket, atoi(argv[1]));
  else
    report_multi_virtuals(connections[connnum].socket, 3);
}

void m_nfind(int connnum, int argc, char *argv[])
{
  if (argc != 2)
    prnt(connections[connnum].socket, "Usage: .%s <wildcarded nick>\n",
         argv[0]);
  else
    list_nicks(connections[connnum].socket, argv[1]);
} 

void m_list(int connnum, int argc, char *argv[])
{
  if (argc < 2)
    prnt(connections[connnum].socket, "Usage: .%s <wildcarded userhost>\n",
         argv[0]);
  else
    list_users(connections[connnum].socket, argv[1]);
}

/*
** dccproc()
**   Handles processing of dcc chat commands
*/
void 
dccproc(int connnum, int argc, char *argv[])
{
  char buff[MAX_BUFF];
  char dccbuff[MAX_BUFF];
  char who_did_command[2*MAX_NICK];
  int len;
  int i;
  int opers_only = SEND_ALL_USERS; 	/* Is it an oper only message ? */
  int ignore_bot = NO;
  char *command, *buffer, *p;
  int kline_time;
  struct common_function *temp;
#ifndef NO_D_LINE_SUPPORT
  char *pattern;  /* u@h or nick */
#endif

  p = buff;
  for (i = 0; i < argc; i++)
  {
    len = sprintf(p, "%s ", argv[i]);
    p += len;
  }
  /* blow away last ' ' */
  *--p = '\0';

  buffer=buff;

  who_did_command[0] = '\0';

  (void)snprintf(who_did_command,sizeof(who_did_command) - 1, "%s@%s",
	         connections[connnum].nick,config_entries.dfltnick);

  if(*buffer != '.')
  {	
    if((buffer[0] == 'o' || buffer[0] == 'O') && buffer[1] == ':')
    {
      opers_only = SEND_OPERS_ONLY;
      (void)snprintf(dccbuff,sizeof(dccbuff) - 1,"o:<%s@%s> %s",
		     connections[connnum].nick,config_entries.dfltnick,
		     buffer+2);
    }
    else
    {
      (void)snprintf(dccbuff,sizeof(dccbuff) - 1,"<%s@%s> %s",
		     connections[connnum].nick,
		     config_entries.dfltnick,
		     buffer);
    }

    if(!ignore_bot)
    {
      if(connections[connnum].type & TYPE_PARTYLINE )
      {
	sendtoalldcc(opers_only, "%s", dccbuff); /* Thanks Garfr, Talen */
      }
      else
      {
	if(opers_only == SEND_OPERS_ONLY)
	  sendtoalldcc(opers_only, "%s", dccbuff);
	else
	  prnt(connections[connnum].socket,
	       "You are not +p, not sending to chat line\n");
      }
    }
    return;
  }

  buffer++;	/* skip the '.' */

  kline_time = 0;
  if (argv[1])
    kline_time = is_kline_time(argv[1]);

  command = argv[0]+1;
  switch(get_token(command))
  {
  case K_VLIST:
    if (connections[connnum].type & TYPE_OPER)
    {
      if (argc<2)
	prnt(connections[connnum].socket, "Usage: .vlist <ip block>\n");
      else
	list_virtual_users(connections[connnum].socket,argv[1]);
    }
    else
      not_authorized(connections[connnum].socket);
    break;

  case K_CLASS:
    if (connections[connnum].type & TYPE_OPER)
    {
      if (argc > 1)
	list_class(connections[connnum].socket,argv[1],NO);
      else
	prnt(connections[connnum].socket, "Usage: .class <class name>\n");
    }
    else
      not_authorized(connections[connnum].socket);
    break;

  case K_CLASST:
    if (connections[connnum].type & TYPE_OPER)
    {
      if (argc > 1)
	list_class(connections[connnum].socket,argv[1],YES);
      else
	prnt(connections[connnum].socket, "Usage: .classt <class name>\n");
    }
    else
      not_authorized(connections[connnum].socket);
    break;


  case K_KILLLIST:	/* - Phisher */
    if (connections[connnum].type & TYPE_REGISTERED)
    {
      if (argc <= 1)
	prnt(connections[connnum].socket,
	     "Usage: %s <wildcarded userhost>\n", argv[0]);
      else
      {
	sendtoalldcc(SEND_OPERS_ONLY,
		     "killlist %s by %s\n", argv[1], who_did_command);
	kill_list_users(connections[connnum].socket, argv[1], 
			"Too many connections, read MOTD");
      }
    }
    else
      prnt(connections[connnum].socket,"You aren't registered\n");
    break;

  case K_KLINE:
    if( connections[connnum].type & TYPE_REGISTERED )
    {
      if (argc < 3)
      {
	prnt(connections[connnum].socket,
	     "Usage: .kline [time] <[nick]|[user@host]> [reason]\n");
	return;
      }
      p = buff+strlen(argv[0]);
      if (*p == ':') ++p;
      if (atoi(argv[1]))
      {
        kline_time = atoi(argv[1]);
        do_a_kline("kline",kline_time,argv[2],p,who_did_command);
      }
      else
        do_a_kline("kline",0,argv[1],p,who_did_command);
    }
    else
      prnt(connections[connnum].socket,"You aren't registered\n");
    break;

    /* Toast */
  case K_KCLONE:
    if( connections[connnum].type & TYPE_REGISTERED )
    {
      if (argc < 2)
      {
	prnt(connections[connnum].socket,
	     "Usage: .kclone [time] <[nick]|[user@host]>\n");
	return;
      }
      if ((kline_time=atoi(argv[1])))
        suggest_action(-get_action_type("clone"), argv[2], NULL, NULL, 
                       kline_time, NO);
      else
        suggest_action(-get_action_type("clone"), argv[1], NULL, NULL, 0, NO);
    }
    else
      prnt(connections[connnum].socket,"You aren't registered\n");
    break;

    /* Toast */
  case K_KFLOOD:
    if( connections[connnum].type & TYPE_REGISTERED )
    {
      if (argc < 2)
      {
	prnt(connections[connnum].socket,
	     "Usage: .kflood [nick]|[user@host]\n");
	return;
      }
      if ((kline_time=atoi(argv[1])))
        suggest_action(-get_action_type("flood"), argv[2], NULL, NULL,
                       kline_time, NO);
      else
        suggest_action(-get_action_type("flood"), argv[1], NULL, NULL, 0, NO);
    }
    else
      prnt(connections[connnum].socket,"You aren't registered\n");
    break;

  case K_KPERM:
    if( connections[connnum].type & TYPE_REGISTERED )
    {
      if (argc < 2)
      {
	prnt(connections[connnum].socket,
	     "Usage: .kperm [nick]|[user@host]\n");
	return;
      }
      do_a_kline("kperm",0,argv[1],REASON_KPERM,who_did_command);
    }
    else
      prnt(connections[connnum].socket,"You aren't registered\n");
    break;

  case K_KLINK:
    if (connections[connnum].type & TYPE_REGISTERED)
    {
      if (argc < 2)
      {
	prnt(connections[connnum].socket,
	     "Usage: .klink [nick]|[user@host]\n");
	return;
      }
      if ((kline_time=atoi(argv[1])))
        suggest_action(-get_action_type("link"), argv[2], NULL, NULL, 
                       kline_time, NO);
      else
        suggest_action(-get_action_type("link"), argv[1], NULL, NULL, NO, NO);
    }
    else
      prnt(connections[connnum].socket,"You aren't registered\n");
    break;

  case K_KDRONE:
    if( connections[connnum].type & TYPE_REGISTERED )
    {
      if (argc < 2)
      {
	prnt(connections[connnum].socket, 
	     "Usage: .kdrone [nick]|[user@host]\n");
	return;
      }
      if ((kline_time=atoi(argv[1])))
        suggest_action(-get_action_type("drone"), argv[2], NULL, NULL, 
                       kline_time, NO);
      else
        suggest_action(-get_action_type("drone"), argv[1], NULL, NULL, NO, NO);
    }
    else
      prnt(connections[connnum].socket,"You aren't registered\n");
    break;

  case K_KBOT:
    if( connections[connnum].type & TYPE_REGISTERED )
    {
      if (argc < 2)
      {
	prnt(connections[connnum].socket, "Usage: .kbot [time] <[nick]|[user@host]>\n");
	return;
      }
      if ((kline_time=atoi(argv[1])))
        suggest_action(-get_action_type("bot"), argv[2], NULL, NULL, 
                       kline_time, NO);
      else
        suggest_action(-get_action_type("bot"), argv[1], NULL, NULL, NO, NO);
    }
    else
      prnt(connections[connnum].socket,"You aren't registered\n");
    break;

  case K_KILL:
  {
    char *reason;
#ifdef NO_D_LINE_SUPPORT
    char *pattern;  /* u@h or nick */
#endif
	
    if( connections[connnum].type & TYPE_REGISTERED )
    {
      if(argc >= 2)
      {
	pattern = argv[1];
	reason = argv[2];

	if(pattern && reason)
	  {
	    log_kline("KILL", pattern, 0, who_did_command, reason);
	    
	    sendtoalldcc(SEND_OPERS_ONLY,	
			 "kill %s :by oper %s@%s %s",
			 pattern,
			 connections[connnum].nick,
			 config_entries.dfltnick,
			 reason);

#ifdef HIDE_OPER_IN_KLINES
	    toserv("KILL %s :%s\n", pattern, reason);
#else
	    toserv("KILL %s :requested by %s reason- %s\n",
		   pattern, who_did_command,
		   reason);
#endif
	  }
	else
	  prnt(connections[connnum].socket,
	       "Usage: .kill [nick]|[user@host] reason\n");
      }
    }
    else
      prnt(connections[connnum].socket,"You aren't registered\n");
  }
  break;

  case K_KSPAM:

    if( connections[connnum].type & TYPE_REGISTERED )
    {
      if (argc < 2)
      {
	prnt(connections[connnum].socket, 
	     "Usage: .kspam [time] <[nick]|[user@host]>\n");
	return;
      }
      if ((kline_time=atoi(argv[1])))
        suggest_action(-get_action_type("spam"), argv[2], NULL, NULL, 
                       kline_time, NO);
      else
        suggest_action(-get_action_type("spam"), argv[1], NULL, NULL, NO, NO);
    }
    else
      prnt(connections[connnum].socket,"You aren't registered\n");
    break;

  case K_HMULTI:
    if (connections[connnum].type & TYPE_OPER)
    {
      int j;
      if (argc >= 2)
      {
	j=atoi(argv[1]);
	if (j<3)
	{
	  prnt(connections[connnum].socket, 
	       "Using a threshold less than 3 is not recommended, changed to 3\n");
	  j=3;
	}
      }
      else
	j=3;
      report_multi_host(connections[connnum].socket,j);
    }
    else
      not_authorized(connections[connnum].socket);
    break;

  case K_UMULTI:
    if (connections[connnum].type & TYPE_OPER)
    {
      int j;
      if (argc >= 2)
	{
	  j=atoi(argv[1]);
	  if (j<3)
	  {
	    prnt(connections[connnum].socket,
		 "Using a threshold less than 3 is not recommended, changed to 3\n");
	    j=3;
	  }
	}
      else
	j=3;
      report_multi_user(connections[connnum].socket,j);
    }
    else
      not_authorized(connections[connnum].socket);
    break;


  case K_REGISTER:
    if (connections[connnum].type & TYPE_OPER && argc == 2)
      register_oper(connnum, argv[1], who_did_command);
    else if (argc != 2)
      prnt(connections[connnum].socket, "Usage: .register <password>\n");
    else
      not_authorized(connections[connnum].socket);
    break;

  case K_OPERS:
    list_opers(connections[connnum].socket);
    break;

  case K_TESTLINE:
    if (!(connections[connnum].type & TYPE_OPER))
    {
      prnt(connections[connnum].socket, "You are not registered\n");
      return;
    }
    if (argc < 2)
    {
      prnt(connections[connnum].socket, "Usage: %s <mask>\n", argv[0]);
      return;
    }
    if (strcasecmp(argv[1], testlines.umask) == 0)
    {
      prnt(connections[connnum].socket, "Already pending %s\n", argv[1]);
      return;
    }
    snprintf(testlines.umask, sizeof(testlines.umask), "%s", argv[1]);
    testlines.index = connnum;
    toserv("TESTLINE %s\n", argv[1]);
    break;

  case K_ACTION:
    if (connections[connnum].type & TYPE_OPER )
    {
      switch (argc)
      {
	/* .action */
      case 1:
	set_actions(connections[connnum].socket, NULL, NULL, 0, NULL);
	break;
	/* .action clone */
	/* .action *c* */
      case 2:
	set_actions(connections[connnum].socket, argv[1], NULL, 0, NULL);
	break;
	/* .action clone :Cloning */
	/* .action clone kline */
      case 3:
	if (argv[2][0] == ':')
	{
	  p = &argv[2][1];
	  set_actions(connections[connnum].socket, argv[1], NULL, 0, p);
	  break;
	}
	set_actions(connections[connnum].socket, argv[1], argv[2], 0, NULL);
	break;
      default:
	if (argc < 4) break;
	/* .action clone :Cloning is prohibited*/
	if (argv[2][0] == ':')
	{
	  p=&argv[2][1];

	  len = snprintf(dccbuff, sizeof(dccbuff), "%s ", p);
	  p = dccbuff + len;

	  for (i = 3; i < argc; i++)
	  {
	    len = sprintf(p, "%s ", argv[i]);
	    p += len;
	  }
	  /* blow away last ' ' */
	  *--p = '\0';

	  set_actions(connections[connnum].socket, argv[1], NULL, 0, dccbuff);
	  break;
	}
	/* .action clone kline :Cloning */
	if (argv[3][0] == ':')
	{
	  p=&argv[3][1];
	  snprintf(dccbuff, sizeof(dccbuff), "%s ", p);
	  for (i=4;i<argc;++i)
	  {
	    strncat((char *)&dccbuff, argv[i], sizeof(dccbuff)-strlen(dccbuff));
	    strncat((char *)&dccbuff, " ", sizeof(dccbuff)-strlen(dccbuff));
	  }
	  if (dccbuff[strlen(dccbuff)-1] == ' ') dccbuff[strlen(dccbuff)-1] = '\0';
	  set_actions(connections[connnum].socket, argv[1], argv[2], 0, dccbuff);
	  break;
	}
	/* .action clone kline 1440 */
	/* .action clone kline 1440 :Cloning is prohibited */
	/* .action clone kline Clones */
	/* .action clone kline Cloning is prohibited */
	if (!(kline_time = atoi(argv[3])))
	{
	  if (argv[3][0] == ':')
	    p = &argv[3][1];
	  else
	    p = &argv[3][0];
	  snprintf(dccbuff, sizeof(dccbuff), "%s ", p);
	  for (i=4;i<argc;++i)
	  {
	    strncat((char *)&dccbuff, argv[i], sizeof(dccbuff)-strlen(dccbuff));
	    strncat((char *)&dccbuff, " ", sizeof(dccbuff)-strlen(dccbuff));
	  }
	  if (dccbuff[strlen(dccbuff)-1] == ' ') dccbuff[strlen(dccbuff)-1] = '\0';
	  
	  set_actions(connections[connnum].socket, argv[1], argv[2], 0, argv[3]);
	  break;
	}
	if (argc == 4)
	{
	  set_actions(connections[connnum].socket, argv[1], argv[2], kline_time, NULL);
	  break;
	}
	if (argv[4][0] == ':')
	  p = &argv[4][1];
	else
	  p = &argv[4][0];

	len = snprintf(dccbuff, sizeof(dccbuff), "%s ", p);
	p = dccbuff + len;

	for (i = 5; i < argc; i++)
	  {
	    len = sprintf(p, "%s ", argv[i]);
	    p += len;
	  }
	/* blow away last ' ' */
	*--p = '\0';

	set_actions(connections[connnum].socket,
		    argv[1], argv[2], kline_time, dccbuff);
	break;
      }
    }
    else
      not_authorized(connections[connnum].socket);
    break;

  case K_SET:
  {
    if(argc < 2)
    {
      if (connections[connnum].set_modes & SET_PRIVMSG)
	prnt(connections[connnum].socket, "MESSAGES\n");
      else
	prnt(connections[connnum].socket, "NOMESSAGES\n");
      
      if (connections[connnum].set_modes & SET_NOTICES)
	prnt(connections[connnum].socket, "NOTICES\n");
      else
	prnt(connections[connnum].socket, "NONOTICES\n");
      return;
    }

    if ((strcasecmp(argv[1],"MESSAGES")) == 0)
    {
      connections[connnum].set_modes |= SET_PRIVMSG;
      prnt(connections[connnum].socket, "You will see privmsgs sent to tcm\n");
    }
    else if ((strcasecmp(argv[1],"NOMESSAGES")) == 0)
    {
      connections[connnum].set_modes &= ~SET_PRIVMSG;
      prnt(connections[connnum].socket, "You will not see privmsgs sent to tcm\n");
    }
    else if ((strcasecmp(argv[1],"NOTICES")) == 0)
    {
      connections[connnum].set_modes |= SET_NOTICES;
      prnt(connections[connnum].socket, "You will see selected server notices\n");
    }
    else if ((strcasecmp(argv[1],"NONOTICES")) == 0)
    {
      connections[connnum].set_modes &= ~SET_NOTICES;
      prnt(connections[connnum].socket, "You will not see server notices\n");
    }
    else
    {
      prnt(connections[connnum].socket, "Usage: .set [MESSAGES|NOMESSAGES]\n");
      prnt(connections[connnum].socket, "Usage: .set [NOTICES|NONOTICES]\n");
    }
  }
  break;
  
  case K_EXEMPTIONS:
    list_exemptions(connections[connnum].socket);
    break;

#ifndef OPERS_ONLY
    case K_BAN:
    {
      if(connections[connnum].type & TYPE_OPER)
      {
	int j;

	if(argc >= 2)
	{
	  if(argv[1][0] == '+')
	    ban_manipulate(connections[connnum].socket,'+',argv[1]+1);
	  else
	    ban_manipulate(connections[connnum].socket,'-',argv[1]+1);
	}
	else
	{
	  prnt(connections[connnum].socket,"current bans\n");
	  for (j=0;j<MAXBANS;j++)
	  {
	    if (!banlist[j].host[0]) break;
	    if (!banlist[j].user[0]) break;
	    if (banlist[j].host[0])
	      prnt(connections[connnum].socket,
		   "%s@%s\n", banlist[j].user, banlist[j].host);
	  }
	}
      }
      else
	not_authorized(connections[connnum].socket);
    }
    break;
#endif
     
  case K_UMODE:

    if (!(connections[connnum].type & TYPE_REGISTERED))
    {
      prnt(connections[connnum].socket, "You aren't registered\n");
      return;
    }

    if (argc < 2)
    {
      prnt(connections[connnum].socket, "Your current flags are: %s\n",
	   type_show(connections[connnum].type));
      break;
    }
    if (argc >= 3)
    {
      if (!(connections[connnum].type & TYPE_ADMIN))
      {
	prnt(connections[connnum].socket, "You aren't an admin\n");
	return;
      }
      if ((argv[2][0] == '+') || (argv[2][0] == '-'))
	set_umode(connnum,argv[2],argv[1]);
      else
	prnt(connections[connnum].socket, ".umode [user flags] | [user] | [flags]\n");
    }
    else
    {
      if ((argv[1][0] == '+') || (argv[1][0] == '-'))
	set_umode(connnum, argv[1], NULL);
      else
	{
	  if (!(connections[connnum].type & TYPE_ADMIN))
	    {
	      prnt(connections[connnum].socket, "You aren't an admin\n");
	      return;
	    }
	  show_user_umodes(connections[connnum].socket,argv[1]);
	}
    }
    break;

  case K_CONNECTIONS:
    list_connections(connections[connnum].socket);
    break;

  case K_DISCONNECT:
    if (connections[connnum].type & TYPE_REGISTERED)
      handle_disconnect(connections[connnum].socket,argv[1],
			who_did_command);
    else
      prnt(connections[connnum].socket,"You aren't registered\n");
    break;

  case K_HELP:
    print_help(connections[connnum].socket, argv[1]);
    break;

  case K_MOTD:
    print_motd(connections[connnum].socket);
    break;

  case K_SAVE:
    if(connections[connnum].type & TYPE_ADMIN)
      handle_save(connections[connnum].socket,connections[connnum].nick);
    else
      prnt(connections[connnum].socket,
	   "You don't have admin priv. to save %s file\n", 
	   CONFIG_FILE);
    break;

  case K_CLOSE:
    prnt(connections[connnum].socket,"Closing connection\n");
    for (temp=dcc_signoff;temp;temp=temp->next)
      temp->function(connnum, 0, NULL);
    break;

/* Added by ParaGod */

  case K_OP:
    if (connections[connnum].type & TYPE_REGISTERED)
    {
      if (argc != 2)
	prnt(connections[connnum].socket,"Usage: op [nick]\n");
      else
	op(config_entries.defchannel,argv[1]); 
    }
    else
      prnt(connections[connnum].socket,"You aren't registered\n");
    break;

  case K_CYCLE:
    if (connections[connnum].type & TYPE_REGISTERED)
    {
      leave(config_entries.defchannel);
      sendtoalldcc(SEND_OPERS_ONLY, "I'm cycling.  Be right back.\n");
      sleep(1);

      /* probably on a cycle, we'd want the tcm to set
       * the key as well...
       */

      toserv("JOIN %s %s\nMODE %s +ntk %s\n", config_entries.defchannel, 
	     config_entries.defchannel_key, config_entries.defchannel, 
	     config_entries.defchannel_key);
    }
    else
      prnt(connections[connnum].socket,"You aren't registered\n");
    break;

  case K_DIE:
    if (connections[connnum].type & TYPE_REGISTERED)
    {
      sendtoalldcc(SEND_ALL_USERS, "I've been ordered to quit irc, goodbye.");
      toserv("QUIT :Dead by request!\n");
      log("DIED by oper %s", who_did_command);
      exit(1);
    }
    else
      not_authorized(connections[connnum].socket);
    break;
    /* End of stuff added by ParaGod */

  case K_RESTART:
    if (connections[connnum].type & TYPE_REGISTERED)
    {
      sendtoalldcc(SEND_ALL_USERS, "I've been ordered to restart.");
      toserv("QUIT :Restart by request!\n");
      log("RESTART by oper %s", who_did_command);
      sleep(1);
      execv(SPATH, NULL);
    }
    else
      not_authorized(connections[connnum].socket);
    break;

  case K_INFO:
    prnt(connections[connnum].socket,
	 "real server name [%s]\n", config_entries.rserver_name);

    if(config_entries.hybrid)
      prnt(connections[connnum].socket,"Hybrid server version %d\n", 
	   config_entries.hybrid_version );
    else
      prnt(connections[connnum].socket,"Not hybrid server\n" );

    break;

  case K_LOCOPS:
    if (!(connections[connnum].type & TYPE_OPER))
      not_authorized(connections[connnum].socket);
    else
    {
      if(argc >= 2)
      {
	p = dccbuff;
	for (i = 1; i < argc; i++)
	  {
	    len = sprintf(p, "%s ", argv[i]);
	    p += len;
	  }
	/* blow away last ' ' */
	*--p = '\0';

	if (dccbuff[0] == ':')
	  toserv("LOCOPS :(%s) %s\n", connections[connnum].nick, dccbuff+1);
	else
	  toserv("LOCOPS :(%s) %s\n", connections[connnum].nick, dccbuff);
      }
      else
	prnt(connections[connnum].socket, "Really, it would help if you said something\n");
    }
    break;

  case K_UNKLINE:
    if (!connections[connnum].type & TYPE_REGISTERED)
    {
      prnt(connections[connnum].socket,"You aren't registered\n");
      return;
    }
    if (argc < 2)
    {
      prnt(connections[connnum].socket, "Usage: .unkline [user@host]\n");
      return;
    }

    log("UNKLINE %s attempted by oper %s", argv[1], who_did_command);

    sendtoalldcc(SEND_OPERS_ONLY,
		 "UNKLINE %s attempted by oper %s", argv[1],who_did_command);
    toserv("UNKLINE %s\n",argv[1]);
    break;

  case K_VBOTS:
    if (!(connections[connnum].type & TYPE_OPER))
    {
      not_authorized(connections[connnum].socket);
      return;
    }
    if (argc >= 2) report_vbots(connections[connnum].socket, atoi(argv[1]));
    else report_vbots(connections[connnum].socket, 3);
    break;

#ifndef NO_D_LINE_SUPPORT
  case K_DLINE:
    if (!connections[connnum].type & TYPE_REGISTERED)
    {
      prnt(connections[connnum].socket,"You aren't registered\n");
      return;
    }
    if (argc >= 3)
    {
      pattern = argv[1];

      p = dccbuff;
      for (i = 2; i < argc; i++)
      {
	len = sprintf(p, "%s ", argv[i]);
	p += len;
      }
      /* blow away last ' ' */
      *--p = '\0';

      if (dccbuff[0] == ':')
	log_kline("DLINE", pattern, 0, who_did_command, dccbuff+1);
      else
	log_kline("DLINE", pattern, 0, who_did_command, dccbuff);

      sendtoalldcc(SEND_OPERS_ONLY, "dline %s : by oper %s %s", pattern, who_did_command,
		   dccbuff);
      
#ifdef HIDE_OPER_IN_KLINES
      toserv("DLINE %s :%s\n", pattern, dccbuff);
#else
      toserv("DLINE %s :%s [%s]\n", pattern, dccbuff, who_did_command);
#endif
    }
    else
      prnt(connections[connnum].socket, "Usage: .dline [nick]|[user@host] reason\n");
    break;
#endif

#ifdef ENABLE_QUOTE
  case K_QUOTE:
    if (connections[connnum].type & TYPE_ADMIN)
    {
      if (argc < 2)
      {
	prnt(connections[connnum].socket,"Usage: %s <server message>\n", argv[0]);
	return;
      }

      p = dccbuff;
      for (i = 1; i < argc; i++)
      {
	len = sprintf(p, "%s ", argv[i]);
	p += len;
      }
      /* blow away last ' ' */
      *--p = '\0';

      toserv("%s\n", dccbuff);
    }
    else
      prnt(connections[connnum].socket, "You don't have admin privileges\n");
    break;
#endif

  default:
    prnt(connections[connnum].socket,"Unknown command [%s]\n",argv[0]+1);
    break;
  }
}

/*
 * set_actions
 *
 * inputs	- 
 * output	- NONE
 * side effects -
 */

static void 
set_actions(int sock, char *key, char *act, int duration, char *reason)
{
  int i;

  if (key == NULL)
  {
    prnt(sock, "Current actions:\n");
    for (i=0; i<MAX_ACTIONS; i++)
    {
      if (actions[i].name[0])
      {
	if (strcasecmp(actions[i].method, "warn") == 0)
	  prnt(sock, "%s action: %s\n", actions[i].name, actions[i].method);
	else
	  prnt(sock, "%s action: %s :%s\n", actions[i].name, actions[i].method,
	       actions[i].reason);
	if (actions[i].report != 0)
	  prnt(sock, " Reported to channel\n");
      }
    }
  }
  else
  {
    for (i=0; i<MAX_ACTIONS; i++)
    {
      if (!wldcmp(key, actions[i].name) && actions[i].name[0])
      {
	if (act)
	  {
	    if (duration) snprintf(actions[i].method,
				   sizeof(actions[i].method),
				   "%s %d", act, duration);
	    else snprintf(actions[i].method, sizeof(actions[i].method), "%s",
			  act);
	  }
	if (reason && reason[0]) snprintf(actions[i].reason, 
					  sizeof(actions[i].reason),
					  "%s", reason);

	if (strcasecmp(actions[i].method, "warn") == 0)
	  prnt(sock, "%s action: %s\n", actions[i].name, actions[i].method);
	else
	  prnt(sock, "%s action: %s :%s\n", actions[i].name, actions[i].method,
	       actions[i].reason);
	if (actions[i].report != 0)
	  prnt(sock, " Reported to channel\n");
      }
    }
  }
}

/*
 * is_kline_time()
 *
 * inputs          - pointer to ascii string in
 * output          - 0 if not an integer number, else the number
 * side effects    - none
 */

static int 
is_kline_time(char *p)
{
  int result = 0;

  while(*p)
  {
    if(isdigit(*p))
    {
      result *= 10;
      result += ((*p) & 0xF);
      p++;
    }
    else
      return(0);
  }

  /* in the degenerate case where oper does a /quote kline 0 user@host :reason
   * i.e. they specifically use 0, I am going to return 1 instead
   * as a return value of non-zero is used to flag it as a temporary kline
   */

  if(result == 0)
    result = 1;
  return(result);
}

/*
 * set_umode
 *
 * inputs	- connection number
 * 		- flags as string
 * 		- nick to change, or NULL if self
 * output	- NONE
 * side effects	-
 */

static void 
set_umode(int connnum, char *flags, char *registered_nick)
{
  int i;
  int reversing = NO;
  int z;
  int found = NO;
  unsigned long type;
  unsigned long new_type;

  /* UMODE! -bill */
  
  if(!registered_nick)
  {
    for( i=0; flags[i]; i++ )
    {
      switch(flags[i])
      {
      case 'e': type = TYPE_ECHO; break;
      case 'i': type = TYPE_INVS; break;
      case 'k': type = TYPE_KLINE; break;
      case 'l': type = TYPE_LINK; break;
      case 'm': type = TYPE_MOTD; break;
      case 'o': type = TYPE_LOCOPS; break;
      case 'p': type = TYPE_PARTYLINE; break;
      case 's': type = TYPE_STAT; break;
      case 'w': type = TYPE_WARN; break;

      case 'I':
	if (connections[connnum].type & TYPE_ADMIN)
	  type = TYPE_INVM ;
	else
	  type = 0;
	break;

      case 'D':
	if (connections[connnum].type & TYPE_ADMIN)
	  type = TYPE_DLINE ;
	else
	  type = 0;
	break;

      case 'G':
	if (connections[connnum].type & TYPE_ADMIN)
	  type = TYPE_GLINE ;
	else
	  type = 0;
	break;

      case '-':
	type = 0;
	reversing=YES;
	break;

      case '+':
	type = 0;
	reversing=NO;
	break;

      default:
	type = 0;
	break;
      }

      if (reversing)
	connections[connnum].type &= ~type;
      else
	connections[connnum].type |= type;
    }

    prnt(connections[connnum].socket,
	 "Your flags are now: +%s\n",
	 type_show(connections[connnum].type));

    save_umodes(connections[connnum].registered_nick,
		connections[connnum].type);
  }
  else /* only called if ADMIN */
  {
    for(z=0;z<MAXDCCCONNS;++z)
    {
      if(found)
	break;

      if (strcasecmp(registered_nick, connections[z].registered_nick) == 0)
      {
	found = YES;
	
	for(i=0; flags[i] ;i++)
	{
	  switch(flags[i])
	  {
	  case 'D': type = TYPE_DLINE; break;
	  case 'G': type = TYPE_GLINE; break;
	  case 'I': type = TYPE_INVM; break;
	  case 'K': type = TYPE_REGISTERED; break;
	  case 'O': type = TYPE_OPER; break;
	  case 'S': type = TYPE_SUSPENDED; break;
	  case 'e': type = TYPE_ECHO; break;
	  case 'i': type = TYPE_INVS; break;
	  case 'k': type = TYPE_KLINE; break;
	  case 'l': type = TYPE_LINK; break;
	  case 'm': type = TYPE_MOTD; break;
	  case 'o': type = TYPE_LOCOPS; break;
	  case 'p': type = TYPE_PARTYLINE; break;
	  case 's': type = TYPE_STAT; break;
	  case 'w': type = TYPE_WARN; break;
	  case '-':
	    reversing=YES;
	    type = 0;
	    break;
	  case '+':
	    reversing=NO;
	    type = 0;
	    break;
	  default:
	    type = 0;
	    break;
	  }

	  /* don't let an admin suspend an admin */
	  
	  if( (connections[z].type & TYPE_ADMIN) &&
	      (type&TYPE_SUSPENDED))
	    continue;

	  if(type)
	  {
	    if (!reversing)
	      connections[z].type |= type;
	    else
	      connections[z].type &= ~type;
	  }
	}

	prnt(connections[connnum].socket,
	     "Flags for %s are now: +%s\n",
	     registered_nick, type_show(connections[z].type));

	prnt(connections[z].socket,
	     "Flags for you changed by %s are now: +%s\n",
	     connections[connnum].nick,
	     type_show(connections[z].type));
      }
    }

    if(!found)
    {
      new_type=0;

      for(z=0;userlist[z].user[0];z++)
      {
	if(found)
	  break;

	if (strcasecmp(registered_nick, userlist[z].usernick) == 0)
	{
	  found = YES;

	  new_type = userlist[z].type;

	  /* default them to partyline */
	  new_type |= TYPE_PARTYLINE;

	  /* Only use user.pref if they exist */
	  if( (type = find_user_umodes(registered_nick)) )
	  {
	    new_type &= TYPE_ADMIN;
	    new_type |= type;
	    type = 0;
	  }

	  for(i=0; flags[i] ;i++)
	  {
	    switch(flags[i])
	    {
	    case 'I': type = TYPE_INVM; break;
	    case 'K': type = TYPE_REGISTERED; break;
	    case 'G': type = TYPE_GLINE; break;
	    case 'D': type = TYPE_DLINE; break;
	    case 'O': type = TYPE_OPER; break;
	    case 'S': type = TYPE_SUSPENDED; break;
	    case 'k': type = TYPE_KLINE; break;
	    case 'p': type = TYPE_PARTYLINE; break;
	    case 's': type = TYPE_STAT; break;
	    case 'w': type = TYPE_WARN; break;
	    case 'e': type = TYPE_ECHO; break;
	    case 'i': type = TYPE_INVS; break;
	    case 'l': type = TYPE_LINK; break;
	    case 'm': type = TYPE_MOTD; break;
	    case 'o': type = TYPE_LOCOPS; break;
	    case '-':
	      reversing=YES;
	      type = 0;
	      break;
	    case '+':
	      reversing=NO;
	      type = 0;
	      break;
	    default:
	      type = 0;
	      break;
	    }
		      
	    if( (new_type & TYPE_ADMIN) &&
		(type&TYPE_SUSPENDED))
	      continue;

	    if (!reversing)
	      new_type |= type;
	    else
	      new_type &= ~type;
	  }
	  
	  prnt(connections[connnum].socket,
	       "Startup flags for %s are now: +%s\n",
	       registered_nick, type_show(new_type));
	  save_umodes(registered_nick, new_type);
	}
      }
    }
  }
}

/*
 * save_umodes
 *
 * inputs	- registered nick
 *		- flags to save
 * output	- none
 * side effect	- 
 */

static void 
save_umodes(char *registered_nick, unsigned long type)
{
  FILE *fp;
  char user_pref[MAX_BUFF];

  (void)snprintf(user_pref,sizeof(user_pref) - 1,
		 "etc/%s.pref",registered_nick);

  if((fp = fopen(user_pref,"w")) == NULL)
  {
    sendtoalldcc(SEND_ALL_USERS, "Couldn't open %s for write\n",
		 user_pref );
    return;
  }

  fprintf(fp,"%lu\n",
	  type & ~(TYPE_ADMIN|TYPE_PENDING));
  (void)fclose(fp);
}

/*
 * load_umodes
 *
 * input	- connection id 
 * output	- none
 * side effect	- 
 */

static void 
load_umodes(int connect_id)
{
  FILE *fp;
  char user_pref[MAX_BUFF];
  char type_string[32];
  char *p;
  unsigned long type;

  (void)snprintf(user_pref,sizeof(user_pref) - 1,"etc/%s.pref",
                connections[connect_id].registered_nick);

  if((fp = fopen(user_pref,"r")) == NULL)
  {
    if((fp = fopen(user_pref,"w")) == NULL)
    {
      sendtoalldcc(SEND_ALL_USERS, "Couldn't open %s for write\n",
		   user_pref );
      return;
    }
    type = connections[connect_id].type;
    fprintf(fp,"%lu\n", type & ~(TYPE_ADMIN|TYPE_PENDING));
    (void)fclose(fp);
    return;
  }

  fgets(type_string,30,fp);
  (void)fclose(fp);

  if((p = strchr(type_string,'\n')) != NULL)
    *p = '\0';
  
  sscanf(type_string,"%lu",&type);
  type &= ~(TYPE_ADMIN|TYPE_PENDING);

  connections[connect_id].type &= TYPE_ADMIN;
  connections[connect_id].type |= type;

  if( type & TYPE_SUSPENDED )
  {
    type = type & TYPE_SUSPENDED;
  }

  prnt(connections[connect_id].socket, "Set umodes from %s\n", user_pref );
  prnt(connections[connect_id].socket, "Your current flags are now: %s\n",
       type_show(connections[connect_id].type));
}

/*
 * find_user_umodes
 *
 * input	- registered nick
 * output	- none
 * side effect	- 
 */

static unsigned long 
find_user_umodes(char *registered_nick)
{
  FILE *fp;
  char user_pref[MAX_BUFF];
  char type_string[32];
  char *p;
  int  unsigned long type;

  (void)snprintf(user_pref,sizeof(user_pref) - 1,
		 "etc/%s.pref",registered_nick);

  if ((fp = fopen(user_pref,"r")) == NULL)
  {
    return 0L;
  }

  if ((fgets(type_string,30,fp)) == NULL)
  {
    (void)fclose(fp);
    return 0L;
  }

  (void)fclose(fp);

  if((p = strchr(type_string,'\n')) != NULL)
    *p = '\0';

  sscanf(type_string,"%lu",&type);

  type &= ~(TYPE_ADMIN|TYPE_PENDING);

  return type;
}

/*
 * show_user_umodes
 *
 * input	- registered nick
 * output	- none
 * side effect	- 
 */

static void 
show_user_umodes(int sock, char *registered_nick)
{
  FILE *fp;
  char user_pref[MAX_BUFF];
  char type_string[32];
  int  i;
  unsigned long type = 0;
  unsigned long pref_type;
  char *p;
  int  found = NO;

  for(i=0; userlist[i].user[0]; i++)
  {
    if (strcasecmp(registered_nick, userlist[i].usernick) == 0)
    {
      type = userlist[i].type;
      found = YES;
      break;
    }
  }

  if(!found)
  {
    prnt(sock,"Can't find user [%s]\n", registered_nick );
    return;
  }
     
  (void)snprintf(user_pref,sizeof(user_pref) - 1,
		 "etc/%s.pref",registered_nick);

  if((fp = fopen(user_pref,"r")) == NULL)
  {
    prnt(sock,"%s user flags are %s\n", 
	 registered_nick,
	 type_show(type));
    return;
  }

  type &= TYPE_ADMIN ;

  fgets(type_string,30,fp);
  (void)fclose(fp);

  if((p = strchr(type_string,'\n')) != NULL)
    *p = '\0';

  sscanf(type_string,"%lu",&pref_type);

  pref_type &= ~(TYPE_ADMIN|TYPE_PENDING);

  prnt(sock,"%s user flags are %s\n", 
       registered_nick,
       type_show(type|pref_type));
}

/*
 * register_oper
 *
 * inputs	- socket
 * 		- password
 *		- who_did_command
 * output	- NONE
 * side effects	- user is warned they aren't an oper
 */

static void
register_oper(int connnum, char *password, char *who_did_command)
{
  if (password)
  {
    if ( islegal_pass(connnum, password) )
    {
      load_umodes(connnum);
	  
      if ( connections[connnum].type & TYPE_SUSPENDED)
      {
	prnt(connections[connnum].socket,
	     "You are suspended\n");
	sendtoalldcc(SEND_OPERS_ONLY,"%s is suspended\n",
		     who_did_command);
	if (connections[connnum].type &
	    (TYPE_PENDING))
	  connections[connnum].type &= ~TYPE_PENDING;
      }
      else
      {
	prnt(connections[connnum].socket,
	     "You are now registered\n");
	sendtoalldcc(SEND_OPERS_ONLY,
		     "%s has registered\n",
		     who_did_command);
	if (connections[connnum].type &
	    (TYPE_PENDING))
	  connections[connnum].type &= ~TYPE_PENDING;
      }
    }
    else
    {
      prnt(connections[connnum].socket,"illegal password\n");
      sendtoalldcc(SEND_OPERS_ONLY,
		   "illegal password from %s\n",
		   who_did_command);
    }
  }
  else
  {
    prnt(connections[connnum].socket,"missing password\n");
  }
}

/*
 * list_opers
 *
 * inputs	- socket
 * output	- NONE
 * side effects	- list current opers on socket
 */

static void 
list_opers(int sock)
{
  int i;
  
  for (i=0; i<MAXUSERS; i++)
  {
    if(userlist[i].user[0] == 0)
      break;

    prnt(sock,
	 "(%s) %s@%s %s\n",
	 (userlist[i].usernick) ? userlist[i].usernick:"unknown",
	 userlist[i].user,
	 userlist[i].host,
	 type_show(userlist[i].type));
  }
}

/*
 * list_exemptions
 *
 * inputs	- socket
 * output	- NONE
 * side effects	- list current exemptions on socket
 */

static void 
list_exemptions(int sock)
{
  int i;

  for (i=0; i<MAXHOSTS; i++)
  {
    if(hostlist[i].host[0] == 0)
      break;
    prnt(sock,"%s@%s\n", hostlist[i].user, hostlist[i].host);
  }
}

/*
 * list_connections
 *
 * inputs	- socket
 * output	- NONE
 * side effects	- active connections are listed to socket
 */

static void 
list_connections(int sock)
{
  int i;

  for (i=1; i<maxconns; i++)
  {
    if (connections[i].socket != INVALID)
    {
      if(connections[i].registered_nick[0] != 0)
      {
	prnt(sock,
	     "%s/%s %s (%s@%s) is connected - idle: %ld\n",
	     connections[i].nick,
	     connections[i].registered_nick,
	     type_show(connections[i].type),
	     connections[i].user,
	     connections[i].host,
	     time((time_t *)NULL)-connections[i].last_message_time );
      }
      else
      {
	prnt(sock,
	     "%s %s (%s@%s) is connected - idle: %ld\n",
	     connections[i].nick,
	     type_show(connections[i].type),
	     connections[i].user,
	     connections[i].host,
	     time((time_t *)NULL)-connections[i].last_message_time  );
      }
    }
  }
}

/*
 * handle_disconnect
 *
 * inputs	- socket
 *		- who did the command
 * output	- NONE
 * side effects	- disconnect user
 */

static void 
handle_disconnect(int sock,char *nickname,char *who_did_command)
{
  char *type;
  int  i;
  struct common_function *temp;

  if (nickname == NULL)
    prnt(sock, "Usage: disconnect <nickname>\n");
  else
  {
    for (i=1; i<maxconns; i++)
      if (sock != INVALID && strcasecmp(nickname,connections[i].nick) == 0)
      {
	type = "user";
	if(connections[i].type & TYPE_OPER)
	  type = "oper";

	prnt(sock,
	     "Disconnecting %s %s\n",
	     type,
	     connections[i].nick);
	prnt(sock,
	     "You have been disconnected by oper %s\n",
	     who_did_command);
	for (temp=dcc_signoff;temp;temp=temp->next)
	  temp->function(i, 0, NULL);
      }
  }
}

/*
 * handle_save
 *
 * inputs	- socket
 *		- nick who did the command
 * output	- NONE
 * side effects	- save tcm prefs
 */

static void 
handle_save(int sock,char *nick)
{
  prnt(sock, "Saving %s file\n", CONFIG_FILE);
  sendtoalldcc(SEND_OPERS_ONLY, "%s is saving %s\n", nick, CONFIG_FILE);
  save_prefs();
}

/*
 * not_authorized
 *
 * inputs	- socket
 * output	- NONE
 * side effects	- user is warned they aren't an oper
 */

static void 
not_authorized(int sock)
{
  prnt(sock,"Only authorized opers may use this command\n");
}

#ifdef IRCD_HYBRID
/*
 * ircd-hybrid-7 loadable module code goes here
 */
#else
struct TcmMessage uptime_msgtab = {
 ".uptime", 0, 0,
 {m_uptime, m_uptime, m_uptime, m_uptime}
};
struct TcmMessage mem_msgtab = {
 ".mem", 0, 0,
 {m_unregistered, m_not_oper, m_not_admin, m_mem}
};
struct TcmMessage clones_msgtab = {
 ".clones", 0, 0,
 {m_unregistered, m_not_oper, m_clones, m_clones}
};
struct TcmMessage nflood_msgtab = {
 ".nflood", 0, 0,
 {m_unregistered, m_not_oper, m_nflood, m_nflood}
};
struct TcmMessage rehash_msgtab = {
 ".rehash", 0, 0,
 {m_unregistered, m_not_oper, m_not_admin, m_rehash}
};
struct TcmMessage trace_msgtab = {
 ".trace", 0, 0,
 {m_unregistered, m_not_oper, m_trace, m_trace}
};
struct TcmMessage failures_msgtab = {
 ".failures", 0, 0,
 {m_unregistered, m_not_oper, m_failures, m_failures}
};
struct TcmMessage domains_msgtab = {
 ".domains", 0, 1,
 {m_unregistered, m_not_oper, m_domains, m_domains}
};
struct TcmMessage bots_msgtab = {
 ".bots", 0, 1,
 {m_unregistered, m_not_oper, m_bots, m_bots}
};
struct TcmMessage vmulti_msgtab = {
 ".vmulti", 0, 1,
 {m_unregistered, m_not_oper, m_vmulti, m_vmulti}
};
struct TcmMessage nfind_msgtab = {
 ".nfind", 0, 1,
 {m_unregistered, m_not_oper, m_nfind, m_nfind}
};
struct TcmMessage list_msgtab = {
 ".list", 0, 1,
 {m_unregistered, m_not_oper, m_list, m_list}
};
#endif

void 
_modinit()
{
  add_common_function(F_DCC, dccproc);
  mod_add_cmd(&uptime_msgtab);
  mod_add_cmd(&mem_msgtab);
  mod_add_cmd(&clones_msgtab);
  mod_add_cmd(&nflood_msgtab);
  mod_add_cmd(&rehash_msgtab);
  mod_add_cmd(&trace_msgtab);
  mod_add_cmd(&failures_msgtab);
  mod_add_cmd(&domains_msgtab);
  mod_add_cmd(&bots_msgtab);
  mod_add_cmd(&vmulti_msgtab);
  mod_add_cmd(&nfind_msgtab);
  mod_add_cmd(&list_msgtab);
}

void
_moddeinit()
{
  mod_del_cmd(&uptime_msgtab);
  mod_del_cmd(&mem_msgtab);
  mod_del_cmd(&clones_msgtab);
  mod_del_cmd(&nflood_msgtab);
  mod_del_cmd(&rehash_msgtab);
  mod_del_cmd(&trace_msgtab);
  mod_del_cmd(&failures_msgtab);
  mod_del_cmd(&domains_msgtab);
  mod_del_cmd(&bots_msgtab);
  mod_del_cmd(&vmulti_msgtab);
  mod_del_cmd(&nfind_msgtab);
  mod_del_cmd(&list_msgtab);
}

/*
 * report_multi_host()
 *
 * inputs       - socket to print out
 * output       - NONE
 * side effects -
 */

static void report_multi_host(int sock,int nclones)
{
  struct hashrec *userptr,*top,*temp;
  int numfound,i;
  int foundany = NO;

  nclones-=1;
  for (i = 0; i < HASHTABLESIZE; ++i)
    {
      for (top = userptr = hosttable[i]; userptr; userptr = userptr->collision)
        {
          /* Ensure we haven't already checked this user & domain */

          for( temp = top, numfound = 0; temp != userptr;
               temp = temp->collision)
            {
              if (!strcmp(temp->info->host,userptr->info->host))
                break;
            }

          if (temp == userptr)
            {
              for ( temp = userptr; temp; temp = temp->collision )
                {
                  if (!strcmp(temp->info->host,userptr->info->host))
                    numfound++; /* - zaph & Dianora :-) */
                }

              if ( numfound > nclones )
                {
                  if (!foundany)
                    {
                      foundany = YES;
                      prnt(sock,
                           "Multiple clients from the following userhosts:\n");
                    }

                  prnt(sock,
                       " %s %2d connections -- *@%s {%s}\n",
                       (numfound-nclones > 2) ? "==>" : "   ",
                       numfound,
                       userptr->info->host,
                       userptr->info->class);
                }
            }

        }
    }
  if (!foundany)
    prnt(sock, "No multiple logins found.\n");
}

/*
 * report_multi()
 *
 * inputs       - socket to print out
 * output       - NONE
 * side effects -
 */

static void
report_multi(int sock,int nclones)
{
  struct hashrec *userptr,*top,*temp;
  int numfound,i;
  int notip;
  int foundany = NO;

  nclones-=2;  /* maybe someday i'll figure out why this is nessecary */
  for (i=0;i<HASHTABLESIZE;++i)
    {
      for( top = userptr = domaintable[i]; userptr;
           userptr = userptr->collision )
        {
          /* Ensure we haven't already checked this user & domain */
          for( temp = top, numfound = 0; temp != userptr;
               temp = temp->collision )
            {
              if (!strcmp(temp->info->user,userptr->info->user) &&
                  !strcmp(temp->info->domain,userptr->info->domain))
                break;
            }

          if (temp == userptr)
            {
              for( temp = temp->collision; temp; temp = temp->collision )
                {
                  if (!strcmp(temp->info->user,userptr->info->user) &&
                      !strcmp(temp->info->domain,userptr->info->domain))
                    numfound++; /* - zaph & Dianora :-) */
                }

              if ( numfound > nclones )
                {
                  if (!foundany)
                    {
                      foundany = YES;
                      prnt(sock,
                           "Multiple clients from the following userhosts:\n");
                    }
                  notip = strncmp(userptr->info->domain,userptr->info->host,
                                  strlen(userptr->info->domain)) ||
                    (strlen(userptr->info->domain) ==
                     strlen(userptr->info->host));
                  numfound++;   /* - zaph and next line*/
                  prnt(sock,
                       " %s %2d connections -- %s@%s%s {%s}\n",
                       (numfound-nclones > 2) ? "==>" :
                       "   ",numfound,userptr->info->user,
                       notip ? "*." : userptr->info->domain,
                       notip ? userptr->info->domain : ".*",
                       userptr->info->class);
                }
            }
        }
    }
  if (!foundany)
    prnt(sock, "No multiple logins found.\n");
}

/*
 * report_multi_user()
 *
 * inputs       - socket to print out
 * output       - NONE
 * side effects -
 */

static void
report_multi_user(int sock,int nclones)
{
  struct hashrec *userptr,*top,*temp;
  int numfound;
  int i;
  int foundany = NO;

  nclones-=1;
  for (i=0;i<HASHTABLESIZE;++i)
    {
      for( top = userptr = usertable[i]; userptr;
           userptr = userptr->collision )
        {
          numfound = 0;
          /* Ensure we haven't already checked this user & domain */

          for( temp = top; temp != userptr; temp = temp->collision )
            {
              if (!strcmp(temp->info->user,userptr->info->user))
                break;
            }

          if (temp == userptr)
            {
              numfound=1;       /* fixed minor boo boo -bill */
              for( temp = temp->collision; temp; temp = temp->collision )
                {
                  if (!strcmp(temp->info->user,userptr->info->user))
                    numfound++; /* - zaph & Dianora :-) */
                }

              if ( numfound > nclones )
                {
                  if (!foundany)
                    {
                      prnt(sock,
                           "Multiple clients from the following usernames:\n");
                      foundany = YES;
                    }

                  prnt(sock,
                       " %s %2d connections -- %s@* {%s}\n",
                       (numfound-nclones > 2) ? "==>" : "   ",
                       numfound,userptr->info->user,
                       userptr->info->class);
                }
            }
        }
    }

  if (!foundany)
    {
      prnt(sock, "No multiple logins found.\n");
    }
}

/*
 * report_multi_virtuals()
 *
 * inputs       - socket to print out
 *              - number to consider as clone
 * output       - NONE
 * side effects -
 */

static void
report_multi_virtuals(int sock,int nclones)
{
  struct hashrec *userptr;
  struct hashrec *top;
  struct hashrec *temp;
  int numfound;
  int i;
  int foundany = 0;

  if(!nclones)
    nclones = 5;

  nclones-=1;
  for (i=0;i<HASHTABLESIZE;++i)
    {
      for ( top = userptr = iptable[i]; userptr; userptr = userptr->collision )
        {
          numfound = 0;

          for (temp = top; temp != userptr; temp = temp->collision)
            {
              if (!strcmp(temp->info->ip_class_c,userptr->info->ip_class_c))
                break;
            }

          if (temp == userptr)
            {
              numfound=1;
              for( temp = temp->collision; temp; temp = temp->collision )
                {
                  if (!strcmp(temp->info->ip_class_c,
                              userptr->info->ip_class_c))
                    numfound++; /* - zaph & Dianora :-) */
                }

              if (numfound > nclones)
                {
                  if (!foundany)
                    {
                      prnt(sock,
                           "Multiple clients from the following ip blocks:\n");
                      foundany = YES;
                    }

                  prnt(sock,
                       " %s %2d connections -- %s.*\n",
                       (numfound-nclones > 3) ? "==>" : "   ",
                       numfound,
                       userptr->info->ip_class_c);
                }
            }
        }
    }

  if (!foundany)
    prnt(sock, "No multiple virtual logins found.\n");
}

/*
 * islegal_pass()
 *
 * inputs       - user
 *              - host
 *              - password
 *              - int connect id
 * output       - YES if legal NO if not
 * side effects - NONE
 */

static int islegal_pass(int connect_id,char *password)
{
  int i;

  for(i=0;userlist[i].user && userlist[i].user[0];i++)
    {
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
 * print_help()
 *
 * inputs       - socket, help_text to use
 * output       - none
 * side effects - prints help file to user
 */

static void
print_help(int sock,char *text)
{
  FILE *userfile;
  char line[MAX_BUFF];
  char help_file[MAX_BUFF];

  if(!text || (*text == '\0'))
    {
      if( (userfile = fopen(HELP_PATH "/" HELP_FILE,"r")) == NULL )
        {
          prnt(sock,"Help is not currently available\n");
          return;
        }
    }
  else
    {
      while(*text == ' ')
        text++;

      if (*text == '\0')
        {
          if( (userfile = fopen(HELP_PATH "/" HELP_FILE,"r")) == NULL )
            {
              prnt(sock,"Help is not currently available\n");
              return;
            }
        }

      (void)snprintf(help_file,sizeof(help_file) - 1,"%s/%s.%s",
                     HELP_PATH,HELP_FILE,text);
      if( (userfile = fopen(help_file,"r")) == NULL)
        {
          prnt(sock,"Help for '%s' is not currently available\n",text);
          return;
        }
    }

  while (fgets(line, MAX_BUFF-1, userfile))
    {
      prnt(sock, "%s", line);
    }
  fclose(userfile);
}

static void
kill_list_users(int sock,char *userhost, char *reason)
{
  struct hashrec *userptr;
  /* Looks fishy but it really isn't */
  char fulluh[MAX_HOST+MAX_DOMAIN+2];
  int i;
  int numfound = 0;

  if (!strcmp(userhost,"*") || !strcmp(userhost,"*@*"))
      prnt(sock, "Let's not kill all the users.\n");
  else
    {
      for (i=0;i<HASHTABLESIZE;++i)
        {
          for( userptr = domaintable[i]; userptr;
               userptr = userptr->collision )
            {
              (void)snprintf(fulluh,sizeof(fulluh) - 1,
                            "%s@%s",userptr->info->user,userptr->info->host);
              if (!wldcmp(userhost,fulluh))
                {
                  if (!numfound++)
                    {
                        log("listkilled %s\n", fulluh);
                    }
                  toserv("KILL %s :%s\n", userptr->info->nick, reason);
                }
            }
        }
      if (numfound > 0)
        prnt(sock,
             "%d matches for %s found\n",numfound,userhost);
      else
        prnt(sock,
             "No matches for %s found\n",userhost);
  }
}

/*
 * list_users()
 *
 * inputs       - socket to reply on
 * output       - NONE
 * side effects -
 */

static void
list_users(int sock,char *userhost)
{
  struct hashrec *userptr;
  char fulluh[MAX_HOST+MAX_DOMAIN];
  int i;
  int numfound = 0;

  if (!strcmp(userhost,"*") || !strcmp(userhost,"*@*"))
    prnt(sock,
         "Listing all users is not recommended.  To do it anyway, use 'list ?*@*'.\n");
  else
    {
      for (i=0;i<HASHTABLESIZE;++i)
        {
          for( userptr = domaintable[i]; userptr;
               userptr = userptr->collision )
            {
              (void)snprintf(fulluh,sizeof(fulluh) - 1,
                            "%s@%s",userptr->info->user,userptr->info->host);
              if (!wldcmp(userhost,fulluh))
                {
                  if (!numfound++)
                    {
                      prnt(sock,
                           "The following clients match %.150s:\n",userhost);
                    }
                  if (userptr->info->ip_host[0] > '9' ||
                      userptr->info->ip_host[0] < '0')
                    prnt(sock,
                         "  %s (%s) {%s}\n",
                         userptr->info->nick,
                         fulluh, userptr->info->class);
                  else
                    prnt(sock, "  %s (%s) [%s] {%s}\n",
                         userptr->info->nick,
                         fulluh, userptr->info->ip_host,
                         userptr->info->class);
                }
            }
        }
      if (numfound > 0)
        prnt(sock,
             "%d matches for %s found\n",numfound,userhost);
      else
        prnt(sock,
             "No matches for %s found\n",userhost);
  }
}
