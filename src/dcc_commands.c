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

static char *version="$Id: dcc_commands.c,v 1.20 2001/10/27 16:17:21 bill Exp $";
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

void _modinit();

extern struct connection connections[];
extern struct s_testline testlines;
extern char allow_nick[MAX_ALLOW_SIZE][MAX_NICK+4];

/*
** dccproc()
**   Handles processing of dcc chat commands
*/
void 
dccproc(int connnum, int argc, char *argv[])
{

/* *sigh* maximum allow for MAXIMUM sprintf limit */
/* connnections[connnum].buffer can be larger than MAX_BUFF plus overhead */
/* connnum].buffer can be much larger than outgoing
*/

#define FLUFF_SIZE (4*MAX_NICK)+10

  char buff[MAX_BUFF];
  char dccbuff[MAX_BUFF];
  char who_did_command[2*MAX_NICK];
  int i;
  int opers_only = SEND_ALL_USERS; 	/* Is it an oper only message ? */
  int ignore_bot = NO;
  char *command, *buffer, *p;
  int kline_time;
  struct common_function *temp;
#ifndef NO_D_LINE_SUPPORT
  char *pattern;  /* u@h or nick */
#endif
#ifdef DEBUGMODE
  placed;
#endif

  if (buff[0]) memset(&buff, 0, sizeof(buff));
  for (i=0;i<argc;++i)
    {
      strncat(buff, argv[i], sizeof(buff)-strlen(buff));
      strncat(buff, " ", sizeof(buff)-strlen(buff));
    }
  if (buff[strlen(buff)-1] == ' ') buff[strlen(buff)-1] = '\0';
  buffer=buff;

  who_did_command[0] = '\0';

  /* remote message, either to a tcm command parser,
     or from a user meant to be sent on to another remote tcm,
     or, its from a remote tcm to be passed onto another tcm
  */

  (void)snprintf(who_did_command,sizeof(who_did_command) - 1, "%s@%s",
	         connections[connnum].nick,config_entries.dfltnick);

  if(*buffer != '.')
    {	
      if((buffer[0] == 'o' || buffer[0] == 'O')
	 && buffer[1] == ':')
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
	      sendtoalldcc(opers_only, dccbuff); /* Thanks Garfr, Talen */
	    }
	  else
	    {
	      if(opers_only == SEND_OPERS_ONLY)
		sendtoalldcc(opers_only, dccbuff);
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
    case K_UPTIME:
      report_uptime(connections[connnum].socket);
      break;

    case K_MEM:
      report_mem(connections[connnum].socket);
      break;

    case K_CLONES:
      if (connections[connnum].type & TYPE_OPER)
        {
          report_clones(connections[connnum].socket);
        }
      else
        {
          not_authorized(connections[connnum].socket);
        }
      break;

    case K_NFLOOD:
      if (connections[connnum].type & TYPE_OPER)
        {
          report_nick_flooders(connections[connnum].socket);
        }
      else
        {
          not_authorized(connections[connnum].socket);
        }
      break;

    case K_REHASH:
      sendtoalldcc(SEND_ALL_USERS,"Rehash requested by %s",who_did_command);

      if (config_entries.hybrid && (config_entries.hybrid_version >= 6))
	toserv("STATS I\n");
      else
	toserv("STATS E\nSTATS F\n");
      initopers();
      break;

    case K_TRACE:
      sendtoalldcc(SEND_OPERS_ONLY,
		   "trace requested by %s\n",
		   who_did_command);
      inithash();
      break;

    case K_FAILURES:

      if (argc < 2)
	report_failures(connections[connnum].socket,7);
      else if (atoi(argv[1]) < 1)
	prnt(connections[connnum].socket,"Usage: .failures [min failures]\n");
      else
	report_failures(connections[connnum].socket,atoi(argv[1]));
      break;

    case K_DOMAINS:

      if (argc < 2)
        report_domains(connections[connnum].socket,5);
      else if (atoi(argv[1]) < 1)
        prnt(connections[connnum].socket,"Usage: .domains [min users]\n");
      else
        report_domains(connections[connnum].socket,atoi(argv[1]));
      break;

    case K_BOTS:
      if (connections[connnum].type & TYPE_OPER)
        {
          if (argc >= 2)
            report_multi(connections[connnum].socket,atoi(argv[1]));
          else
            report_multi(connections[connnum].socket,3);
        }
      else
        not_authorized(connections[connnum].socket);
      break;

    case K_VMULTI:
      if (connections[connnum].type & TYPE_OPER)
        {
          if (argc >= 2)
            report_multi_virtuals(connections[connnum].socket,atoi(argv[1]));
          else
            report_multi_virtuals(connections[connnum].socket,3);
        }
      else
        not_authorized(connections[connnum].socket);
      break;
      
    case K_NFIND:
      if (connections[connnum].type & TYPE_OPER)
	{
	  if (argc < 2)
	    prnt(connections[connnum].socket, "Usage: .nfind <wildcarded nick>\n");
	  else
	    list_nicks(connections[connnum].socket,argv[1]);
	}
      else
        not_authorized(connections[connnum].socket);
      break;

    case K_LIST:
      if (connections[connnum].type & TYPE_OPER)
	{
	  if (argc < 2)
	    prnt(connections[connnum].socket, "Usage: .list <wildcarded userhost>\n");
	  else
	    list_users(connections[connnum].socket,argv[1]);
	}
      else
	not_authorized(connections[connnum].socket);
      break;

    case K_VLIST:
      if (connections[connnum].type & TYPE_OPER)
	{
	  if (argc<2)
	    prnt(connections[connnum].socket, "Usage: .vlist <ip_block>\n");
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
	    prnt(connections[connnum].socket, "Usage: %s <wildcarded userhost>\n", argv[0]);
	  else
	    {
	      sendtoalldcc(SEND_OPERS_ONLY, "killlist %s by %s\n", argv[1], who_did_command);
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
	      prnt(connections[connnum].socket, "Usage: .kline [nick]|[user@host] reason\n");
	      return;
	    }
	  do_a_kline("kline",kline_time,argv[1],argv[2],who_did_command);
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
	      prnt(connections[connnum].socket, "Usage: .kclone [nick]|[user@host]\n");
	      return;
	    }
          suggest_action(get_action_type("clone"), argv[1], NULL, NULL, NO, NO);
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
	      prnt(connections[connnum].socket, "Usage: .kflood [nick]|[user@host]\n");
	      return;
	    }
          suggest_action(get_action_type("flood"), argv[1], NULL, NULL, NO, NO);
	}
      else
	prnt(connections[connnum].socket,"You aren't registered\n");
    break;

    case K_KPERM:
      if( connections[connnum].type & TYPE_REGISTERED )
	{
	  if (argc < 2)
	    {
	      prnt(connections[connnum].socket, "Usage: .kperm [nick]|[user@host]\n");
              return;
	    }
	  do_a_kline("kperm",kline_time,argv[1],REASON_KPERM,who_did_command);
	}
      else
	prnt(connections[connnum].socket,"You aren't registered\n");
    break;

    case K_KLINK:
      if (connections[connnum].type & TYPE_REGISTERED)
	{
	  if (argc < 2)
	    {
	      prnt(connections[connnum].socket, "Usage: .klink [nick]|[user@host]\n");
              return;
	    }
          suggest_action(get_action_type("link"), argv[1], NULL, NULL, NO, NO);
	}
      else
	prnt(connections[connnum].socket,"You aren't registered\n");
      break;

    case K_KDRONE:
      if( connections[connnum].type & TYPE_REGISTERED )
	{
	  if (argc < 2)
	    {
	      prnt(connections[connnum].socket, "Usage: .kdrone [nick]|[user@host]\n");
	      return;
	    }
          suggest_action(get_action_type("drone"), argv[1], NULL, NULL, NO, NO);
	}
      else
	prnt(connections[connnum].socket,"You aren't registered\n");
    break;

    case K_KBOT:
      if( connections[connnum].type & TYPE_REGISTERED )
	{
	  if (argc < 2)
	    {
	      prnt(connections[connnum].socket, "Usage: .kbot [nick]|[user@host]\n");
	      return;
	    }
          suggest_action(get_action_type("bot"), argv[1], NULL, NULL, NO, NO);
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
                    toserv("KILL %s :requested by %s reason- %s\n", pattern, who_did_command,
			   reason);
#endif
                  }
                else
                  prnt(connections[connnum].socket, "Usage: .kill [nick]|[user@host] reason\n");
              }
          }
	else
	  prnt(connections[connnum].socket,"You aren't registered\n");
      }
    break;

    case K_SPAM:

      if( connections[connnum].type & TYPE_REGISTERED )
	{
	  if (argc < 2)
	    {
	      prnt(connections[connnum].socket, "Usage: .kspam [nick]|[user@host]\n");
	      return;
	    }
          suggest_action(get_action_type("spam"), argv[1], NULL, NULL, NO, NO);
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
      if (!strcasecmp(argv[1], testlines.umask))
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
                    memset(&dccbuff, 0, sizeof(dccbuff));
                    p=&argv[2][1];
                    snprintf(dccbuff, sizeof(dccbuff), "%s ", p);
                    for (i=3;i<argc;++i)
                      {
                        strncat((char *)&dccbuff, argv[i], sizeof(dccbuff)-strlen(dccbuff));
                        strncat((char *)&dccbuff, " ", sizeof(dccbuff)-strlen(dccbuff));
                      }
                    if (dccbuff[strlen(dccbuff)-1] == ' ') dccbuff[strlen(dccbuff)-1] = '\0';
                    set_actions(connections[connnum].socket, argv[1], NULL, 0, dccbuff);
                    break;
                  }
                /* .action clone kline :Cloning */
                if (argv[3][0] == ':')
                  {
                    memset(&dccbuff, 0, sizeof(dccbuff));
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
                    memset(&dccbuff, 0, sizeof(dccbuff));
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
                memset(&dccbuff, 0, sizeof(dccbuff));
                if (argv[4][0] == ':')
                  p = &argv[4][1];
                else
                  p = &argv[4][0];
                snprintf(dccbuff, sizeof(dccbuff), "%s ", p);
                for (i=5;i<argc;++i)
                  {
                    strncat((char *)&dccbuff, argv[i], sizeof(dccbuff)-strlen(dccbuff));
                    strncat((char *)&dccbuff, " ", sizeof(dccbuff)-strlen(dccbuff));
                  }
                if (dccbuff[strlen(dccbuff)-1] == ' ') dccbuff[strlen(dccbuff)-1] = '\0';
                set_actions(connections[connnum].socket, argv[1], argv[2], kline_time, dccbuff);
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

	if (!(strcasecmp(argv[1],"MESSAGES")))
	  {
	    connections[connnum].set_modes |= SET_PRIVMSG;
	    prnt(connections[connnum].socket, "You will see privmsgs sent to tcm\n");
	  }
	else if (!(strcasecmp(argv[1],"NOMESSAGES")))
	  {
	    connections[connnum].set_modes &= ~SET_PRIVMSG;
	    prnt(connections[connnum].socket, "You will not see privmsgs sent to tcm\n");
	  }
	else if (!(strcasecmp(argv[1],"NOTICES")))
	  {
	    connections[connnum].set_modes |= SET_NOTICES;
	    prnt(connections[connnum].socket, "You will see selected server notices\n");
	  }
	else if (!(strcasecmp(argv[1],"NONOTICES")))
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
	  prnt(connections[connnum].socket, "You don't have admin priv. to save %s file\n", 
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
      prnt(connections[connnum].socket, "real server name [%s]\n", config_entries.rserver_name);

      if(config_entries.hybrid)
	prnt(connections[connnum].socket,"Hybrid server version %d\n", 
             config_entries.hybrid_version );
      else
	prnt(connections[connnum].socket,"Not hybrid server\n" );

      break;

    case K_AUTOPILOT:
      if (!(connections[connnum].type & TYPE_OPER))
	not_authorized(connections[connnum].socket);
      else
	{
	  if(config_entries.autopilot)
	    {
	      sendtoalldcc(SEND_OPERS_ONLY, "autopilot is now OFF");
	      config_entries.autopilot = NO;
	      prnt(connections[connnum].socket, "autopilot is now OFF");
	      log("AUTOPILOT turned off by oper %s", who_did_command);
	    }
	  else
	    {
	      sendtoalldcc(SEND_OPERS_ONLY, "autopilot is now ON");
	      config_entries.autopilot = YES;
	      prnt(connections[connnum].socket, "autopilot is now ON");

	      log("AUTOPILOT turned on by oper %s", who_did_command);
	    }
	}
      break;

    case K_LOCOPS:
      if (!(connections[connnum].type & TYPE_OPER))
	not_authorized(connections[connnum].socket);
      else
	{
	  if(argc >= 2)
	    {
              memset(&dccbuff,0,sizeof(dccbuff));
              for (i=1;i<argc;++i)
                {
                  strncat((char *)&dccbuff, argv[i], sizeof(dccbuff)-strlen(dccbuff));
                  strncat((char *)&dccbuff, " ", sizeof(dccbuff)-strlen(dccbuff));
                }
              if (dccbuff[strlen(dccbuff)-1] == ' ') dccbuff[strlen(dccbuff)-1] = '\0';
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

      sendtoalldcc(SEND_OPERS_ONLY, "UNKLINE %s attempted by oper %s", argv[1],who_did_command);
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
          memset((char *)&dccbuff,0,sizeof(dccbuff));
          for (i=2;i<argc;++i)
            {
              strncat((char *)&dccbuff, argv[i], sizeof(dccbuff)-strlen(dccbuff));
              strncat((char *)&dccbuff, " ", sizeof(dccbuff)-strlen(dccbuff));
            }
          if (dccbuff[strlen(dccbuff)-1] == ' ') dccbuff[strlen(dccbuff)-1] = '\0';
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
        prnt(connections[connnum].socket, "Usage: .dline [nick]|[user@host] reason\"\n");
      break;
#endif

#ifdef ENABLE_QUOTE
      case K_QUOTE:
        if (connections[connnum].type & TYPE_ADMIN)
          {
            if (argc < 2)
              {
                prnt(connections[connnum].socket,"Usage: .quote <server message>\n");
                return;
              }
            memset((char *)&dccbuff,0,sizeof(dccbuff));
            for (i=1;i<argc;++i)
              {
                strncat((char *)&dccbuff, argv[i], sizeof(dccbuff)-strlen(dccbuff));
                strncat((char *)&dccbuff, " ", sizeof(dccbuff)-strlen(dccbuff));
              }
            if (dccbuff[strlen(dccbuff)-1] == ' ') dccbuff[strlen(dccbuff)-1] = '\0';
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
  if (!key)
    {
      prnt(sock, "Current actions:\n");
      for (i=0;i<MAX_ACTIONS;++i)
        {
          if (actions[i].name[0])
            {
              if (!strcasecmp(actions[i].method, "warn"))
                prnt(sock, "%s action: %s\n", actions[i].name, actions[i].method);
              else
                prnt(sock, "%s action: %s :%s\n", actions[i].name, actions[i].method,
                     actions[i].reason);
              if (actions[i].report)
                prnt(sock, " Reported to channel\n");
            }
        }
    }
  else
    {
      for (i=0;i<MAX_ACTIONS;++i)
        {
          if (!wldcmp(key, actions[i].name) && actions[i].name[0])
            {
             if (act)
               {
                 if (duration) snprintf(actions[i].method, sizeof(actions[i].method),
                                        "%s %d", act, duration);
                 else snprintf(actions[i].method, sizeof(actions[i].method), "%s",
                               act);
               }
             if (reason && reason[0]) snprintf(actions[i].reason, 
                                               sizeof(actions[i].reason), "%s", reason);
             if (!strcasecmp(actions[i].method, "warn"))
                prnt(sock, "%s action: %s\n", actions[i].name, actions[i].method);
              else
                prnt(sock, "%s action: %s :%s\n", actions[i].name, actions[i].method,
                     actions[i].reason);
              if (actions[i].report)
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
#ifdef DEBUGMODE
  placed;
#endif

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

  if(!result)
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

	  if (!strcasecmp(registered_nick, connections[z].registered_nick))
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
	      if(userlist[z].type & TYPE_TCM)
		continue;

	      if(found)
		break;

	      if (!strcasecmp(registered_nick, userlist[z].usernick))
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

  (void)snprintf(user_pref,sizeof(user_pref) - 1,"etc/%s.pref",registered_nick);

  if(!(fp = fopen(user_pref,"w")))
    {
      sendtoalldcc(SEND_ALL_USERS, "Couldn't open %s for write\n",
		   user_pref );
      return;
    }

  fprintf(fp,"%lu\n",
	  type & ~(TYPE_TCM|TYPE_ADMIN|TYPE_PENDING));
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

  if(!(fp = fopen(user_pref,"r")))
    {
      if(!(fp = fopen(user_pref,"w")))
	{
	  sendtoalldcc(SEND_ALL_USERS, "Couldn't open %s for write\n",
		       user_pref );
	  return;
	}
      type = connections[connect_id].type;
      fprintf(fp,"%lu\n",
	      type & ~(TYPE_TCM|TYPE_ADMIN|TYPE_PENDING));
      (void)fclose(fp);
      return;
    }

  fgets(type_string,30,fp);
  (void)fclose(fp);

  if( (p = strchr(type_string,'\n')) )
     *p = '\0';
  
  sscanf(type_string,"%lu",&type);
  type &= ~(TYPE_TCM|TYPE_ADMIN|TYPE_PENDING);

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

  (void)snprintf(user_pref,sizeof(user_pref) - 1,"etc/%s.pref",registered_nick);

  if(!(fp = fopen(user_pref,"r")))
    {
      return 0L;
    }

  if( !(fgets(type_string,30,fp)) )
    {
      (void)fclose(fp);
      return 0L;
    }

  (void)fclose(fp);

  if( (p = strchr(type_string,'\n')) )
     *p = '\0';

  sscanf(type_string,"%lu",&type);

  type &= ~(TYPE_TCM|TYPE_ADMIN|TYPE_PENDING);

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
      if(userlist[i].type & TYPE_TCM)
	continue;

      if (!strcasecmp(registered_nick, userlist[i].usernick))
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
     
  (void)snprintf(user_pref,sizeof(user_pref) - 1,"etc/%s.pref",registered_nick);

  if(!(fp = fopen(user_pref,"r")))
    {
      prnt(sock,"%s user flags are %s\n", 
	   registered_nick,
	   type_show(type));
      return;
    }

  type &= TYPE_ADMIN ;

  fgets(type_string,30,fp);
  (void)fclose(fp);

  if( (p = strchr(type_string,'\n')) )
     *p = '\0';

  sscanf(type_string,"%lu",&pref_type);

  pref_type &= ~(TYPE_TCM|TYPE_ADMIN|TYPE_PENDING);

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
  if(password)
    {
      if( islegal_pass(connnum, password) )
	{
	  load_umodes(connnum);
	  
	  if( connections[connnum].type & TYPE_SUSPENDED)
	    {
	      prnt(connections[connnum].socket,
		   "You are suspended\n");
	      sendtoalldcc(SEND_OPERS_ONLY,"%s is suspended\n",
			   who_did_command);
	      if (connections[connnum].type &
		  (TYPE_PENDING|~TYPE_TCM))
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
		  (TYPE_PENDING|~TYPE_TCM))
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
  
  for(i=0;i<MAXUSERS;i++)
    {
      if(!userlist[i].user[0])
	break;

      if(userlist[i].type & TYPE_TCM)
	{
	  prnt(sock,
	       "%s [%s@%s] %s\n",
	       userlist[i].user,
	       userlist[i].host,
	       userlist[i].usernick,
	       type_show(userlist[i].type));
	}
      else
	{
	  prnt(sock,
	       "(%s) %s@%s %s\n",
	       (userlist[i].usernick) ? userlist[i].usernick:"unknown",
	       userlist[i].user,
	       userlist[i].host,
	       type_show(userlist[i].type));
	}
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

  for(i=0;i<MAXHOSTS;i++)
    {
      if(!hostlist[i].host[0])
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

  for (i=1;i<maxconns;i++)
    {
      if (connections[i].socket != INVALID)
	{
	  if(connections[i].registered_nick[0])
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

  if (!nickname)
    prnt(sock,
	 "Usage: disconnect <nickname>\n");
  else
    {
      for (i=1;i<maxconns;++i)
	if (sock != INVALID &&
	    !strcasecmp(nickname,connections[i].nick))
	  {
	    type = "user";
	    if(connections[i].type & TYPE_OPER)
	      type = "oper";
	    if(connections[i].type & TYPE_TCM)
	      type = "tcm";

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

void 
_modinit()
{
  add_common_function(F_DCC, dccproc);
}
