/* $Id: dcc_commands.c,v 1.83 2002/05/25 16:21:06 leeh Exp $ */

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


#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <fcntl.h>
#include "config.h"
#include "tcm.h"
#include "event.h"
#include "bothunt.h"
#include "userlist.h"
#include "serverif.h"
#include "logging.h"
#include "commands.h"
#include "stdcmds.h"
#include "modules.h"
#include "tcm_io.h"
#include "wild.h"
#include "match.h"

#ifdef HAVE_CRYPT_H
#include <crypt.h>
#endif

static void set_actions(int sock, char *key, char *act, int duration, char *reason);
static void save_umodes(char *registered_nick, unsigned long type);
static void load_umodes(int connect_id);
static unsigned long find_user_umodes(char *nick);
static void set_umode(int connnum, char *flags, char *registered_nick);
static void show_user_umodes(int sock, char *registered_nick);
static void register_oper(int connnum, char *password, char *who_did_command);
static void list_opers(int sock);
static void list_connections(int sock);
static void list_exemptions(int sock);
static void handle_disconnect(int sock,char *param2,char *who_did_command);
static void handle_save(int sock,char *nick);
static int  is_legal_pass(int connect_id,char *password);
static void print_help(int sock,char *text);

extern struct s_testline testlines;
extern char * get_method_names(int method);
extern int get_method_number(char * name);

void
m_vlist(int connnum, int argc, char *argv[])
{
#ifdef HAVE_REGEX_H
  if ((argc < 2) || (argc > 2 && strcasecmp(argv[1], "-r")))
    print_to_socket(connections[connnum].socket,
		    "Usage: %s <wildcarded/regexp ip>",
		    argv[0]);
  else if (argc == 2)
    list_virtual_users(connections[connnum].socket, argv[1], NO);
  else
    list_virtual_users(connections[connnum].socket, argv[2], YES);
#else
  if (argc < 2)
    print_to_socket(connections[connnum].socket, 
		    "Usage %s <wildcarded ip>", argv[0]);
  else
    list_virtual_users(connections[connnum].socket, argv[1], NO);
#endif
}

void
m_class(int connnum, int argc, char *argv[])
{
  if (argc < 2)
    print_to_socket(connections[connnum].socket,
		    "Usage: %s <class name>", argv[0]);
  else
    list_class(connections[connnum].socket, argv[1], NO);
}

void
m_classt(int connnum, int argc, char *argv[])
{
  if (argc < 2)
    print_to_socket(connections[connnum].socket,
		    "Usage: %s <class name>", argv[0]);
  else
    list_class(connections[connnum].socket, argv[1], YES);
}

void
m_killlist(int connnum, int argc, char *argv[])
{
  char reason[MAX_REASON];

#ifdef HAVE_REGEX_H
  if ((argc < 2) || (argc > 2 && strcasecmp(argv[1], "-r")))
  {
    print_to_socket(connections[connnum].socket,
		    "Usage: %s [-r] <wildcarded/regex userhost>", argv[0]);
    return;
  }
  if (argc >= 4)
  {
    expand_args(reason, MAX_REASON-1, argc-3, argv+3);
  }
#else
  if (argc < 2)
  {
    print_to_socket(connections[connnum].socket,
         "Usage: %s <wildcarded userhost>", argv[0]);
    return;
  }
  if (argc >= 3)
  {
    expand_args(reason, sizeof(reason)-1, argc-3, argv+3);
  }
  else
    snprintf(reason, sizeof(reason), "No reason");
#endif
  if (!(connections[connnum].type & (TYPE_INVS|TYPE_INVM)))
  {
    strncat(reason, " (requested by ", sizeof(reason)-strlen(reason));
    strncat(reason, connections[connnum].registered_nick,
            sizeof(reason)-strlen(reason));
    strncat(reason, ")", sizeof(reason)-strlen(reason));
  }
#ifdef HAVE_REGEX_H
  if (strcasecmp(argv[1], "-r"))
  {
    send_to_all( SEND_ALL, "*** killlist %s :%s by %s", argv[1],
                 reason, connections[connnum].registered_nick);
    kill_list_users(connections[connnum].socket, argv[1], reason, NO);
  }
  else
  {
    send_to_all( SEND_ALL, "*** killlist %s :%s by %s", argv[2],
                 reason, connections[connnum].registered_nick);
    kill_list_users(connections[connnum].socket, argv[2], reason, YES);
  }
#else
  send_to_all( SEND_ALL, "*** killlist %s :%s by %s", argv[1],
               reason, connections[connnum].registered_nick);
  kill_list_users(connections[connnum].socket, argv[1], reason, NO);
#endif
}

void
m_kline(int connnum, int argc, char *argv[])
{
  char buff[MAX_BUFF];
  int kline_time;

  if (argc < 3)
    print_to_socket(connections[connnum].socket,
         "Usage: %s [time] <[nick]|[user@host]> [reason]", argv[0]);
  else
  {
    if ((kline_time = atoi(argv[1])))
    {
      if (argc >= 4)
      {
	expand_args(buff, MAX_BUFF-1, argc-3, argv+3);
      }
      else
        snprintf(buff, sizeof(buff), "No reason");
      do_a_kline("kline", kline_time, argv[2], buff, 
                 connections[connnum].registered_nick);
    }
    else
    {
      if (argc >= 3)
      {
	expand_args(buff, MAX_BUFF-1, argc-3, argv+3);
      }
      do_a_kline("kline", 0, argv[1], buff,
		 connections[connnum].registered_nick);
    }
  }
}

void
m_kperm(int connnum, int argc, char *argv[])
{
  if (argc < 2)
    print_to_socket(connections[connnum].socket,
         "Usage: %s [time] <[nick]|[user@host]>", argv[0]);
  else
    do_a_kline("kperm", 0, argv[1], REASON_KPERM, 
               connections[connnum].registered_nick);
}

void
m_kill(int connnum, int argc, char *argv[])
{
  char reason[1024];

  if (argc < 2)
  {
    print_to_socket(connections[connnum].socket,
         "Usage: %s <nick|user@host> [reason]", argv[0]);
    return;
  }
  else if (argc == 2)
    snprintf(reason, sizeof(reason), "No reason");
  else
  {
    expand_args(reason, sizeof(reason)-1, argc-2, argv+2);
  }
  send_to_all( SEND_KLINE_NOTICES, "*** kill %s :%s by %s",
               argv[1], reason, connections[connnum].registered_nick);
  log_kline("KILL", argv[1], 0, connections[connnum].registered_nick, reason);
  if (!(connections[connnum].type & (TYPE_INVS|TYPE_INVM)))
  {
    strncat(reason, " (requested by ", sizeof(reason)-strlen(reason));
    strncat(reason, connections[connnum].registered_nick,
            sizeof(reason)-strlen(reason));
    strncat(reason, ")", sizeof(reason)-strlen(reason));
  }
  print_to_server("KILL %s :%s", argv[1], reason);
}

void
m_use_kaction(int connnum, int argc, char *argv[])
{
  print_to_socket(connections[connnum].socket,
		  "%s is deprecated, please use .kaction", argv[0]);

}

void
m_kaction(int connnum, int argc, char *argv[])
{
  int actionid;
  int kline_time = 0;
  char *who, *host;

  if (argc < 3)
    {
      print_to_socket(connections[connnum].socket,
		      "Usage: %s action [time] <[nick]|[user@host]>",
		      argv[0]);
      return;
    } 

  actionid = find_action(argv[1]);
  if (actionid < 0)
    {
      print_to_socket(connections[connnum].socket,
		      "%s is not a valid action", argv[1]);
      return;
    }
  
  if (argc == 4)
    {
      if (actions[actionid].method & METHOD_TKLINE)
	{
	  kline_time = atoi(argv[2]);
	  if (!kline_time)
	    {
	      print_to_socket(connections[connnum].socket,
			      "%s is not a valid k-line time", argv[2]);
	      return;
	    }
	}
      else
	{
	  print_to_socket(connections[connnum].socket,
 "The %s action is not configured to use temporary k-lines, k-line time will be ignored\n", argv[1]);
	}
      who = argv[3];
    }
  else
    who = argv[2];
  
  if ((host = strchr(who, '@')))
    *host++=0;

  handle_action(actionid, 0, host ? "" : who, host ? who : 0, host ? host : 0, 0, "Manually set");
}


void
m_hmulti(int connnum, int argc, char *argv[])
{
  int t;

  if (argc >= 2)
  {
    if ((t = atoi(argv[1])) < 3)
    {
      print_to_socket(connections[connnum].socket,
           "Using a threshold less than 3 is forbidden, changed to 3\n");
      t = 3;
    }
  }
  else
    t = 3;
  report_multi_host(connections[connnum].socket, t);
}

void
m_umulti(int connnum, int argc, char *argv[])
{
  int t;

  if (argc >= 2)
  {
    if ((t = atoi(argv[1])) < 3)
    {
      print_to_socket(connections[connnum].socket,
           "Using a threshold less than 3 is forbidden, changed to 3\n");
      t = 3;
    }
  }
  else
    t = 3;
  report_multi_user(connections[connnum].socket, t);
}

void
m_register(int connnum, int argc, char *argv[])
{
  if (connections[connnum].type & TYPE_OPER)
  {
    print_to_socket(connections[connnum].socket, 
		    "You are already registered.");
    return;
  }

  if (argc != 2)
    print_to_socket(connections[connnum].socket,
		    "Usage: %s <password>", argv[0]);
  else
    register_oper(connnum, argv[1], connections[connnum].nick);
}

void m_opers(int connnum, int argc, char *argv[])
{
  list_opers(connections[connnum].socket);
}

void
m_testline(int connnum, int argc, char *argv[])
{
  if (argc < 2)
  {
    print_to_socket(connections[connnum].socket,
		    "Usage: %s <mask>", argv[0]);
    return;
  }
  if (strcasecmp(argv[1], testlines.umask) == 0)
  {
    print_to_socket(connections[connnum].socket,
		    "Already pending %s", argv[1]);
    return;
  }
  snprintf(testlines.umask, sizeof(testlines.umask), "%s", argv[1]);
  testlines.index = connnum;
  print_to_server("TESTLINE %s", argv[1]);
}

void
m_actions(int connnum, int argc, char *argv[])
{
  print_to_socket(connections[connnum].socket,
		  "%s is deprecated, use .action", argv[0]);
}

void
m_action(int connnum, int argc, char *argv[])
{
  int kline_time, i;
  char methods[MAX_BUFF], reason[MAX_BUFF];

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
    /* .action clone :Cloning is prohibited */
    /* .action clone kline */
    /* .action clone kline :Cloning */
    /* .action clone kline 1440 ircwarn dccwarn :Cloning is prohibited*/        
    default:
      /* Scan up to first ':' (extracting first found number if any)
	 and make two strings; methods & reason */
      kline_time = 0;
      methods[0] = 0;
      reason[0] = 0;
      for (i=2;i<argc;i++)
	{
	  if (argv[i][0]==':')
	    {
	      snprintf(reason, sizeof(reason), "%s ", argv[i]+1);
	      for (;i<argc;i++)
		{
		  strncat(reason, argv[i], sizeof(reason));
		  strncat(reason, " ", sizeof(reason));
		}
	      break;
	    }
	  if ((!kline_time) && (atoi(argv[i])>0))
	    {
	      kline_time = atoi(argv[i]);
	    }
	  else
	    {
	      strncat(methods, argv[i], sizeof(methods));
	      strncat(methods, " ", sizeof(methods));
	    }
	}
      i = strlen(methods);
      if (i && (methods[i-1]==' '))
	methods[i-1] = 0;
      i = strlen(reason);
      if (i && (reason[i-1]==' '))
	reason[i-1] = 0;
      set_actions(connections[connnum].socket, argv[1], 
		  methods[0] ? methods : NULL, 
		  kline_time, 
		  reason[0] ? reason : NULL);
      break;
  }
}

void
m_set(int connnum, int argc, char *argv[])
{
  if (argc < 2)
  {
    if (connections[connnum].set_modes & SET_PRIVMSG)
      print_to_socket(connections[connnum].socket, "MESSAGES");
    else
      print_to_socket(connections[connnum].socket, "NOMESSAGES");
    if (connections[connnum].set_modes & SET_NOTICES)
      print_to_socket(connections[connnum].socket, "NOTICES");
    else
      print_to_socket(connections[connnum].socket, "NONOTICES");
    return;
  }
  if ((strcasecmp(argv[1],"MESSAGES")) == 0)
  {
    connections[connnum].set_modes |= SET_PRIVMSG;
    print_to_socket(connections[connnum].socket,
		    "You will see privmsgs sent to tcm");
  }
  else if ((strcasecmp(argv[1],"NOMESSAGES")) == 0)
  {
    connections[connnum].set_modes &= ~SET_PRIVMSG;
    print_to_socket(connections[connnum].socket,
		    "You will not see privmsgs sent to tcm");
  }
  else if ((strcasecmp(argv[1],"NOTICES")) == 0)
  {
    connections[connnum].set_modes |= SET_NOTICES;
    print_to_socket(connections[connnum].socket,
		    "You will see selected server notices");
  }
  else if ((strcasecmp(argv[1],"NONOTICES")) == 0)
  {
    connections[connnum].set_modes &= ~SET_NOTICES;
    print_to_socket(connections[connnum].socket,
		    "You will not see server notices");
  }
  else
  {
    print_to_socket(connections[connnum].socket,
		    "Usage: .set [MESSAGES|NOMESSAGES]");
    print_to_socket(connections[connnum].socket,
		    "Usage: .set [NOTICES|NONOTICES]");
  }
}

void
m_uptime(int connnum, int argc, char *argv[])
{
  report_uptime(connections[connnum].socket);
}

void m_exemptions(int connnum, int argc, char *argv[])
{
  list_exemptions(connections[connnum].socket);
}

void
m_umode(int connnum, int argc, char *argv[])
{
  if (argc < 2)
  {
    print_to_socket(connections[connnum].socket,
		    "Your current flags are: %s",
         type_show(connections[connnum].type));
    return;
  }
  if (argc >= 3)
  {
    if (!(connections[connnum].type & TYPE_ADMIN))
    {
      print_to_socket(connections[connnum].socket, "You aren't an admin");
      return;
    }
    if ((argv[2][0] == '+') || (argv[2][0] == '-'))
      set_umode(connnum,argv[2],argv[1]);
    else
        print_to_socket(connections[connnum].socket,
             ".umode [user flags] | [user] | [flags]");
  }
  else
  {
    if ((argv[1][0] == '+') || (argv[1][0] == '-'))
      set_umode(connnum, argv[1], NULL);
    else
    {
      if (!(connections[connnum].type & TYPE_ADMIN))
        {
          print_to_socket(connections[connnum].socket,
			  "You aren't an admin");
          return;
        }
      show_user_umodes(connections[connnum].socket,argv[1]);
    }
  }
}

void
m_connections(int connnum, int argc, char *argv[])
{
  list_connections(connections[connnum].socket);
}

void
m_disconnect(int connnum, int argc, char *argv[])
{
  if (argc < 2)
    print_to_socket(connections[connnum].socket,
		    "Usage: %s <nick>", argv[0]);
  else
    handle_disconnect(connections[connnum].socket, argv[1],
                      connections[connnum].registered_nick);
}

void
m_help(int connnum, int argc, char *argv[])
{
  if (argc < 2)
    print_to_socket(connections[connnum].socket, 
		    "Usage: %s ?", argv[0]);
  else
    print_help(connections[connnum].socket, argv[1]);
}

void
m_motd(int connnum, int argc, char *argv[])
{
  print_motd(connections[connnum].socket);
}

void
m_save(int connnum, int argc, char *argv[])
{
  handle_save(connections[connnum].socket, 
              connections[connnum].registered_nick);
}

void
m_close(int connnum, int argc, char *argv[])
{
  print_to_socket(connections[connnum].socket, "Closing connection");
  closeconn(connnum, 0, NULL);
}

void
m_op(int connnum, int argc, char *argv[])
{
  if (argc < 2)
    print_to_socket(connections[connnum].socket,
		    "Usage: %s <nick>", argv[0]);
  else
    op(config_entries.defchannel, argv[1]);
}

void
m_cycle(int connnum, int argc, char *argv[])
{
  leave(config_entries.defchannel);
  send_to_all( SEND_ALL, "I'm cycling.  Be right back.\n");
  sleep(1);
  /* probably on a cycle, we'd want the tcm to set
   * the key as well...
   */
  join(config_entries.defchannel, config_entries.defchannel_key);
  set_modes(config_entries.defchannel, config_entries.defchannel_mode,
            config_entries.defchannel_key);
}

void
m_die(int connnum, int argc, char *argv[])
{
  send_to_all( SEND_ALL, "I've been ordered to quit irc, goodbye.");
  print_to_server("QUIT :Dead by request!");
  log("DIEd by oper %s\n", connections[connnum].registered_nick);
  exit(1);
}

void
m_restart(int connnum, int argc, char *argv[])
{
  send_to_all( SEND_ALL, "I've been ordered to restart.");
  print_to_server("QUIT :Restart by request!");
  log("RESTART by oper %s", connections[connnum].registered_nick);
  sleep(1);
  execv(SPATH, NULL);
}

void
m_info(int connnum, int argc, char *argv[])
{
  print_to_socket(connections[connnum].socket, "real server name [%s]",
       config_entries.rserver_name);
  if (config_entries.hybrid)
    print_to_socket(connections[connnum].socket, "Hybrid server version %d",
         config_entries.hybrid_version);
  else
    print_to_socket(connections[connnum].socket, "Non hybrid server");
}

void
m_locops(int connnum, int argc, char *argv[])
{
  char *p, dccbuff[MAX_BUFF];
  int i, len;

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
      print_to_server("LOCOPS :(%s) %s", connections[connnum].nick, dccbuff+1);
    else
      print_to_server("LOCOPS :(%s) %s", connections[connnum].nick, dccbuff);
  }
  else
    print_to_socket(connections[connnum].socket,
         "Really, it would help if you said something");
}

void
m_unkline(int connnum, int argc, char *argv[])
{
  if (argc < 2)
    print_to_socket(connections[connnum].socket, 
		    "Usage: %s <user@host>", argv[0]);
  else
  {
    log("UNKLINE %s attempted by oper %s", argv[1],
        connections[connnum].registered_nick);
    send_to_all( SEND_KLINE_NOTICES, "UNKLINE %s attempted by oper %s", 
                 argv[1], connections[connnum].registered_nick);
    print_to_server("UNKLINE %s",argv[1]);
  }
}

void
m_vbots(int connnum, int argc, char *argv[])
{
  if (argc >= 2)
    report_vbots(connections[connnum].socket, atoi(argv[1]));
  else
    report_vbots(connections[connnum].socket, 3);
}

#ifndef NO_D_LINE_SUPPORT
void
m_dline(int connnum, int argc, char *argv[])
{
  char *p, reason[MAX_BUFF];
  int i, len;

  if (!(connections[connnum].type & TYPE_DLINE))
  {
    print_to_socket(connections[connnum].socket,
		    "You do not have access to .dline");
    return;
  }
  if (argc >= 3)
  {
    p = reason;
    for (i = 2; i < argc; i++)
    {
      len = sprintf(p, "%s ", argv[i]);
      p += len;
    }
    /* blow away last ' ' */
    *--p = '\0';
    if (reason[0] == ':')
      log_kline("DLINE", argv[1], 0, connections[connnum].registered_nick, 
                reason+1);
    else
      log_kline("DLINE", argv[1], 0, connections[connnum].registered_nick,
                reason);
    send_to_all( SEND_ALL, "*** dline %s :%s by %s", argv[1],
                 reason, connections[connnum].registered_nick);
    if (!connections[connnum].type & (TYPE_INVS|TYPE_INVM))
    {
      strncat(reason, " (requested by ", sizeof(reason)-strlen(reason));
      strncat(reason, connections[connnum].nick,
              sizeof(reason)-strlen(reason));
      strncat(reason, ")", sizeof(reason)-strlen(reason));
    }
    print_to_server("DLINE %s :%s", argv[1], reason);
  }
}
#endif

#ifdef ENABLE_QUOTE
void
m_quote(int connnum, int argc, char *argv[])
{
  char dccbuff[MAX_BUFF];

  if (argc < 2)
  {
    print_to_socket(connections[connnum].socket,
		    "Usage: %s <server message>", 
         argv[0]);
    return;
  }
  expand_args(dccbuff, MAX_BUFF-1, argc, argv);
  print_to_server("%s", dccbuff);
}
#endif

void
m_mem(int connnum, int argc, char *argv[])
{
  report_mem(connections[connnum].socket);
}

void
m_clones(int connnum, int argc, char *argv[])
{
  report_clones(connections[connnum].socket);
}

void m_nflood(int connnum, int argc, char *argv[])
{
  report_nick_flooders(connections[connnum].socket);
}

void
m_rehash(int connnum, int argc, char *argv[])
{
  send_to_all( SEND_ALL,
	       "*** rehash requested by %s", 
               connections[connnum].registered_nick[0] ?
               connections[connnum].registered_nick :
               connections[connnum].nick);

  if (config_entries.hybrid && (config_entries.hybrid_version >= 6))
    {
      print_to_server("STATS I");
      print_to_server("STATS Y");
    }
  else
    {
      print_to_server("STATS E");
      print_to_server("STATS F");
      print_to_server("STATS Y");
    }

  initopers();
  logclear();
}

void
m_trace(int connnum, int argc, char *argv[])
{
  send_to_all( SEND_ALL,
	       "Trace requested by %s",
               connections[connnum].registered_nick[0] ?
               connections[connnum].registered_nick :
               connections[connnum].nick);

  inithash();
  print_to_server("STATS Y");
}

void
m_failures(int connnum, int argc, char *argv[])
{
  if (argc < 2)
    report_failures(connections[connnum].socket, 7);
  else if (atoi(argv[1]) < 1)
    print_to_socket(connections[connnum].socket,
		    "Usage: %s [min failures]", argv[0]);
  else
    report_failures(connections[connnum].socket, atoi(argv[1]));
}

void
m_domains(int connnum, int argc, char *argv[])
{
  if (argc < 2)
    report_domains(connections[connnum].socket, 5);
  else if (atoi(argv[1]) < 1)
    print_to_socket(connections[connnum].socket,
		    "Usage: %s [min users]", argv[0]);
  else
    report_domains(connections[connnum].socket, atoi(argv[1]));
}

void
m_bots(int connnum, int argc, char *argv[])
{
  if (argc >= 2)
    report_multi(connections[connnum].socket, atoi(argv[1]));
  else
    report_multi(connections[connnum].socket, 3);
}

void
m_events(int connnum, int argc, char *argv[])
{
  show_events(connections[connnum].socket);
}

#ifdef VIRTUAL
void m_vmulti(int connnum, int argc, char *argv[])
{
  if (argc >= 2)
    report_multi_virtuals(connections[connnum].socket, atoi(argv[1]));
  else
    report_multi_virtuals(connections[connnum].socket, 3);
}
#endif

void
m_nfind(int connnum, int argc, char *argv[])
{
#ifdef HAVE_REGEX_H
  if ((argc < 2) || (argc > 2 && strcasecmp(argv[1], "-r")))
    print_to_socket(connections[connnum].socket,
		    "Usage: %s [-r] <wildcarded/regexp nick>", argv[0]);
  else if (argc == 2)
    list_nicks(connections[connnum].socket, argv[1], NO);
  else
    list_nicks(connections[connnum].socket, argv[2], YES);
#else
  if (argc <= 2)
    print_to_socket(connections[connnum].socket,
		    "Usage: %s <wildcarded nick>", argv[0]);
  else
    list_nicks(connections[connnum].socket, argv[1], NO);
#endif
} 

void
m_list(int connnum, int argc, char *argv[])
{
#ifdef HAVE_REGEX_H
  if ((argc < 2) || (argc > 2 && strcasecmp(argv[1], "-r")))
    print_to_socket(connections[connnum].socket,
         "Usage: %s [-r] <wildcarded/regex userhost>", argv[0]);
  else if (argc == 2)
    list_users(connections[connnum].socket, argv[1], NO);
  else
    list_users(connections[connnum].socket, argv[2], YES);
#else
  if (argc < 2)
    print_to_socket(connections[connnum].socket,
		    "Usage: %s <wildcarded userhost>",
         argv[0]);
  else
    list_users(connections[connnum].socket, argv[1], NO);
#endif
}

#ifdef WANT_ULIST
void
m_ulist(int connnum, int argc, char *argv[])
{
  char buf[MAX_BUFF];

#ifdef HAVE_REGEX_H
  if ((argc < 2) || (argc > 2 && strcasecmp(argv[1], "-r")))
    print_to_socket(connections[connnum].socket,
         "Usage: %s [-r] <wildcarded/regex username>", argv[0]);
  else if (argc == 2)
  {
    snprintf(buf, MAX_BUFF, "%s@*", argv[1]);
    list_users(connections[connnum].socket, buf, NO);
  }
  else
  {
    snprintf(buf, MAX_BUFF, "%s@*", argv[2]);
    list_users(connections[connnum].socket, buf, YES);
  }
#else
  if (argc < 2)
    print_to_socket(connections[connnum].socket,
		    "Usage: %s <wildcarded username>",
         argv[0]);
  else
  {
    snprintf(buf, MAX_BUFF, "%s@*", argv[1]);
    list_users(connections[connnum].socket, argv[1], NO);
  }
#endif
}
#endif

#ifdef WANT_HLIST
void
m_hlist(int connnum, int argc, char *argv[])
{
  char buf[MAX_BUFF];

#ifdef HAVE_REGEX_H
  if ((argc < 2) || (argc > 2 && strcasecmp(argv[1], "-r")))
    print_to_socket(connections[connnum].socket,
         "Usage: %s [-r] <wildcarded/regex host>", argv[0]);
  else if (argc == 2)
  {
    snprintf(buf, MAX_BUFF, "*@%s", argv[1]);
    list_users(connections[connnum].socket, buf, NO);
  }
  else
  {
    snprintf(buf, MAX_BUFF, "*@%s", argv[2]);
    list_users(connections[connnum].socket, buf, YES);
  }
#else
  if (argc < 2)
    print_to_socket(connections[connnum].socket, 
		    "Usage: %s <wildcarded host>",
         argv[0]);
  else
  {
    snprintf(buf, MAX_BUFF, "*@%s", argv[1]);
    list_users(connections[connnum].socket, argv[1], NO);
  }
#endif
}
#endif

/*
 * set_actions
 *
 * inputs	- 
 * output	- NONE
 * side effects -
 */

static void 
set_actions(int sock, char *key, char *methods, int duration, char *reason)
{
  int i;
  char * p;
  int newmethods = 0;
  int changing = (methods || duration || reason);

  while (methods)
    {
      p = strchr(methods, ' ');
      if (p) 
	*p++ = 0;
      /* Lookup method constant based on method name */
      i = get_method_number(methods);
      if (i)
	{
	  newmethods |= i;
	}
      else
	{
	  print_to_socket(sock, "%s is not a valid method", methods);
	  return;
	}
      methods = p;
    }

  if (key == NULL)
    key = "*";
  if (changing)
    {
      print_to_socket(sock, "Updating actions matching '%s'", key);
    }
  else
    {
      print_to_socket(sock, "Listing actions matching '%s'", key);
    }

  for (i=0; i<MAX_ACTIONS; i++)
    {
      if (actions[i].name[0])
	{
	  if (!wldcmp(key, actions[i].name))
	    {
	      if (newmethods) 
		set_action_method(i, newmethods);
	      if (reason)
		set_action_reason(i, reason);
	      if (duration)
		set_action_time(i, duration);
	
	      if (changing)
		{
		  print_to_socket(
				  sock,
			  "%s action now: %s, duration %d, reason '%s'",
				  actions[i].name,
				  get_method_names(actions[i].method),
				  actions[i].klinetime,
				  actions[i].reason);
		}
	      else
		{
		  print_to_socket(
				  sock,
				  "%s action: %s, duration %d, reason '%s'",
				  actions[i].name,
				  get_method_names(actions[i].method),
				  actions[i].klinetime,
				  actions[i].reason);
		}
	    }
	}
    }
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
      case 'k': type = TYPE_VIEW_KLINES; break;
      case 'y': type = TYPE_SPY; break;
      case 'o': type = TYPE_LOCOPS; break;
      case 'p': type = TYPE_PARTYLINE; break;
      case 'w': type = TYPE_WARN; break;
      case 'x': type = TYPE_SERVERS; break;

      case 'I':
	if (connections[connnum].type & TYPE_ADMIN)
	  type = TYPE_INVM ;
	else
	  type = 0;
	break;

#ifndef NO_D_LINE_SUPPORT
      case 'D':
	if (connections[connnum].type & TYPE_ADMIN)
	  type = TYPE_DLINE ;
	else
	  type = 0;
	break;
#endif

      case 'G':
	if (connections[connnum].type & TYPE_ADMIN)
	  type = TYPE_GLINE ;
	else
	  type = 0;
	break;

#ifdef ENABLE_W_FLAG
      case 'W':
        if (connections[connnum].type & TYPE_ADMIN)
          type = TYPE_OPERWALL ;
        else
          type = 0;
#endif

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

    print_to_socket(connections[connnum].socket,
	 "Your flags are now: +%s",
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
#ifndef NO_D_LINE_SUPPORT
	  case 'D': type = TYPE_DLINE; break;
#endif
	  case 'G': type = TYPE_GLINE; break;
	  case 'I': type = TYPE_INVM; break;
	  case 'K': type = TYPE_KLINE; break;
	  case 'S': type = TYPE_SUSPENDED; break;
#ifdef ENABLE_W_FLAG
          case 'W': type = TYPE_OPERWALL; break;
#endif
	  case 'e': type = TYPE_ECHO; break;
	  case 'i': type = TYPE_INVS; break;
	  case 'k': type = TYPE_VIEW_KLINES; break;
          case 'y': type = TYPE_SPY; break;
	  case 'o': type = TYPE_LOCOPS; break;
	  case 'p': type = TYPE_PARTYLINE; break;
	  case 'w': type = TYPE_WARN; break;
          case 'x': type = TYPE_SERVERS; break;
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

	print_to_socket(connections[connnum].socket,
			"Flags for %s are now: +%s",
			registered_nick, type_show(connections[z].type));

	print_to_socket(connections[z].socket,
			"Flags for you changed by %s are now: +%s",
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
	    case 'K': type = TYPE_KLINE; break;
	    case 'G': type = TYPE_GLINE; break;
#ifndef NO_D_LINE_SUPPORT
	    case 'D': type = TYPE_DLINE; break;
#endif
	    case 'S': type = TYPE_SUSPENDED; break;
#ifdef ENABLE_W_FLAG
            case 'W': type = TYPE_OPERWALL; break;
#endif
	    case 'k': type = TYPE_VIEW_KLINES; break;
	    case 'p': type = TYPE_PARTYLINE; break;
	    case 'w': type = TYPE_WARN; break;
	    case 'e': type = TYPE_ECHO; break;
	    case 'i': type = TYPE_INVS; break;
            case 'y': type = TYPE_SPY; break;
	    case 'o': type = TYPE_LOCOPS; break;
            case 'x': type = TYPE_SERVERS; break;
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
	  
	  print_to_socket(connections[connnum].socket,
	       "Startup flags for %s are now: +%s",
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
    send_to_all( SEND_ALL, "Couldn't open %s for write", user_pref);
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
      send_to_all( SEND_ALL, "Couldn't open %s for write", user_pref);
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

  print_to_socket(connections[connect_id].socket, 
		  "Set umodes from %s", user_pref );
  print_to_socket(connections[connect_id].socket,
		  "Your current flags are now: %s",
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
    print_to_socket(sock,"Can't find user [%s]", registered_nick );
    return;
  }
     
  (void)snprintf(user_pref,sizeof(user_pref) - 1,
		 "etc/%s.pref",registered_nick);

  if((fp = fopen(user_pref,"r")) == NULL)
  {
    print_to_socket(sock,"%s user flags are %s", 
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

  print_to_socket(sock,"%s user flags are %s", 
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
  if (password != NULL)
  {
    if (is_legal_pass(connnum, password))
    {
      load_umodes(connnum);
	  
      if (connections[connnum].type & TYPE_SUSPENDED)
      {
	print_to_socket(connections[connnum].socket,
	     "You are suspended");
	send_to_all(SEND_ALL, "%s is suspended", who_did_command);
	if (connections[connnum].type & TYPE_PENDING)
	  connections[connnum].type &= ~TYPE_PENDING;
      }
      else
      {
	print_to_socket(connections[connnum].socket,
	                "You are now registered");
	send_to_all(SEND_ALL, "%s has registered", who_did_command);

	if (connections[connnum].type & TYPE_PENDING)
	  connections[connnum].type &= ~TYPE_PENDING;

	connections[connnum].type |= TYPE_OPER;
      }
    }
    else
    {
      print_to_socket(connections[connnum].socket,"illegal password");
      send_to_all(SEND_ALL, "illegal password from %s", who_did_command);
    }
  }
  else
  {
    print_to_socket(connections[connnum].socket,"missing password");
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

    print_to_socket(sock,
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
  int i, n;
  char buf[512];

  for (i=0; i<MAXHOSTS; i++)
  {
    if(hostlist[i].host[0] == 0)
      break;
    sprintf(buf, "%s@%s is exempted for:", hostlist[i].user, hostlist[i].host);
    for (n=0;actions[n].name[0];n++)
      if ((1 << n) & hostlist[i].type)
	snprintf(buf + strlen(buf), sizeof(buf) - strlen(buf), " %s", actions[n].name);
    print_to_socket(sock,"%s", buf);
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
	print_to_socket(sock,
	     "%s/%s %s (%s@%s) is connected - idle: %ld",
	     connections[i].nick,
	     connections[i].registered_nick,
	     type_show(connections[i].type),
	     connections[i].user,
	     connections[i].host,
	     time((time_t *)NULL)-connections[i].last_message_time );
      }
      else
      {
	print_to_socket(sock,
	     "%s %s (%s@%s) is connected - idle: %ld",
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
handle_disconnect(int sock, char *nickname, char *who_did_command)
{
  int  i;

  if (nickname == NULL)
    print_to_socket(sock, "Usage: disconnect <nickname>");
  else
  {
    for (i=1; i<maxconns; i++)
      if (sock != INVALID && strcasecmp(nickname,connections[i].nick) == 0)
      {
	print_to_socket(sock, "Disconnecting oper %s", connections[i].nick);
	print_to_socket(sock, "You have been disconnected by oper %s", 
			who_did_command);
	closeconn(i, 0, NULL);
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
  print_to_socket(sock, "Saving %s file", CONFIG_FILE);
  send_to_all( SEND_ALL, "%s is saving %s", nick, CONFIG_FILE);
  save_prefs();
}

#ifdef IRCD_HYBRID
/*
 * ircd-hybrid-7 loadable module code goes here
 */
#else
struct dcc_command vlist_msgtab = {
 "vlist", NULL, {m_unregistered, m_vlist, m_vlist}
};
struct dcc_command class_msgtab = {
 "class", NULL, {m_unregistered, m_class, m_class}
};
struct dcc_command classt_msgtab = {
 "classt", NULL, {m_unregistered, m_classt, m_classt}
};
struct dcc_command killlist_msgtab = {
 "killlist", NULL, {m_unregistered, m_killlist, m_killlist}
};
struct dcc_command kline_msgtab = {
 "kline", NULL, {m_unregistered, m_kline, m_kline}
};
struct dcc_command kclone_msgtab = {
 "kclone", NULL, {m_unregistered, m_use_kaction, m_use_kaction}
};
struct dcc_command kflood_msgtab = {
 "kflood", NULL, {m_unregistered, m_use_kaction, m_use_kaction}
};
struct dcc_command kperm_msgtab = {
 "kperm", NULL, {m_unregistered, m_kperm, m_kperm}
};
struct dcc_command klink_msgtab = {
 "klink", NULL, {m_unregistered, m_use_kaction, m_use_kaction}
};
struct dcc_command kdrone_msgtab = {
 "kdrone", NULL, {m_unregistered, m_use_kaction, m_use_kaction}
};
struct dcc_command kbot_msgtab = {
 "kbot", NULL, {m_unregistered, m_use_kaction, m_use_kaction}
};
struct dcc_command kill_msgtab = {
 "kill", NULL, {m_unregistered, m_kill, m_kill}
};
struct dcc_command kaction_msgtab = {
 "kaction", NULL, {m_unregistered, m_kaction, m_kaction}
};
struct dcc_command kspam_msgtab = {
 "kspam", NULL, {m_unregistered, m_use_kaction, m_use_kaction}
};
struct dcc_command hmulti_msgtab = {
 "hmulti", NULL, {m_unregistered, m_hmulti, m_hmulti}
};
struct dcc_command umulti_msgtab = {
 "umulti", NULL, {m_unregistered, m_umulti, m_umulti}
};
struct dcc_command register_msgtab = {
 "register", NULL, {m_register, m_register, m_register}
};
struct dcc_command opers_msgtab = {
 "opers", NULL, {m_unregistered, m_opers, m_opers}
};
struct dcc_command testline_msgtab = {
 "testline", NULL, {m_unregistered, m_testline, m_testline}
};
struct dcc_command actions_msgtab = {
 "actions", NULL, {m_actions, m_actions, m_actions}
};
struct dcc_command action_msgtab = {
 "action", NULL, {m_unregistered, m_action, m_action}
};
struct dcc_command set_msgtab = {
 "set", NULL, {m_unregistered, m_set, m_set}
};
struct dcc_command uptime_msgtab = {
 "uptime", NULL, {m_uptime, m_uptime, m_uptime}
};
struct dcc_command exemptions_msgtab = {
 "exemptions", NULL, {m_unregistered, m_exemptions, m_exemptions}
};
struct dcc_command umode_msgtab = {
 "umode", NULL, {m_unregistered, m_umode, m_umode}
};
struct dcc_command connections_msgtab = {
 "connections", NULL, {m_connections, m_connections, m_connections}
};
struct dcc_command whom_msgtab = {
 "whom", NULL, {m_connections, m_connections, m_connections}
};
struct dcc_command who_msgtab = {
 "who", NULL, {m_connections, m_connections, m_connections}
};
struct dcc_command disconnect_msgtab = {
 "disconnect", NULL, {m_unregistered, m_not_admin, m_disconnect}
};
struct dcc_command quit_msgtab = {
 "quit", NULL, {m_close, m_close, m_close}
};
struct dcc_command help_msgtab = {
 "help", NULL, {m_help, m_help, m_help}
};
struct dcc_command motd_msgtab = {
 "motd", NULL, {m_motd, m_motd, m_motd}
};
struct dcc_command save_msgtab = {
 "save", NULL, {m_unregistered, m_not_admin, m_save}
};
struct dcc_command close_msgtab = {
 "close", NULL, {m_close, m_close, m_close}
};
struct dcc_command op_msgtab = {
 "op", NULL, {m_unregistered, m_op, m_op}
};
struct dcc_command cycle_msgtab = {
 "cycle", NULL, {m_unregistered, m_cycle, m_cycle}
};
struct dcc_command die_msgtab = {
 "die", NULL, {m_unregistered, m_not_admin, m_die}
};
struct dcc_command restart_msgtab = { 
 "restart", NULL, {m_unregistered, m_not_admin, m_restart}
};
struct dcc_command info_msgtab = {
 "info", NULL, {m_info, m_info, m_info}
};
struct dcc_command locops_msgtab = {
 "locops", NULL, {m_unregistered, m_locops, m_locops}
};
struct dcc_command unkline_msgtab = {
 "unkline", NULL, {m_unregistered, m_unkline, m_unkline}
};
struct dcc_command vbots_msgtab = {
 "vbots", NULL, {m_unregistered, m_vbots, m_vbots}
};
#ifndef NO_D_LINE_SUPPORT
struct dcc_command dline_msgtab = {
 "dline", NULL, {m_unregistered, m_dline, m_dline}
};
#endif
#ifdef ENABLE_QUOTE
struct dcc_command quote_msgtab = {
 "quote", NULL, {m_unregistered, m_not_admin, m_quote}
};
#endif
struct dcc_command mem_msgtab = {
 "mem", NULL, {m_unregistered, m_not_admin, m_mem}
};
struct dcc_command clones_msgtab = {
 "clones", NULL, {m_unregistered, m_clones, m_clones}
};
struct dcc_command nflood_msgtab = {
 "nflood", NULL, {m_unregistered, m_nflood, m_nflood}
};
struct dcc_command rehash_msgtab = {
 "rehash", NULL, {m_unregistered, m_not_admin, m_rehash}
};
struct dcc_command trace_msgtab = {
 "trace", NULL, {m_unregistered, m_trace, m_trace}
};
struct dcc_command failures_msgtab = {
 "failures", NULL, {m_unregistered, m_failures, m_failures}
};
struct dcc_command domains_msgtab = {
 "domains", NULL, {m_unregistered, m_domains, m_domains}
};
struct dcc_command bots_msgtab = {
 "bots", NULL, {m_unregistered, m_bots, m_bots}
};
struct dcc_command events_msgtab = {
 "events", NULL, {m_unregistered, m_events, m_events}
};
#ifdef VIRTUAL
struct dcc_command vmulti_msgtab = {
 "vmulti", NULL, {m_unregistered, m_vmulti, m_vmulti}
};
#endif
struct dcc_command nfind_msgtab = {
 "nfind", NULL, {m_unregistered, m_nfind, m_nfind}
};
struct dcc_command list_msgtab = {
 "list", NULL, {m_unregistered, m_list, m_list}
};
#ifdef WANT_ULIST
struct dcc_command ulist_msgtab = {
 "ulist", NULL, {m_unregistered, m_ulist, m_ulist}
};
#endif
#ifdef WANT_HLIST
struct dcc_command hlist_msgtab = {
 "hlist", NULL, {m_unregistered, m_hlist, m_hlist}
};
#endif
#endif

void 
init_commands(void)
{
  add_dcc_handler(&vlist_msgtab);
  add_dcc_handler(&class_msgtab);
  add_dcc_handler(&classt_msgtab);
  add_dcc_handler(&killlist_msgtab);
  add_dcc_handler(&kline_msgtab);
  add_dcc_handler(&kclone_msgtab);
  add_dcc_handler(&kflood_msgtab);
  add_dcc_handler(&kperm_msgtab);
  add_dcc_handler(&klink_msgtab);
  add_dcc_handler(&kdrone_msgtab);
  add_dcc_handler(&kbot_msgtab);
  add_dcc_handler(&kill_msgtab);
  add_dcc_handler(&kaction_msgtab);
  add_dcc_handler(&kspam_msgtab);
  add_dcc_handler(&hmulti_msgtab);
  add_dcc_handler(&umulti_msgtab);
  add_dcc_handler(&register_msgtab);
  add_dcc_handler(&opers_msgtab);
  add_dcc_handler(&testline_msgtab);
  add_dcc_handler(&action_msgtab);
  add_dcc_handler(&set_msgtab);
  add_dcc_handler(&exemptions_msgtab);
  add_dcc_handler(&umode_msgtab);
  add_dcc_handler(&connections_msgtab);
  add_dcc_handler(&whom_msgtab);
  add_dcc_handler(&who_msgtab);
  add_dcc_handler(&disconnect_msgtab);
  add_dcc_handler(&quit_msgtab);
  add_dcc_handler(&help_msgtab);
  add_dcc_handler(&motd_msgtab);
  add_dcc_handler(&save_msgtab);
  add_dcc_handler(&close_msgtab);
  add_dcc_handler(&op_msgtab);
  add_dcc_handler(&cycle_msgtab);
  add_dcc_handler(&die_msgtab);
  add_dcc_handler(&restart_msgtab);
  add_dcc_handler(&info_msgtab);
  add_dcc_handler(&locops_msgtab);
  add_dcc_handler(&unkline_msgtab);
  add_dcc_handler(&vbots_msgtab);
#ifndef NO_D_LINE_SUPPORT
  add_dcc_handler(&dline_msgtab);
#endif
#ifdef ENABLE_QUOTE
  add_dcc_handler(&quote_msgtab);
#endif
  add_dcc_handler(&mem_msgtab);
  add_dcc_handler(&clones_msgtab);
  add_dcc_handler(&nflood_msgtab);
  add_dcc_handler(&rehash_msgtab);
  add_dcc_handler(&trace_msgtab);
  add_dcc_handler(&failures_msgtab);
  add_dcc_handler(&domains_msgtab);
  add_dcc_handler(&bots_msgtab);
  add_dcc_handler(&events_msgtab);
#ifdef VIRTUAL
  add_dcc_handler(&vmulti_msgtab);
#endif
  add_dcc_handler(&nfind_msgtab);
  add_dcc_handler(&list_msgtab);
#ifdef WANT_ULIST
  add_dcc_handler(&ulist_msgtab);
#endif
#ifdef WANT_HLIST
  add_dcc_handler(&hlist_msgtab);
#endif
  add_dcc_handler(&uptime_msgtab);
}

/*
 * is_legal_pass()
 *
 * inputs       - user
 *              - host
 *              - password
 *              - int connect id
 * output       - oper type if legal 0 if not
 * side effects - NONE
 */

static int
is_legal_pass(int connect_id, char *password)
{
  int i;

  for(i=0; userlist[i].user && userlist[i].host[0]; i++)
    {
      if ((!match(userlist[i].user,connections[connect_id].user)) &&
          (!wldcmp(userlist[i].host,connections[connect_id].host)))
        {
	  /* 
	   * userlist entries discovered from stats O
	   * has no valid password field. ignore them.
	   */

          if(userlist[i].password[0])
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
#else
              if(!strcmp(userlist[i].password,password))
                {
                  strncpy(connections[connect_id].registered_nick,
                          userlist[i].usernick,
                          MAX_NICK);
                  connections[connect_id].type = userlist[i].type;
                  return(userlist[i].type);
                }
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

  if(!text || (*text == '\0') || (*text == '?'))
    {
      if( (userfile = fopen(HELP_PATH "/" HELP_FILE,"r")) == NULL )
        {
          print_to_socket(sock,"Help is not currently available");
          return;
        }
    }
  else
    {
      while(*text == ' ')
        text++;

      if ((*text == '\0') || (*text == '?'))
        {
          if( (userfile = fopen(HELP_PATH "/" HELP_FILE,"r")) == NULL )
            {
              print_to_socket(sock,"Help is not currently available");
              return;
            }
        }

      (void)snprintf(help_file,sizeof(help_file) - 1,"%s/%s.%s",
                     HELP_PATH,HELP_FILE,text);
      if( (userfile = fopen(help_file,"r")) == NULL)
        {
          print_to_socket(sock,
			  "Help for '%s' is not currently available",text);
          return;
        }
    }

  while (fgets(line, MAX_BUFF-1, userfile))
    {
      print_to_socket(sock, "%s", line);
    }
  fclose(userfile);
}
